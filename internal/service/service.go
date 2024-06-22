package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/cybericebox/wireguard/internal/config"
	"github.com/cybericebox/wireguard/internal/delivery/repository/postgres"
	"github.com/cybericebox/wireguard/internal/model"
	"github.com/cybericebox/wireguard/pkg/ipam"
	wg_key_gen "github.com/cybericebox/wireguard/pkg/wg-key-gen"
	"github.com/gofrs/uuid"
	"github.com/hashicorp/go-multierror"
	"github.com/rs/zerolog/log"
	"github.com/sqlc-dev/pqtype"
	"net"
	"path"
	"strings"
	"sync"
)

type (
	Service struct {
		m            sync.RWMutex
		config       *config.VPNConfig
		clients      map[string]*model.Client
		keyGenerator *wg_key_gen.KeyGenerator
		repository   Repository
		ipaManager   IPAManager
	}

	Repository interface {
		CreateVpnClient(ctx context.Context, arg postgres.CreateVpnClientParams) error
		DeleteVPNClient(ctx context.Context, id uuid.UUID) error
		GetVPNClients(ctx context.Context) ([]postgres.VpnClient, error)
		UpdateVPNClientBanStatus(ctx context.Context, arg postgres.UpdateVPNClientBanStatusParams) error

		GetVPNPrivateKey(ctx context.Context) (string, error)
		GetVPNPublicKey(ctx context.Context) (string, error)
		SetVPNPrivateKey(ctx context.Context, value string) error
		SetVPNPublicKey(ctx context.Context, value string) error
	}

	IPAManager interface {
		AcquireSingleIP(ctx context.Context, ip ...string) (string, error)
		ReleaseSingleIP(ctx context.Context, ip string) error
		GetFirstIP() (string, error)
	}

	Dependencies struct {
		Repository   Repository
		IPAManager   IPAManager
		KeyGenerator *wg_key_gen.KeyGenerator
		Config       *config.VPNConfig
	}
)

func NewService(deps Dependencies) *Service {
	return &Service{
		config:       deps.Config,
		clients:      make(map[string]*model.Client),
		keyGenerator: deps.KeyGenerator,
		repository:   deps.Repository,
		ipaManager:   deps.IPAManager,
	}
}

func (s *Service) GetClientConfig(ctx context.Context, clientID, destCIDR string) (string, error) {
	s.m.Lock()

	// check if user exists
	client, ex := s.clients[clientID]

	s.m.Unlock()
	// if user does not exist create new user
	if !ex {
		client = &model.Client{
			ID:         clientID,
			AllowedIPs: destCIDR,
		}

		// create user
		if err := s.createClient(ctx, client); err != nil {
			return "", fmt.Errorf("creating client error: [%w]", err)
		}
	}

	return s.generateClientConfig(client)
}

func (s *Service) DeleteClient(ctx context.Context, clientID string) error {
	s.m.Lock()
	defer s.m.Unlock()

	parsedID, err := uuid.FromString(clientID)
	if err != nil {
		return fmt.Errorf("parsing client id error: [%w]", err)
	}

	client, ex := s.clients[clientID]
	if !ex {
		return fmt.Errorf("client with id [ %s ] does not exist", clientID)
	}

	// delete user
	// delete user peer
	if err = s.deletePeer(client.Address, client.PublicKey); err != nil {
		return fmt.Errorf("deleting client peer error: [%w]", err)
	}

	// delete nat rule
	if err = s.deleteNATRule(client.ID, client.Address, client.AllowedIPs); err != nil {
		return fmt.Errorf("deleting client NAT rule error: [%w]", err)
	}

	// delete ban rule if user is banned
	if client.Banned {
		if err = s.deleteBlockRule(client.ID, client.Address); err != nil {
			return fmt.Errorf("deleting client blocking rule error: [%w]", err)
		}
	}

	// cut mask from address, because release function get only ip
	addr, _ := strings.CutSuffix(client.Address, "/32")

	// release user address
	if err = s.ipaManager.ReleaseSingleIP(ctx, addr); err != nil {
		return fmt.Errorf("realising client ip error: [%w]", err)
	}

	// delete user from db
	if err = s.repository.DeleteVPNClient(ctx, parsedID); err != nil {
		return fmt.Errorf("deleting client from db error: [%w]", err)
	}

	delete(s.clients, clientID)

	return nil
}

func (s *Service) BanClient(ctx context.Context, clientID string) error {
	s.m.Lock()
	defer s.m.Unlock()

	parsedID, err := uuid.FromString(clientID)
	if err != nil {
		return fmt.Errorf("parsing client id error: [%w]", err)
	}

	if _, ex := s.clients[clientID]; !ex {
		return fmt.Errorf("client with id [ %s ] does not exist", clientID)
	}

	// ban user
	if err = s.addBlockRule(clientID, s.clients[clientID].Address); err != nil {
		return fmt.Errorf("adding client blocking rule error: [%w]", err)
	}

	if err = s.repository.UpdateVPNClientBanStatus(ctx, postgres.UpdateVPNClientBanStatusParams{
		ID:     parsedID,
		Banned: true,
	}); err != nil {
		return fmt.Errorf("adding client blocking to db error: [%w]", err)
	}

	s.clients[clientID].Banned = true

	return nil

}

func (s *Service) UnBanClient(ctx context.Context, clientID string) error {
	s.m.Lock()
	defer s.m.Unlock()

	parsedID, err := uuid.FromString(clientID)
	if err != nil {
		return fmt.Errorf("parsing client id error: [%w]", err)
	}

	if _, ex := s.clients[clientID]; !ex {
		return fmt.Errorf("client with id [ %s ] does not exist", clientID)
	}

	// unban user
	if err = s.deleteBlockRule(clientID, s.clients[clientID].Address); err != nil {
		return fmt.Errorf("deleting client blocking rule error: [%w]", err)
	}

	if err = s.repository.UpdateVPNClientBanStatus(ctx, postgres.UpdateVPNClientBanStatusParams{
		ID:     parsedID,
		Banned: false,
	}); err != nil {
		return fmt.Errorf("deleting client blocking from db error: [%w]", err)
	}

	s.clients[clientID].Banned = false

	return nil
}

func (s *Service) createClient(ctx context.Context, client *model.Client) (err error) {
	parsedID, err := uuid.FromString(client.ID)
	if err != nil {
		return fmt.Errorf("parsing client id error: [%w]", err)
	}

	// generate client address
	client.Address, err = s.ipaManager.AcquireSingleIP(ctx)
	if err != nil {
		return fmt.Errorf("acquiring client ip error: [%w]", err)
	}
	// generate client key pair
	keys, err := s.keyGenerator.NewKeyPair()
	if err != nil {
		return fmt.Errorf("generating client key pair error: [%w]", err)
	}

	client.PublicKey, client.PrivateKey = keys.PublicKey, keys.PrivateKey

	// add client peer
	if err = s.addPeer(client.Address, client.PublicKey); err != nil {
		return fmt.Errorf("adding client peer error: [%w]", err)
	}

	// add nat rule
	if err = s.addNATRule(client.ID, client.Address, client.AllowedIPs); err != nil {
		return fmt.Errorf("adding client NAT rule error: [%w]", err)
	}

	_, ip, err := net.ParseCIDR(fmt.Sprintf("%s/32", client.Address))
	if err != nil {
		return fmt.Errorf("parsing client ip error: [%w]", err)
	}

	_, allowedIPs, err := net.ParseCIDR(client.AllowedIPs)
	if err != nil {
		return fmt.Errorf("parsing client allowedIPs error: [%w]", err)
	}

	// add client to db
	if err = s.repository.CreateVpnClient(ctx, postgres.CreateVpnClientParams{
		ID: parsedID,
		IpAddress: pqtype.Inet{
			IPNet: *ip,
			Valid: true,
		},
		PublicKey:  client.PublicKey,
		PrivateKey: client.PrivateKey,
		LaboratoryCidr: pqtype.Inet{
			IPNet: *allowedIPs,
			Valid: true,
		},
	}); err != nil {
		return fmt.Errorf("creating client in db error: [%w]", err)
	}

	// generate client DNS address
	client.DNS, err = ipam.GetFirstCIDRIP(client.AllowedIPs)
	if err != nil {
		return fmt.Errorf("generating client DNS ip error: [%w]", err)

	}

	s.m.Lock()
	defer s.m.Unlock()

	s.clients[client.ID] = client

	return nil
}

func (s *Service) InitServer(ctx context.Context) error {
	var err error
	// set wg server address
	s.config.Address, err = s.ipaManager.GetFirstIP()
	if err != nil {
		return fmt.Errorf("getting server ip error: [%w]", err)
	}

	// reserve server address
	if _, err = s.ipaManager.AcquireSingleIP(ctx, s.config.Address); err != nil {
		return fmt.Errorf("acquiring server ip error: [%w]", err)
	}

	// get server private key
	s.config.PrivateKey, err = s.repository.GetVPNPrivateKey(ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("getting server private key error: [%w]", err)
	}

	// get server public key
	s.config.PublicKey, err = s.repository.GetVPNPublicKey(ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("getting server public key error: [%w]", err)
	}

	// if server private key does not exist generate new key pair
	if s.config.PrivateKey == "" || s.config.PublicKey == "" {
		// generate server key pair
		keys, err := s.keyGenerator.NewKeyPair()
		if err != nil {
			return fmt.Errorf("generating server key pair error: [%w]", err)
		}

		s.config.PrivateKey, s.config.PublicKey = keys.PrivateKey, keys.PublicKey

		// save server key pair
		if err = s.repository.SetVPNPrivateKey(ctx, s.config.PrivateKey); err != nil {
			return fmt.Errorf("saving server private key error: [%w]", err)
		}

		if err = s.repository.SetVPNPublicKey(ctx, s.config.PublicKey); err != nil {
			return fmt.Errorf("saving server public key error: [%w]", err)
		}
	}

	strConfig, err := s.generateServerConfig()
	if err != nil {
		return fmt.Errorf("creating wireguard config error: [%w]", err)
	}

	if err = writeToFile(path.Join(configPath, nic+".conf"), strConfig); err != nil {
		return fmt.Errorf("writing wireguard config to file error: [%w]", err)
	}

	if err = upInterface(); err != nil {
		return fmt.Errorf("making wireguard interface up error: [%w]", err)
	}

	log.Debug().Str("Address: ", s.config.Address).
		Str("ListenPort: ", s.config.Port).Msgf("Interface %s created and it is up", nic)

	return nil
}

func (s *Service) InitServerUsers(ctx context.Context) (errs error) {
	s.m.Lock()
	defer s.m.Unlock()

	// get all users from db
	users, err := s.repository.GetVPNClients(ctx)
	if err != nil {
		return fmt.Errorf("getting clients from db error: [%w]", err)
	}
	// create users
	for _, u := range users {
		user := &model.Client{
			ID:         u.ID.String(),
			Address:    u.IpAddress.IPNet.String(),
			PrivateKey: u.PrivateKey,
			PublicKey:  u.PublicKey,
			AllowedIPs: u.LaboratoryCidr.IPNet.String(),
			Banned:     u.Banned,
		}
		// generate user DNS address
		user.DNS, err = ipam.GetFirstCIDRIP(user.AllowedIPs)
		if err != nil {
			return err

		}

		if err = s.addPeer(user.Address, user.PublicKey); err != nil {
			errs = multierror.Append(fmt.Errorf("adding client peer error: [%w]", err))
		}

		// add nat rule
		if err = s.addNATRule(user.ID, user.Address, user.AllowedIPs); err != nil {
			errs = multierror.Append(fmt.Errorf("adding client NAT rule error: [%w]", err))
		}

		// if user is banned add block rule
		if user.Banned {
			if err = s.addBlockRule(user.ID, user.Address); err != nil {
				errs = multierror.Append(fmt.Errorf("adding client blocking rule error: [%w]", err))
			}
		}

		s.clients[user.ID] = user
	}
	return errs
}
