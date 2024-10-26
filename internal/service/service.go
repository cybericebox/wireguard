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
	"github.com/cybericebox/wireguard/pkg/wg-key-gen"
	"github.com/gofrs/uuid"
	"github.com/hashicorp/go-multierror"
	"github.com/rs/zerolog/log"
	"net/netip"
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
		GetVPNClients(ctx context.Context) ([]postgres.VpnClient, error)
		UpdateVPNClientBanStatus(ctx context.Context, arg postgres.UpdateVPNClientBanStatusParams) error
		UpdateVPNClientBannedStatusByGroupID(ctx context.Context, arg postgres.UpdateVPNClientBannedStatusByGroupIDParams) error
		UpdateVPNClientBannedStatusByUserID(ctx context.Context, arg postgres.UpdateVPNClientBannedStatusByUserIDParams) error

		DeleteVPNClient(ctx context.Context, arg postgres.DeleteVPNClientParams) error
		DeleteVPNClientsByGroupID(ctx context.Context, groupID uuid.UUID) error
		DeleteVPNClientsByUserID(ctx context.Context, userID uuid.UUID) error

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

func getClientID(userID, groupID uuid.UUID) string {
	return fmt.Sprintf("%s-%s", userID, groupID)
}

func (s *Service) GetClientConfig(ctx context.Context, userID, groupID uuid.UUID, destCIDR string) (string, error) {
	s.m.Lock()

	// check if user exists
	client, ex := s.clients[getClientID(userID, groupID)]

	s.m.Unlock()
	// if user does not exist create new user
	if !ex {
		client = &model.Client{
			UserID:     userID,
			GroupID:    groupID,
			AllowedIPs: destCIDR,
		}

		// create user
		if err := s.createClient(ctx, client); err != nil {
			return "", fmt.Errorf("creating client error: [%w]", err)
		}
	}

	return s.generateClientConfig(client)
}

func (s *Service) getFilteredClients(userID, groupID uuid.UUID) []*model.Client {
	s.m.RLock()
	defer s.m.RUnlock()

	clients := make([]*model.Client, 0, len(s.clients))
	for id, c := range s.clients {
		if userID != uuid.Nil && groupID != uuid.Nil {
			if id == getClientID(userID, groupID) {
				clients = append(clients, c)
				break
			}
		} else if userID != uuid.Nil {
			if c.UserID == userID {
				clients = append(clients, c)
			}
		} else if groupID != uuid.Nil {
			if c.GroupID == groupID {
				clients = append(clients, c)
			}
		} else {
			clients = append(clients, c)
		}
	}

	return clients
}

func (s *Service) DeleteClients(ctx context.Context, userID, groupID uuid.UUID) error {
	s.m.Lock()
	defer s.m.Unlock()

	var errs error

	clients := s.getFilteredClients(userID, groupID)

	if len(clients) == 0 {
		return fmt.Errorf("client with userID: [%s] and groupID: [%s] does not exist", userID, groupID)
	}

	for _, c := range clients {
		// delete user peer
		if err := s.deletePeer(c.Address, c.PublicKey); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("deleting client peer error: [%w]", err))
			continue
		}

		// delete nat rule
		if err := s.deleteNATRule(getClientID(c.UserID, c.GroupID), c.Address, c.AllowedIPs); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("deleting client NAT rule error: [%w]", err))
			continue
		}

		// delete ban rule if user is banned
		if c.Banned {
			if err := s.deleteBlockRule(getClientID(c.UserID, c.GroupID), c.Address); err != nil {
				errs = multierror.Append(errs, fmt.Errorf("deleting client blocking rule error: [%w]", err))
				continue
			}
		}

		// cut mask from address, because release function get only ip
		addr, _ := strings.CutSuffix(c.Address, "/32")

		// release user address
		if err := s.ipaManager.ReleaseSingleIP(ctx, addr); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("releasing client ip error: [%w]", err))
			continue
		}

		delete(s.clients, getClientID(c.UserID, c.GroupID))
	}

	if errs != nil {
		return errs
	}

	if len(clients) == 1 {
		if err := s.repository.DeleteVPNClient(ctx, postgres.DeleteVPNClientParams{
			UserID:  userID,
			GroupID: groupID,
		}); err != nil {
			return fmt.Errorf("deleting client from db error: [%w]", err)
		}
	} else {
		if userID != uuid.Nil {
			if err := s.repository.DeleteVPNClientsByUserID(ctx, userID); err != nil {
				return fmt.Errorf("deleting clients from db error: [%w]", err)
			}
		}
		if groupID != uuid.Nil {
			if err := s.repository.DeleteVPNClientsByGroupID(ctx, groupID); err != nil {
				return fmt.Errorf("deleting clients from db error: [%w]", err)
			}
		}
	}

	return nil
}

func (s *Service) BanClients(ctx context.Context, userID, groupID uuid.UUID) error {
	s.m.Lock()
	defer s.m.Unlock()

	var errs error

	clients := s.getFilteredClients(userID, groupID)

	if len(clients) == 0 {
		return fmt.Errorf("client with userID: [%s] and groupID: [%s] does not exist", userID, groupID)
	}

	for _, c := range clients {
		// ban user
		if err := s.addBlockRule(getClientID(c.UserID, c.GroupID), c.Address); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("adding client blocking rule error: [%w]", err))
			continue
		}

	}

	if errs != nil {
		return errs
	}

	if len(clients) == 1 {
		if err := s.repository.UpdateVPNClientBanStatus(ctx, postgres.UpdateVPNClientBanStatusParams{
			UserID:  userID,
			GroupID: groupID,
			Banned:  true,
		}); err != nil {
			return fmt.Errorf("updating client ban status in db error: [%w]", err)
		}
	} else {
		if userID != uuid.Nil {
			if err := s.repository.UpdateVPNClientBannedStatusByUserID(ctx, postgres.UpdateVPNClientBannedStatusByUserIDParams{
				UserID: userID,
				Banned: true,
			}); err != nil {
				return fmt.Errorf("updating client ban status in db error: [%w]", err)
			}
		}
		if groupID != uuid.Nil {
			if err := s.repository.UpdateVPNClientBannedStatusByGroupID(ctx, postgres.UpdateVPNClientBannedStatusByGroupIDParams{
				GroupID: groupID,
				Banned:  true,
			}); err != nil {
				return fmt.Errorf("updating client ban status in db error: [%w]", err)
			}
		}
	}

	for _, c := range clients {
		s.clients[getClientID(c.UserID, c.GroupID)].Banned = true
	}

	return nil

}

func (s *Service) UnBanClients(ctx context.Context, userID, groupID uuid.UUID) error {
	s.m.Lock()
	defer s.m.Unlock()

	var errs error

	clients := s.getFilteredClients(userID, groupID)

	if len(clients) == 0 {
		return fmt.Errorf("client with userID: [%s] and groupID: [%s] does not exist", userID, groupID)
	}

	for _, c := range clients {
		// ban user
		if err := s.deleteBlockRule(getClientID(c.UserID, c.GroupID), c.Address); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("deleting client blocking rule error: [%w]", err))
			continue
		}

	}

	if errs != nil {
		return errs
	}

	if len(clients) == 1 {
		if err := s.repository.UpdateVPNClientBanStatus(ctx, postgres.UpdateVPNClientBanStatusParams{
			UserID:  userID,
			GroupID: groupID,
			Banned:  false,
		}); err != nil {
			return fmt.Errorf("updating client ban status in db error: [%w]", err)
		}
	} else {
		if userID != uuid.Nil {
			if err := s.repository.UpdateVPNClientBannedStatusByUserID(ctx, postgres.UpdateVPNClientBannedStatusByUserIDParams{
				UserID: userID,
				Banned: false,
			}); err != nil {
				return fmt.Errorf("updating client ban status in db error: [%w]", err)
			}
		}
		if groupID != uuid.Nil {
			if err := s.repository.UpdateVPNClientBannedStatusByGroupID(ctx, postgres.UpdateVPNClientBannedStatusByGroupIDParams{
				GroupID: groupID,
				Banned:  false,
			}); err != nil {
				return fmt.Errorf("updating client ban status in db error: [%w]", err)
			}
		}
	}

	for _, c := range clients {
		s.clients[getClientID(c.UserID, c.GroupID)].Banned = false
	}

	return nil

}

func (s *Service) createClient(ctx context.Context, client *model.Client) (err error) {
	// generate client address
	client.Address, err = s.ipaManager.AcquireSingleIP(ctx)
	if err != nil {
		return fmt.Errorf("acquiring client ip error: [%w]", err)
	}

	// add 32 mask to address
	client.Address = fmt.Sprintf("%s/32", client.Address)

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
	if err = s.addNATRule(getClientID(client.UserID, client.GroupID), client.Address, client.AllowedIPs); err != nil {
		return fmt.Errorf("adding client NAT rule error: [%w]", err)
	}

	ip, err := netip.ParsePrefix(client.Address)
	if err != nil {
		return fmt.Errorf("parsing client ip error: [%w]", err)
	}

	allowedIPs, err := netip.ParsePrefix(client.AllowedIPs)
	if err != nil {
		return fmt.Errorf("parsing client allowedIPs error: [%w]", err)
	}

	// add client to db
	if err = s.repository.CreateVpnClient(ctx, postgres.CreateVpnClientParams{
		UserID:         client.UserID,
		GroupID:        client.GroupID,
		IpAddress:      ip,
		PublicKey:      client.PublicKey,
		PrivateKey:     client.PrivateKey,
		LaboratoryCidr: allowedIPs,
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

	s.clients[getClientID(client.UserID, client.GroupID)] = client

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
	clients, err := s.repository.GetVPNClients(ctx)
	if err != nil {
		return fmt.Errorf("getting clients from db error: [%w]", err)
	}
	// create users
	for _, c := range clients {
		client := &model.Client{
			UserID:     c.UserID,
			GroupID:    c.GroupID,
			Address:    c.IpAddress.String(),
			DNS:        "",
			PrivateKey: c.PrivateKey,
			PublicKey:  c.PublicKey,
			AllowedIPs: c.LaboratoryCidr.String(),
			Endpoint:   "",
			Banned:     c.Banned,
		}
		// generate user DNS address
		client.DNS, err = ipam.GetFirstCIDRIP(client.AllowedIPs)
		if err != nil {
			return err

		}

		if err = s.addPeer(client.Address, client.PublicKey); err != nil {
			errs = multierror.Append(fmt.Errorf("adding c peer error: [%w]", err))
		}

		// add nat rule
		if err = s.addNATRule(getClientID(client.UserID, client.GroupID), client.Address, client.AllowedIPs); err != nil {
			errs = multierror.Append(fmt.Errorf("adding c NAT rule error: [%w]", err))
		}

		// if user is banned add block rule
		if client.Banned {
			if err = s.addBlockRule(getClientID(client.UserID, client.GroupID), client.Address); err != nil {
				errs = multierror.Append(fmt.Errorf("adding c blocking rule error: [%w]", err))
			}
		}

		s.clients[getClientID(client.UserID, client.GroupID)] = client
	}
	return errs
}
