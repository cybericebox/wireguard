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
	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Getting client config from cache")
	client, ex := s.clients[getClientID(userID, groupID)]

	s.m.Unlock()
	// if user does not exist create new user
	if !ex {
		client = &model.Client{
			UserID:     userID,
			GroupID:    groupID,
			AllowedIPs: destCIDR,
		}
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Creating new client")
		// create user
		if err := s.createClient(ctx, client); err != nil {
			return "", fmt.Errorf("creating client error: [%w]", err)
		}
	}

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Returning client config from cache")

	return s.generateClientConfig(client)
}

func (s *Service) getFilteredClients(userID, groupID uuid.UUID, filter func(*model.Client) bool) []*model.Client {
	s.m.RLock()
	defer s.m.RUnlock()

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Getting filtered clients")
	clients := make([]*model.Client, 0, len(s.clients))
	for id, c := range s.clients {
		if filter != nil {
			if !filter(c) {
				continue
			}
		}
		if !userID.IsNil() && !groupID.IsNil() {
			if id == getClientID(userID, groupID) {
				clients = append(clients, c)
				break
			}
		} else if !userID.IsNil() {
			if c.UserID == userID {
				clients = append(clients, c)
			}
		} else if !groupID.IsNil() {
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

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Get clients for deletion")
	clients := s.getFilteredClients(userID, groupID, nil)

	if len(clients) == 0 {
		return nil
	}

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Deleting clients")
	for _, c := range clients {
		// delete user peer
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Str("address", c.Address).Msg("Deleting client peer")
		if err := s.deletePeer(c.Address, c.PublicKey); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("deleting client peer error: [%w]", err))
			continue
		}

		// delete nat rule
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Str("address", c.Address).Msg("Deleting client NAT rule")
		if err := s.deleteNATRule(getClientID(c.UserID, c.GroupID), c.Address, c.AllowedIPs); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("deleting client NAT rule error: [%w]", err))
			continue
		}

		// delete ban rule if user is banned
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Str("address", c.Address).Msg("Deleting client blocking rule")
		if c.Banned {
			if err := s.deleteBlockRule(getClientID(c.UserID, c.GroupID), c.Address); err != nil {
				errs = multierror.Append(errs, fmt.Errorf("deleting client blocking rule error: [%w]", err))
				continue
			}
		}

		// cut mask from address, because release function get only ip
		addr, _ := strings.CutSuffix(c.Address, "/32")

		// release user address
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Str("address", c.Address).Msg("Releasing client ip")
		if err := s.ipaManager.ReleaseSingleIP(ctx, addr); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("releasing client ip error: [%w]", err))
			continue
		}

		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Deleting client from cache")
		delete(s.clients, getClientID(c.UserID, c.GroupID))
	}

	if errs != nil {
		return errs
	}

	if len(clients) == 1 {
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Deleting client from db")
		if err := s.repository.DeleteVPNClient(ctx, postgres.DeleteVPNClientParams{
			UserID:  userID,
			GroupID: groupID,
		}); err != nil {
			return fmt.Errorf("deleting client from db error: [%w]", err)
		}
	} else {
		if !userID.IsNil() {
			log.Debug().Str("userID", userID.String()).Msg("Deleting clients by userID from db")
			if err := s.repository.DeleteVPNClientsByUserID(ctx, userID); err != nil {
				return fmt.Errorf("deleting clients from db error: [%w]", err)
			}
		}
		if !groupID.IsNil() {
			log.Debug().Str("groupID", groupID.String()).Msg("Deleting clients by groupID from db")
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

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Get clients for banning")
	clients := s.getFilteredClients(userID, groupID, func(c *model.Client) bool {
		return !c.Banned
	})

	if len(clients) == 0 {
		return nil
	}

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Banning clients")
	for _, c := range clients {
		// ban user
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Str("address", c.Address).Msg("Adding client blocking rule")
		if err := s.addBlockRule(getClientID(c.UserID, c.GroupID), c.Address); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("adding client blocking rule error: [%w]", err))
			continue
		}

	}

	if errs != nil {
		return errs
	}

	if len(clients) == 1 {
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Updating client ban status in db")
		if err := s.repository.UpdateVPNClientBanStatus(ctx, postgres.UpdateVPNClientBanStatusParams{
			UserID:  userID,
			GroupID: groupID,
			Banned:  true,
		}); err != nil {
			return fmt.Errorf("updating client ban status in db error: [%w]", err)
		}
	} else {
		if !userID.IsNil() {
			log.Debug().Str("userID", userID.String()).Msg("Updating clients ban status by userID in db")
			if err := s.repository.UpdateVPNClientBannedStatusByUserID(ctx, postgres.UpdateVPNClientBannedStatusByUserIDParams{
				UserID: userID,
				Banned: true,
			}); err != nil {
				return fmt.Errorf("updating client ban status in db error: [%w]", err)
			}
		}
		if !groupID.IsNil() {
			log.Debug().Str("groupID", groupID.String()).Msg("Updating clients ban status by groupID in db")
			if err := s.repository.UpdateVPNClientBannedStatusByGroupID(ctx, postgres.UpdateVPNClientBannedStatusByGroupIDParams{
				GroupID: groupID,
				Banned:  true,
			}); err != nil {
				return fmt.Errorf("updating client ban status in db error: [%w]", err)
			}
		}
	}

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Updating clients ban status in cache")
	for _, c := range clients {
		s.clients[getClientID(c.UserID, c.GroupID)].Banned = true
	}

	return nil

}

func (s *Service) UnBanClients(ctx context.Context, userID, groupID uuid.UUID) error {
	s.m.Lock()
	defer s.m.Unlock()

	var errs error

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Get clients for unbanning")
	clients := s.getFilteredClients(userID, groupID, func(c *model.Client) bool {
		return c.Banned
	})

	if len(clients) == 0 {
		return nil
	}

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Unbanning clients")
	for _, c := range clients {
		// ban user
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Str("address", c.Address).Msg("Deleting client blocking rule")
		if err := s.deleteBlockRule(getClientID(c.UserID, c.GroupID), c.Address); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("deleting client blocking rule error: [%w]", err))
			continue
		}

	}

	if errs != nil {
		return errs
	}

	if len(clients) == 1 {
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Updating client ban status in db")
		if err := s.repository.UpdateVPNClientBanStatus(ctx, postgres.UpdateVPNClientBanStatusParams{
			UserID:  userID,
			GroupID: groupID,
			Banned:  false,
		}); err != nil {
			return fmt.Errorf("updating client ban status in db error: [%w]", err)
		}
	} else {
		if !userID.IsNil() {
			log.Debug().Str("userID", userID.String()).Msg("Updating clients ban status by userID in db")
			if err := s.repository.UpdateVPNClientBannedStatusByUserID(ctx, postgres.UpdateVPNClientBannedStatusByUserIDParams{
				UserID: userID,
				Banned: false,
			}); err != nil {
				return fmt.Errorf("updating client ban status in db error: [%w]", err)
			}
		}
		if !groupID.IsNil() {
			log.Debug().Str("groupID", groupID.String()).Msg("Updating clients ban status by groupID in db")
			if err := s.repository.UpdateVPNClientBannedStatusByGroupID(ctx, postgres.UpdateVPNClientBannedStatusByGroupIDParams{
				GroupID: groupID,
				Banned:  false,
			}); err != nil {
				return fmt.Errorf("updating client ban status in db error: [%w]", err)
			}
		}
	}

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Updating clients ban status in cache")
	for _, c := range clients {
		s.clients[getClientID(c.UserID, c.GroupID)].Banned = false
	}

	return nil

}

func (s *Service) createClient(ctx context.Context, client *model.Client) (err error) {
	// generate client address
	log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Creating new client")
	log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Acquiring client ip")
	client.Address, err = s.ipaManager.AcquireSingleIP(ctx)
	if err != nil {
		return fmt.Errorf("acquiring client ip error: [%w]", err)
	}

	// add 32 mask to address
	client.Address = fmt.Sprintf("%s/32", client.Address)

	// generate client key pair
	log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Generating client key pair")
	keys, err := s.keyGenerator.NewKeyPair()
	if err != nil {
		return fmt.Errorf("generating client key pair error: [%w]", err)
	}

	client.PublicKey, client.PrivateKey = keys.PublicKey, keys.PrivateKey

	// add client peer
	log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Adding client peer")
	if err = s.addPeer(client.Address, client.PublicKey); err != nil {
		return fmt.Errorf("adding client peer error: [%w]", err)
	}

	// add nat rule
	log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Adding client NAT rule")
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
	log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Creating client in db")
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
	log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Generating client DNS ip")
	client.DNS, err = ipam.GetFirstCIDRIP(client.AllowedIPs)
	if err != nil {
		return fmt.Errorf("generating client DNS ip error: [%w]", err)

	}

	s.m.Lock()
	defer s.m.Unlock()

	log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Adding client to cache")
	s.clients[getClientID(client.UserID, client.GroupID)] = client

	return nil
}

func (s *Service) InitServer(ctx context.Context) error {
	var err error
	// set wg server address
	log.Debug().Msg("Setting server address")
	s.config.Address, err = s.ipaManager.GetFirstIP()
	if err != nil {
		return fmt.Errorf("getting server ip error: [%w]", err)
	}

	// reserve server address
	log.Debug().Str("Address: ", s.config.Address).Msg("Reserving server ip")
	if _, err = s.ipaManager.AcquireSingleIP(ctx, s.config.Address); err != nil {
		return fmt.Errorf("acquiring server ip error: [%w]", err)
	}

	// get server private key
	log.Debug().Msg("Getting server private key from db")
	s.config.PrivateKey, err = s.repository.GetVPNPrivateKey(ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("getting server private key error: [%w]", err)
	}

	// get server public key
	log.Debug().Msg("Getting server public key from db")
	s.config.PublicKey, err = s.repository.GetVPNPublicKey(ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("getting server public key error: [%w]", err)
	}

	// if server private key does not exist generate new key pair
	if s.config.PrivateKey == "" || s.config.PublicKey == "" {
		// generate server key pair
		log.Debug().Msg("Key pair does not exist, generating new key pair")
		keys, err := s.keyGenerator.NewKeyPair()
		if err != nil {
			return fmt.Errorf("generating server key pair error: [%w]", err)
		}

		s.config.PrivateKey, s.config.PublicKey = keys.PrivateKey, keys.PublicKey

		// save server key pair
		log.Debug().Msg("Saving server private key pair to db")
		if err = s.repository.SetVPNPrivateKey(ctx, s.config.PrivateKey); err != nil {
			return fmt.Errorf("saving server private key error: [%w]", err)
		}
		log.Debug().Msg("Saving server public key pair to db")
		if err = s.repository.SetVPNPublicKey(ctx, s.config.PublicKey); err != nil {
			return fmt.Errorf("saving server public key error: [%w]", err)
		}
	}

	log.Debug().Msg("Generating server config")
	strConfig, err := s.generateServerConfig()
	if err != nil {
		return fmt.Errorf("creating wireguard config error: [%w]", err)
	}

	log.Debug().Msg("Writing server config to file")
	if err = writeToFile(path.Join(configPath, nic+".conf"), strConfig); err != nil {
		return fmt.Errorf("writing wireguard config to file error: [%w]", err)
	}

	log.Debug().Msg("Creating wireguard interface")
	if err = upInterface(); err != nil {
		return fmt.Errorf("making wireguard interface up error: [%w]", err)
	}

	log.Debug().Str("Address: ", s.config.Address).
		Str("ListenPort: ", s.config.Port).Msgf("Interface %s created and it is up", nic)

	return nil
}

func (s *Service) InitServerClients(ctx context.Context) (errs error) {
	s.m.Lock()
	defer s.m.Unlock()

	// get all users from db
	log.Debug().Msg("Getting clients from db")
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
		log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Generating client DNS ip")
		client.DNS, err = ipam.GetFirstCIDRIP(client.AllowedIPs)
		if err != nil {
			return err

		}
		log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Adding client peer")
		if err = s.addPeer(client.Address, client.PublicKey); err != nil {
			errs = multierror.Append(fmt.Errorf("adding c peer error: [%w]", err))
		}

		// add nat rule
		log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Adding client NAT rule")
		if err = s.addNATRule(getClientID(client.UserID, client.GroupID), client.Address, client.AllowedIPs); err != nil {
			errs = multierror.Append(fmt.Errorf("adding c NAT rule error: [%w]", err))
		}

		// if user is banned add block rule
		log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Bool("banned", client.Banned).Msg("Adding client blocking rule if user is banned")
		if client.Banned {
			if err = s.addBlockRule(getClientID(client.UserID, client.GroupID), client.Address); err != nil {
				errs = multierror.Append(fmt.Errorf("adding c blocking rule error: [%w]", err))
			}
		}

		log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Adding client to cache")
		s.clients[getClientID(client.UserID, client.GroupID)] = client
	}
	return errs
}
