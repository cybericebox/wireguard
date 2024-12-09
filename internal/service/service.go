package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/cybericebox/lib/pkg/ipam"
	"github.com/cybericebox/lib/pkg/wgKeyGen"
	"github.com/cybericebox/wireguard/internal/config"
	"github.com/cybericebox/wireguard/internal/delivery/repository/postgres"
	"github.com/cybericebox/wireguard/internal/model"
	"github.com/cybericebox/wireguard/pkg/appError"
	"github.com/gofrs/uuid"
	"github.com/hashicorp/go-multierror"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type (
	Service struct {
		m            sync.RWMutex
		config       *config.VPNConfig
		clients      map[string]*model.Client
		keyGenerator *wgKeyGen.KeyGenerator
		repository   Repository
		ipaManager   IPAManager
	}

	Repository interface {
		CreateVpnClient(ctx context.Context, arg postgres.CreateVpnClientParams) error

		GetVPNClients(ctx context.Context) ([]postgres.VpnClient, error)

		UpdateVPNClientsBanStatus(ctx context.Context, arg postgres.UpdateVPNClientsBanStatusParams) (int64, error)

		DeleteVPNClients(ctx context.Context, arg postgres.DeleteVPNClientsParams) (int64, error)

		GetVPNServerPrivateKey(ctx context.Context) (string, error)
		GetVPNServerPublicKey(ctx context.Context) (string, error)
		SetVPNServerPrivateKey(ctx context.Context, value string) error
		SetVPNServerPublicKey(ctx context.Context, value string) error
	}

	IPAManager interface {
		AcquireSingleIP(ctx context.Context, ip ...string) (string, error)
		ReleaseSingleIP(ctx context.Context, ip string) error
		GetFirstIP() (string, error)
	}

	Dependencies struct {
		Repository   Repository
		IPAManager   IPAManager
		KeyGenerator *wgKeyGen.KeyGenerator
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

func (s *Service) GetClients(_ context.Context, userID, groupID uuid.UUID) ([]*model.Client, error) {
	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Getting clients")
	clients := s.getFilteredClients(userID, groupID, nil)

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Returning clients")
	peers, err := s.getPeersLastHandshake()
	if err != nil {
		return nil, appError.ErrClient.WithError(err).WithMessage("Failed to get peers last handshake").Err()
	}

	for _, c := range clients {
		if lastHandshake, ok := peers[c.PublicKey]; ok {
			c.LastSeen = -1
			if lastHandshake > 0 {
				c.LastSeen = time.Now().Unix() - int64(lastHandshake)
			}
		}
	}

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Returning clients")
	return clients, nil
}

func (s *Service) GetClientConfig(ctx context.Context, userID, groupID uuid.UUID, destCIDR string) (string, error) {
	s.m.RLock()

	// check if user exists
	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Getting client config from cache")
	client, ex := s.clients[getClientID(userID, groupID)]

	s.m.RUnlock()
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
			return "", appError.ErrClient.WithError(err).WithMessage("Failed to create client").Err()
		}
	}

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Returning client config from cache")

	clientConfig, err := s.generateClientConfig(client)
	if err != nil {
		return "", appError.ErrClient.WithError(err).WithMessage("Failed to generate client config").Err()
	}

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Returning client config")
	return clientConfig, nil
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

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Returning filtered clients")
	return clients
}

func (s *Service) DeleteClients(ctx context.Context, userID, groupID uuid.UUID) (int64, error) {
	var errs error

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Get clients for deletion")
	clients := s.getFilteredClients(userID, groupID, nil)

	if len(clients) == 0 {
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("No clients found for deletion")
		return 0, nil
	}

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Deleting clients")
	for _, c := range clients {
		// delete user peer
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Str("address", c.Address).Msg("Deleting client peer")
		if err := s.deletePeer(c.Address, c.PublicKey); err != nil {
			errs = multierror.Append(errs, appError.ErrClient.WithError(err).WithMessage("Failed to delete client peer").Err())
			continue
		}

		// delete nat rule
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Str("address", c.Address).Msg("Deleting client NAT rule")
		if err := s.deleteNATRule(getClientID(c.UserID, c.GroupID), c.Address, c.AllowedIPs); err != nil {
			errs = multierror.Append(errs, appError.ErrClient.WithError(err).WithMessage("Failed to delete client NAT rule").Err())
			continue
		}

		// delete ban rule if user is banned
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Str("address", c.Address).Msg("Deleting client blocking rule")
		if c.Banned {
			if err := s.deleteBlockRule(getClientID(c.UserID, c.GroupID), c.Address); err != nil {
				errs = multierror.Append(errs, appError.ErrClient.WithError(err).WithMessage("Failed to delete client blocking rule").Err())
				continue
			}
		}

		// cut mask from address, because release function get only ip
		addr, _ := strings.CutSuffix(c.Address, "/32")

		// release user address
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Str("address", c.Address).Msg("Releasing client ip")
		if err := s.ipaManager.ReleaseSingleIP(ctx, addr); err != nil {
			errs = multierror.Append(errs, appError.ErrClient.WithError(err).WithMessage("Failed to release client ip").Err())
			continue
		}
	}

	if errs != nil {
		return 0, appError.ErrClient.WithError(errs).WithMessage("Failed to delete clients").Err()
	}

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Deleting client from db")
	affected, err := s.repository.DeleteVPNClients(ctx, postgres.DeleteVPNClientsParams{
		UserID: uuid.NullUUID{
			UUID:  userID,
			Valid: !userID.IsNil(),
		},
		GroupID: uuid.NullUUID{
			UUID:  groupID,
			Valid: !groupID.IsNil(),
		},
	})
	if err != nil {
		return 0, appError.ErrClient.WithWrappedError(appError.ErrPostgres.WithError(err)).WithMessage("Failed to delete clients from db").Err()
	}

	s.m.Lock()
	defer s.m.Unlock()
	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Deleting clients from cache")
	for _, c := range clients {
		delete(s.clients, getClientID(c.UserID, c.GroupID))
	}

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Returning clients deletion")
	return affected, nil
}

func (s *Service) BanClients(ctx context.Context, userID, groupID uuid.UUID) (int64, error) {
	var errs error

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Get clients for banning")
	clients := s.getFilteredClients(userID, groupID, func(c *model.Client) bool {
		return !c.Banned
	})

	if len(clients) == 0 {
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("No clients found for banning")
		return 0, nil
	}

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Banning clients")
	for _, c := range clients {
		// ban user
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Str("address", c.Address).Msg("Adding client blocking rule")
		if err := s.addBlockRule(getClientID(c.UserID, c.GroupID), c.Address); err != nil {
			errs = multierror.Append(errs, appError.ErrClient.WithError(err).WithMessage("Failed to add client blocking rule").Err())
			continue
		}
	}

	if errs != nil {
		return 0, appError.ErrClient.WithError(errs).WithMessage("Failed to ban clients").Err()
	}

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Updating clients ban status in db")
	affected, err := s.repository.UpdateVPNClientsBanStatus(ctx, postgres.UpdateVPNClientsBanStatusParams{
		UserID: uuid.NullUUID{
			UUID:  userID,
			Valid: !userID.IsNil(),
		},
		GroupID: uuid.NullUUID{
			UUID:  groupID,
			Valid: !groupID.IsNil(),
		},
		Banned: true,
	})

	if err != nil {
		return 0, appError.ErrClient.WithWrappedError(appError.ErrPostgres.WithError(err)).WithMessage("Failed to update clients ban status in db").Err()
	}

	s.m.Lock()
	defer s.m.Unlock()
	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Updating clients ban status in cache")
	for _, c := range clients {
		s.clients[getClientID(c.UserID, c.GroupID)].Banned = true
	}

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Returning clients banning")
	return affected, nil

}

func (s *Service) UnBanClients(ctx context.Context, userID, groupID uuid.UUID) (int64, error) {
	var errs error

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Get clients for unbanning")
	clients := s.getFilteredClients(userID, groupID, func(c *model.Client) bool {
		return c.Banned
	})

	if len(clients) == 0 {
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("No clients found for unbanning")
		return 0, nil
	}

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Unbanning clients")
	for _, c := range clients {
		// ban user
		log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Str("address", c.Address).Msg("Deleting client blocking rule")
		if err := s.deleteBlockRule(getClientID(c.UserID, c.GroupID), c.Address); err != nil {
			errs = multierror.Append(errs, appError.ErrClient.WithError(err).WithMessage("Failed to delete client blocking rule").Err())
			continue
		}

	}

	if errs != nil {
		return 0, appError.ErrClient.WithError(errs).WithMessage("Failed to unban clients").Err()
	}

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Updating clients ban status in db")
	affected, err := s.repository.UpdateVPNClientsBanStatus(ctx, postgres.UpdateVPNClientsBanStatusParams{
		UserID: uuid.NullUUID{
			UUID:  userID,
			Valid: !userID.IsNil(),
		},
		GroupID: uuid.NullUUID{
			UUID:  groupID,
			Valid: !groupID.IsNil(),
		},
		Banned: false,
	})

	if err != nil {
		return 0, appError.ErrClient.WithWrappedError(appError.ErrPostgres.WithError(err)).WithMessage("Failed to update clients ban status in db").Err()
	}

	s.m.Lock()
	defer s.m.Unlock()
	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Updating clients ban status in cache")
	for _, c := range clients {
		s.clients[getClientID(c.UserID, c.GroupID)].Banned = false
	}

	log.Debug().Str("userID", userID.String()).Str("groupID", groupID.String()).Msg("Returning clients unbanning")
	return affected, nil

}

func (s *Service) createClient(ctx context.Context, client *model.Client) (err error) {
	// generate client address
	log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Creating new client")
	log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Acquiring client ip")
	client.Address, err = s.ipaManager.AcquireSingleIP(ctx)
	if err != nil {
		return appError.ErrClient.WithError(err).WithMessage("Failed to acquire client ip").Err()
	}

	// add 32 mask to address
	client.Address = fmt.Sprintf("%s/32", client.Address)

	// generate client key pair
	log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Generating client key pair")
	keys, err := s.keyGenerator.NewKeyPair()
	if err != nil {
		return appError.ErrClient.WithError(err).WithMessage("Failed to generate client key pair").Err()
	}

	client.PublicKey, client.PrivateKey = keys.PublicKey, keys.PrivateKey

	// add client peer
	log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Adding client peer")
	if err = s.addPeer(client.Address, client.PublicKey); err != nil {
		return appError.ErrClient.WithError(err).WithMessage("Failed to add client peer").Err()
	}

	ip, err := netip.ParsePrefix(client.Address)
	if err != nil {
		return appError.ErrClient.WithError(err).WithMessage("Failed to parse client address").Err()
	}

	allowedIPs, err := netip.ParsePrefix(client.AllowedIPs)
	if err != nil {
		return appError.ErrClientInvalidAllowedIPs.WithError(err).Err()
	}

	// add nat rule
	log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Adding client NAT rule")
	if err = s.addNATRule(getClientID(client.UserID, client.GroupID), client.Address, client.AllowedIPs); err != nil {
		return appError.ErrClient.WithError(err).WithMessage("Failed to add client NAT rule").Err()
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
		return appError.ErrClient.WithWrappedError(appError.ErrPostgres.WithError(err)).WithMessage("Failed to create client in db").Err()
	}

	// generate client DNS address
	log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Generating client DNS ip")
	client.DNS, err = ipam.GetFirstCIDRIP(client.AllowedIPs)
	if err != nil {
		return appError.ErrClient.WithError(err).WithMessage("Failed to generate client DNS ip").Err()
	}

	s.m.Lock()
	defer s.m.Unlock()

	log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Adding client to cache")
	s.clients[getClientID(client.UserID, client.GroupID)] = client

	log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Client created")
	return nil
}

func (s *Service) InitServer(ctx context.Context) error {
	var err error
	// set wg server address
	log.Debug().Msg("Setting server address")
	s.config.Address, err = s.ipaManager.GetFirstIP()
	if err != nil {
		return appError.ErrPlatform.WithError(err).WithMessage("Failed to get vpn server address").Err()
	}

	// reserve server address
	log.Debug().Str("Address: ", s.config.Address).Msg("Reserving server ip")
	if _, err = s.ipaManager.AcquireSingleIP(ctx, s.config.Address); err != nil {
		return appError.ErrPlatform.WithError(err).WithMessage("Failed to reserve vpn server address").Err()
	}

	// get server private key
	log.Debug().Msg("Getting server private key from db")
	s.config.PrivateKey, err = s.repository.GetVPNServerPrivateKey(ctx)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return appError.ErrPlatform.WithWrappedError(appError.ErrPostgres.WithError(err)).WithMessage("Failed to get server private key from db").Err()
	}

	// get server public key
	log.Debug().Msg("Getting server public key from db")
	s.config.PublicKey, err = s.repository.GetVPNServerPublicKey(ctx)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return appError.ErrPlatform.WithWrappedError(appError.ErrPostgres.WithError(err)).WithMessage("Failed to get server public key from db").Err()
	}

	// if server private key does not exist generate new key pair
	if s.config.PrivateKey == "" || s.config.PublicKey == "" {
		// generate server key pair
		log.Debug().Msg("Key pair does not exist, generating new key pair")
		keys, err := s.keyGenerator.NewKeyPair()
		if err != nil {
			return appError.ErrPlatform.WithError(err).WithMessage("Failed to generate server key pair").Err()
		}

		s.config.PrivateKey, s.config.PublicKey = keys.PrivateKey, keys.PublicKey

		// save server key pair
		log.Debug().Msg("Saving server private key pair to db")
		if err = s.repository.SetVPNServerPrivateKey(ctx, s.config.PrivateKey); err != nil {
			return appError.ErrPlatform.WithWrappedError(appError.ErrPostgres.WithError(err)).WithMessage("Failed to save server private key to db").Err()
		}
		log.Debug().Msg("Saving server public key pair to db")
		if err = s.repository.SetVPNServerPublicKey(ctx, s.config.PublicKey); err != nil {
			return appError.ErrPlatform.WithWrappedError(appError.ErrPostgres.WithError(err)).WithMessage("Failed to save server public key to db").Err()
		}
	}

	log.Debug().Msg("Create server")
	if err = s.createServer(); err != nil {
		return appError.ErrPlatform.WithError(err).WithMessage("Failed to create server").Err()
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
		return appError.ErrPlatform.WithError(appError.ErrPostgres.WithError(err).Err()).WithMessage("Failed to get clients from db").Err()
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
			errs = multierror.Append(errs, appError.ErrPlatform.WithError(err).WithMessage("Failed to generate client DNS ip").Err())
			continue
		}
		log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Adding client peer")
		if err = s.addPeer(client.Address, client.PublicKey); err != nil {
			errs = multierror.Append(errs, appError.ErrPlatform.WithError(err).WithMessage("Failed to add client peer").Err())
			continue
		}

		// add nat rule
		log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Adding client NAT rule")
		if err = s.addNATRule(getClientID(client.UserID, client.GroupID), client.Address, client.AllowedIPs); err != nil {
			errs = multierror.Append(errs, appError.ErrPlatform.WithError(err).WithMessage("Failed to add client NAT rule").Err())
			continue
		}

		// if user is banned add block rule
		log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Bool("banned", client.Banned).Msg("Adding client blocking rule if user is banned")
		if client.Banned {
			if err = s.addBlockRule(getClientID(client.UserID, client.GroupID), client.Address); err != nil {
				errs = multierror.Append(errs, appError.ErrPlatform.WithError(err).WithMessage("Failed to add client blocking rule").Err())
				continue
			}
		}

		log.Debug().Str("userID", client.UserID.String()).Str("groupID", client.GroupID.String()).Msg("Adding client to cache")
		s.clients[getClientID(client.UserID, client.GroupID)] = client
	}

	if errs != nil {
		return appError.ErrPlatform.WithError(errs).WithMessage("Failed to create clients").Err()
	}

	log.Debug().Msg("Clients created")
	return nil
}
