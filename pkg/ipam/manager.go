package ipam

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	goipam "github.com/metal-stack/go-ipam"
	"net"
	"net/netip"
)

type (
	IPAManager struct {
		ipaManager goipam.Ipamer
		cidr       string
	}

	PostgresConfig struct {
		Host     string
		Port     string
		Username string
		Password string
		Database string
		SSLMode  string
	}

	Dependencies struct {
		PostgresConfig PostgresConfig
		CIDR           string
	}
)

func NewIPAManager(deps Dependencies) (*IPAManager, error) {
	storage, err := goipam.NewPostgresStorage(
		deps.PostgresConfig.Host,
		deps.PostgresConfig.Port,
		deps.PostgresConfig.Username,
		deps.PostgresConfig.Password,
		deps.PostgresConfig.Database,
		goipam.SSLMode(deps.PostgresConfig.SSLMode),
	)

	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	ipam := goipam.NewWithStorage(storage)

	if deps.CIDR == "" {
		return nil, fmt.Errorf("cidr must be specifid")
	}

	_, err = ipam.PrefixFrom(ctx, deps.CIDR)

	if err != nil {
		if !errors.Is(err, goipam.ErrNotFound) {
			return nil, err
		}
		if _, err = ipam.NewPrefix(ctx, deps.CIDR); err != nil {
			return nil, err
		}
	}

	return &IPAManager{
		ipaManager: ipam,
		cidr:       deps.CIDR,
	}, nil
}

func (m *IPAManager) AcquireChildCIDR(ctx context.Context, blockSize uint32) (*IPAManager, error) {
	prefix, err := m.ipaManager.AcquireChildPrefix(ctx, m.cidr, uint8(blockSize))
	if err != nil {
		return nil, err
	}
	return &IPAManager{
		ipaManager: m.ipaManager,
		cidr:       prefix.Cidr,
	}, nil
}

func (m *IPAManager) GetChildCIDR(ctx context.Context, cidr string) (*IPAManager, error) {
	prefix, err := m.ipaManager.PrefixFrom(ctx, cidr)
	if err != nil {
		return nil, err
	}
	return &IPAManager{
		ipaManager: m.ipaManager,
		cidr:       prefix.Cidr,
	}, nil
}

func (m *IPAManager) ReleaseChildCIDR(ctx context.Context, childCIDR string) error {
	// release all IPs in the CIDR
	prefix, err := m.ipaManager.PrefixFrom(ctx, childCIDR)
	if err != nil {
		return err
	}

	addr, netCIDR, err := net.ParseCIDR(prefix.Cidr)
	if err != nil {
		return err
	}

	ip := addr.String()

	for {
		if err = m.ipaManager.ReleaseIPFromPrefix(ctx, prefix.Cidr, ip); err != nil {
			if !errors.Is(err, goipam.ErrNotFound) {
				return err
			}
		}
		// get next IP
		ip = netip.MustParseAddr(ip).Next().String()

		if !netCIDR.Contains(net.ParseIP(ip)) {
			break
		}
	}
	prefix, err = m.ipaManager.PrefixFrom(ctx, childCIDR)
	if err != nil {
		return err
	}

	return m.ipaManager.ReleaseChildPrefix(ctx, prefix)
}

func (m *IPAManager) AcquireSingleIP(ctx context.Context, specificIP ...string) (string, error) {
	if len(specificIP) > 0 {
		_, err := m.ipaManager.AcquireSpecificIP(ctx, m.cidr, specificIP[0])
		if err != nil && !errors.Is(err, goipam.ErrAlreadyAllocated) {
			return "", err
		}
		return specificIP[0], nil
	}

	ip, err := m.ipaManager.AcquireIP(ctx, m.cidr)
	if err != nil {
		return "", err
	}
	return ip.IP.String(), nil
}

func (m *IPAManager) ReleaseSingleIP(ctx context.Context, ip string) error {
	return m.ipaManager.ReleaseIPFromPrefix(ctx, m.cidr, ip)
}

func (m *IPAManager) GetFirstIP() (string, error) {
	return GetFirstCIDRIP(m.cidr)
}

func (m *IPAManager) GetCIDR() string {
	return m.cidr
}

func GetFirstCIDRIP(cidr string) (string, error) {
	_, parsedCIDR, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err

	}
	return int2ip(ip2int(parsedCIDR.IP) + uint32(1)).String(), nil
}

func ip2int(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}
