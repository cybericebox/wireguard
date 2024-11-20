package service

import (
	"fmt"
	"github.com/cybericebox/wireguard/pkg/appError"
	"github.com/rs/zerolog/log"
	"os/exec"
)

const (
	iptablesNat = `iptables -t nat -%s POSTROUTING -o eth+ -s %s -d %s -j MASQUERADE -m comment --comment "client %s"`
	blockRule   = `iptables -%s FORWARD -s %s -j DROP -m comment --comment "ban client %s"`
)

func (s *Service) addNATRule(id, ip, destCidr string) error {
	command := fmt.Sprintf(iptablesNat, "A", ip, destCidr, id)

	log.Debug().Str("command", command).Msg("Adding NAT rule")

	if err := exec.Command("/bin/sh", "-c", command).Run(); err != nil {
		return appError.ErrIptables.WithError(err).WithMessage("Failed to add NAT rule").WithContext("command", command).Raise()
	}
	return nil
}

func (s *Service) deleteNATRule(id, ip, destCidr string) error {
	command := fmt.Sprintf(iptablesNat, "D", ip, destCidr, id)

	log.Debug().Str("command", command).Msg("Deleting NAT rule")

	if err := exec.Command("/bin/sh", "-c", command).Run(); err != nil {
		return appError.ErrIptables.WithError(err).WithMessage("Failed to delete NAT rule").WithContext("command", command).Raise()
	}
	return nil
}

func (s *Service) addBlockRule(id, ip string) error {
	command := fmt.Sprintf(blockRule, "A", ip, id)

	log.Debug().Str("command", command).Msg("Adding blocking rule")

	if err := exec.Command("/bin/sh", "-c", command).Run(); err != nil {
		return appError.ErrIptables.WithError(err).WithMessage("Failed to add blocking rule").WithContext("command", command).Raise()
	}
	return nil
}

func (s *Service) deleteBlockRule(id, ip string) error {
	command := fmt.Sprintf(blockRule, "D", ip, id)

	log.Debug().Str("command", command).Msg("Deleting blocking rule")

	if err := exec.Command("/bin/sh", "-c", command).Run(); err != nil {
		return appError.ErrIptables.WithError(err).WithMessage("Failed to delete blocking rule").WithContext("command", command).Raise()
	}
	return nil
}
