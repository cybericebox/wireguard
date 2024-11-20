package service

import (
	"bytes"
	"fmt"
	"github.com/cybericebox/wireguard/internal/model"
	"github.com/cybericebox/wireguard/pkg/appError"
	"github.com/rs/zerolog/log"
	"io"
	"os"
	"os/exec"
	"text/template"
)

const (
	wgQuickBin           = "wg-quick"
	wgManageBin          = "wg"
	nic                  = "wg0"
	configPath           = "/etc/wireguard"
	keepalive            = 25
	serverConfigTemplate = `[Interface]
Address = {{.Address}}
ListenPort = {{.Port}}
PrivateKey = {{.PrivateKey}}
SaveConfig = true

PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT;
PostUp = sysctl -w -q net.ipv4.ip_forward=1;
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT;
PostDown = sysctl -w -q net.ipv4.ip_forward=0;`
	clientConfigTemplate = `[Interface]
PrivateKey = {{.PrivateKey}}
Address = {{.Address}}
DNS = {{.DNS}}, 1.1.1.1

[Peer]
PublicKey = {{.PublicKey}}
AllowedIPs = {{.AllowedIPs}}
Endpoint = {{.Endpoint}}
PersistentKeepalive = 25
`
)

func (s *Service) addPeer(ip, publicKey string) error {
	log.Debug().Msgf("Peer with publickey [ %s ] is adding to %s", publicKey, ip)

	command := fmt.Sprintf("%s set %s peer %s persistent-keepalive %d allowed-ips %s", wgManageBin, nic, publicKey, keepalive, ip)

	log.Debug().Str("command", command).Msg("Adding peer")

	if err := exec.Command("/bin/sh", "-c", command).Run(); err != nil {
		return appError.ErrWireguard.WithError(err).WithMessage("Failed to add peer").WithContext("command", command).Raise()
	}

	command = fmt.Sprintf("ip -4 route add %s dev %s", ip, nic)

	log.Debug().Str("command", command).Msg("Adding route")

	if err := exec.Command("/bin/sh", "-c", command).Run(); err != nil {
		return appError.ErrWireguard.WithError(err).WithMessage("Failed to add route").WithContext("command", command).Raise()
	}

	return nil
}

func (s *Service) deletePeer(ip, publicKey string) error {
	log.Debug().Msgf("Peer with publickey [ %s ] is deleting from %s", publicKey, ip)

	command := fmt.Sprintf("%s set %s peer %s remove", wgManageBin, nic, publicKey)

	log.Debug().Str("command", command).Msg("Deleting peer")

	if err := exec.Command("/bin/sh", "-c", command).Run(); err != nil {
		return appError.ErrWireguard.WithError(err).WithMessage("Failed to delete peer").WithContext("command", command).Raise()
	}

	command = fmt.Sprintf("ip -4 route delete %s dev %s", ip, nic)

	log.Debug().Str("command", command).Msg("Deleting route")

	if err := exec.Command("/bin/sh", "-c", command).Run(); err != nil {
		return appError.ErrWireguard.WithError(err).WithMessage("Failed to delete route").WithContext("command", command).Raise()
	}

	return nil
}

func (s *Service) generateServerConfig() (string, error) {
	config, err := s.generateConfig(serverConfigTemplate, s.config)
	if err != nil {
		return "", appError.ErrWireguard.WithError(err).WithMessage("Failed to generate server config").Raise()
	}

	return config, nil
}

func (s *Service) generateClientConfig(data *model.Client) (string, error) {
	// populate server endpoint to user config
	data.Endpoint = s.config.Endpoint

	// populate server public key to user config
	data.PublicKey = s.config.PublicKey

	config, err := s.generateConfig(clientConfigTemplate, data)
	if err != nil {
		return "", appError.ErrWireguard.WithError(err).WithMessage("Failed to generate client config").Raise()
	}

	return config, nil
}

func (s *Service) generateConfig(tmpl string, data interface{}) (string, error) {
	var tpl bytes.Buffer

	t, err := template.New("config").Parse(tmpl)
	if err != nil {
		return "", appError.ErrWireguard.WithError(err).WithMessage("Failed to parse template").Raise()
	}

	if err = t.Execute(&tpl, data); err != nil {
		return "", appError.ErrWireguard.WithError(err).WithMessage("Failed to execute template").Raise()
	}

	return tpl.String(), nil
}

func writeToFile(filename string, data string) error {
	file, err := os.Create(filename)
	if err != nil {
		return appError.ErrWireguard.WithError(err).WithMessage("Failed to create file").WithContext("filename", filename).Raise()
	}
	defer func() {
		if err = file.Close(); err != nil {
			log.Fatal().Err(err).Msg("failed to close file")
		}
	}()

	if _, err = io.WriteString(file, data); err != nil {
		return appError.ErrWireguard.WithError(err).WithMessage("Failed to write to file").WithContext("filename", filename).Raise()
	}

	if err = file.Sync(); err != nil {
		return appError.ErrWireguard.WithError(err).WithMessage("Failed to sync file").WithContext("filename", filename).Raise()
	}

	return nil
}

func upInterface() error {
	command := wgQuickBin + " up " + nic

	log.Info().Str("interface", nic).Msg("Interface is called to be up")

	if err := exec.Command("/bin/sh", "-c", command).Run(); err != nil {
		return appError.ErrWireguard.WithError(err).WithMessage("Failed to up interface").WithContext("interface", nic).Raise()
	}

	return nil
}
