package xray

import (
	"encoding/json"
	"fmt"
)

// MahsaNGConfig represents a full MahsaNG/Xray client configuration.
type MahsaNGConfig struct {
	Log       LogConfig  `json:"log"`
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
}

// LogConfig is the Xray log configuration.
type LogConfig struct {
	LogLevel string `json:"loglevel"`
}

// Inbound represents an Xray inbound proxy.
type Inbound struct {
	Port     int             `json:"port"`
	Listen   string          `json:"listen"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings"`
}

// Outbound represents an Xray outbound proxy.
type Outbound struct {
	Protocol       string          `json:"protocol"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings *StreamSettings `json:"streamSettings,omitempty"`
}

// StreamSettings holds transport layer settings.
type StreamSettings struct {
	Network       string         `json:"network"`
	DNSTTSettings *DNSTTSettings `json:"dnsttSettings,omitempty"`
}

// DNSTTSettings holds dnstt transport settings.
type DNSTTSettings struct {
	ServerAddress   string `json:"serverAddress"`
	ServerPublicKey string `json:"serverPublicKey"`
}

// SSServerConfig holds Shadowsocks server settings for the outbound.
type SSServerConfig struct {
	Servers []SSServer `json:"servers"`
}

// SSServer is a single SS server entry.
type SSServer struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Method   string `json:"method"`
	Password string `json:"password"`
}

// GenerateParams holds the parameters needed to generate a MahsaNG config.
type GenerateParams struct {
	DNSResolverAddr string
	DNSResolverPort int
	SSMethod        string
	ServerKey       string
	UserKey         string
	DNSTTDomain     string
	DNSTTPubkey     string
	LocalPort       int // SOCKS port, default 1080
}

// GenerateMahsaNGConfig creates a MahsaNG-compatible Xray JSON config.
func GenerateMahsaNGConfig(params GenerateParams) ([]byte, error) {
	if params.LocalPort == 0 {
		params.LocalPort = 1080
	}

	ssPassword := fmt.Sprintf("%s:%s", params.ServerKey, params.UserKey)

	ssSettings, err := json.Marshal(SSServerConfig{
		Servers: []SSServer{
			{
				Address:  params.DNSResolverAddr,
				Port:     params.DNSResolverPort,
				Method:   params.SSMethod,
				Password: ssPassword,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal ss settings: %w", err)
	}

	socksSettings, err := json.Marshal(map[string]string{"auth": "noauth"})
	if err != nil {
		return nil, fmt.Errorf("marshal socks settings: %w", err)
	}

	config := MahsaNGConfig{
		Log: LogConfig{LogLevel: "warning"},
		Inbounds: []Inbound{
			{
				Port:     params.LocalPort,
				Listen:   "127.0.0.1",
				Protocol: "socks",
				Settings: socksSettings,
			},
		},
		Outbounds: []Outbound{
			{
				Protocol: "shadowsocks",
				Settings: ssSettings,
				StreamSettings: &StreamSettings{
					Network: "dnstt",
					DNSTTSettings: &DNSTTSettings{
						ServerAddress:   params.DNSTTDomain,
						ServerPublicKey: params.DNSTTPubkey,
					},
				},
			},
		},
	}

	return json.MarshalIndent(config, "", "  ")
}
