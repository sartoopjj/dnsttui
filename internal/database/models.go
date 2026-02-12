package database

import (
	"fmt"
	"time"
)

// timeScanner wraps *time.Time to handle SQLite DATETIME text values.
type timeScanner struct{ t *time.Time }

func (s *timeScanner) Scan(src interface{}) error {
	switch v := src.(type) {
	case time.Time:
		*s.t = v
	case string:
		p, err := parseTimeString(v)
		if err != nil {
			return err
		}
		*s.t = p
	case nil:
		*s.t = time.Time{}
	default:
		return fmt.Errorf("cannot scan %T into time.Time", src)
	}
	return nil
}

func scanTime(t *time.Time) *timeScanner { return &timeScanner{t: t} }

// nullTimeScanner wraps **time.Time to handle nullable SQLite DATETIME text values.
type nullTimeScanner struct{ t **time.Time }

func (s *nullTimeScanner) Scan(src interface{}) error {
	if src == nil {
		*s.t = nil
		return nil
	}
	t := &time.Time{}
	switch v := src.(type) {
	case time.Time:
		*t = v
	case string:
		if v == "" {
			*s.t = nil
			return nil
		}
		p, err := parseTimeString(v)
		if err != nil {
			return err
		}
		*t = p
	default:
		return fmt.Errorf("cannot scan %T into *time.Time", src)
	}
	*s.t = t
	return nil
}

func scanNullTime(t **time.Time) *nullTimeScanner { return &nullTimeScanner{t: t} }

// parseTimeString tries several common formats for SQLite datetime values.
func parseTimeString(s string) (time.Time, error) {
	formats := []string{
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02T15:04:05.999999999Z",
		time.RFC3339,
		time.RFC3339Nano,
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse %q as time", s)
}

// nowUTC returns the current time formatted for SQLite storage.
func nowUTC() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05")
}

// PanelConfig holds all server configuration stored in SQLite.
type PanelConfig struct {
	ID              int64     `json:"id"`
	AdminUser       string    `json:"admin_user"`
	AdminPass       string    `json:"-"`
	PanelBasePath   string    `json:"panel_base_path"`
	PanelDomain     string    `json:"panel_domain"`
	PanelPort       int       `json:"panel_port"`
	ACMEEmail       string    `json:"acme_email"`
	DNSTTUDPAddr    string    `json:"dnstt_udp_addr"`
	DNSTTDomain     string    `json:"dnstt_domain"`
	DNSTTPrivkey    string    `json:"-"`
	DNSTTPubkey     string    `json:"dnstt_pubkey"`
	DNSTTMTU        int       `json:"dnstt_mtu"`
	SSListenAddr    string    `json:"ss_listen_addr"`
	SSPort          int       `json:"ss_port"`
	SSMethod        string    `json:"ss_method"`
	SSServerKey     string    `json:"ss_server_key"`
	DNSResolverAddr string    `json:"dns_resolver_addr"`
	DNSResolverPort int       `json:"dns_resolver_port"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// SSUser represents a Shadowsocks user.
type SSUser struct {
	ID              int64      `json:"id"`
	Username        string     `json:"username"`
	Password        string     `json:"password"` // base64 PSK
	Enabled         bool       `json:"enabled"`
	TrafficLimit    int64      `json:"traffic_limit"`     // bytes, 0 = unlimited
	TrafficUsedUp   int64      `json:"traffic_used_up"`   // bytes uploaded
	TrafficUsedDown int64      `json:"traffic_used_down"` // bytes downloaded
	ExpireAt        *time.Time `json:"expire_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// IsExpired returns true if the user has an expiry date that has passed.
func (u *SSUser) IsExpired() bool {
	if u.ExpireAt == nil {
		return false
	}
	return time.Now().After(*u.ExpireAt)
}

// IsOverLimit returns true if the user has exceeded their traffic limit.
func (u *SSUser) IsOverLimit() bool {
	if u.TrafficLimit == 0 {
		return false
	}
	return (u.TrafficUsedUp + u.TrafficUsedDown) >= u.TrafficLimit
}

// IsActive returns true if the user is enabled and not expired/over-limit.
func (u *SSUser) IsActive() bool {
	return u.Enabled && !u.IsExpired() && !u.IsOverLimit()
}

// TotalTraffic returns total bytes used (up + down).
func (u *SSUser) TotalTraffic() int64 {
	return u.TrafficUsedUp + u.TrafficUsedDown
}

// TrafficLog records periodic traffic samples.
type TrafficLog struct {
	ID         int64     `json:"id"`
	UserID     int64     `json:"user_id"`
	BytesUp    int64     `json:"bytes_up"`
	BytesDown  int64     `json:"bytes_down"`
	RecordedAt time.Time `json:"recorded_at"`
}
