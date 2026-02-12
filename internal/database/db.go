package database

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// DB wraps the sql.DB connection and provides application-level methods.
type DB struct {
	conn *sql.DB
}

// Open opens or creates an SQLite database at the given path. It enables WAL
// mode and runs migrations automatically.
func Open(dbPath string) (*DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)", dbPath)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	conn.SetMaxOpenConns(1) // SQLite doesn't handle concurrent writes well
	conn.SetMaxIdleConns(1)
	conn.SetConnMaxLifetime(0)

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// Conn returns the underlying *sql.DB for advanced queries.
func (db *DB) Conn() *sql.DB {
	return db.conn
}

func (db *DB) migrate() error {
	_, err := db.conn.Exec(`
	CREATE TABLE IF NOT EXISTS panel_config (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		admin_user TEXT NOT NULL DEFAULT 'admin',
		admin_pass TEXT NOT NULL DEFAULT '',
		panel_base_path TEXT NOT NULL DEFAULT '',
		panel_port INTEGER NOT NULL DEFAULT 8080,
		panel_domain TEXT NOT NULL DEFAULT '',
		acme_email TEXT NOT NULL DEFAULT '',
		dnstt_udp_addr TEXT NOT NULL DEFAULT ':5300',
		dnstt_domain TEXT NOT NULL DEFAULT '',
		dnstt_privkey TEXT NOT NULL DEFAULT '',
		dnstt_pubkey TEXT NOT NULL DEFAULT '',
		dnstt_mtu INTEGER NOT NULL DEFAULT 1232,
		ss_listen_addr TEXT NOT NULL DEFAULT '127.0.0.1',
		ss_port INTEGER NOT NULL DEFAULT 8388,
		ss_method TEXT NOT NULL DEFAULT '2022-blake3-aes-128-gcm',
		ss_server_key TEXT NOT NULL DEFAULT '',
		dns_resolver_addr TEXT NOT NULL DEFAULT '8.8.8.8',
		dns_resolver_port INTEGER NOT NULL DEFAULT 53,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS ss_users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL DEFAULT '',
		enabled INTEGER NOT NULL DEFAULT 1,
		traffic_limit INTEGER NOT NULL DEFAULT 0,
		traffic_used_up INTEGER NOT NULL DEFAULT 0,
		traffic_used_down INTEGER NOT NULL DEFAULT 0,
		expire_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS traffic_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		bytes_up INTEGER NOT NULL DEFAULT 0,
		bytes_down INTEGER NOT NULL DEFAULT 0,
		recorded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES ss_users(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_traffic_log_user ON traffic_log(user_id);
	CREATE INDEX IF NOT EXISTS idx_traffic_log_time ON traffic_log(recorded_at);

	CREATE TABLE IF NOT EXISTS panel_sessions (
		token TEXT PRIMARY KEY,
		expires_at DATETIME NOT NULL
	);
	`)
	if err != nil {
		return err
	}

	// Add panel_base_path column if missing (migration for existing DBs)
	db.conn.Exec(`ALTER TABLE panel_config ADD COLUMN panel_base_path TEXT NOT NULL DEFAULT ''`)

	return nil
}

// InitDefaultConfig inserts the default panel config row if it does not exist.
func (db *DB) InitDefaultConfig(adminUser, adminPassHash, basePath string) error {
	_, err := db.conn.Exec(`
		INSERT OR IGNORE INTO panel_config (id, admin_user, admin_pass, panel_base_path)
		VALUES (1, ?, ?, ?)
	`, adminUser, adminPassHash, basePath)
	return err
}

// ConfigExists returns true if the panel config row exists.
func (db *DB) ConfigExists() (bool, error) {
	var count int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM panel_config WHERE id = 1`).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// GetConfig returns the panel configuration.
func (db *DB) GetConfig() (*PanelConfig, error) {
	cfg := &PanelConfig{}
	row := db.conn.QueryRow(`SELECT
		id, admin_user, admin_pass, panel_base_path, panel_port, panel_domain, acme_email,
		dnstt_udp_addr, dnstt_domain, dnstt_privkey, dnstt_pubkey, dnstt_mtu,
		ss_listen_addr, ss_port, ss_method, ss_server_key,
		dns_resolver_addr, dns_resolver_port, created_at, updated_at
		FROM panel_config WHERE id = 1`)
	err := row.Scan(
		&cfg.ID, &cfg.AdminUser, &cfg.AdminPass, &cfg.PanelBasePath, &cfg.PanelPort, &cfg.PanelDomain,
		&cfg.ACMEEmail, &cfg.DNSTTUDPAddr, &cfg.DNSTTDomain, &cfg.DNSTTPrivkey,
		&cfg.DNSTTPubkey, &cfg.DNSTTMTU, &cfg.SSListenAddr, &cfg.SSPort, &cfg.SSMethod,
		&cfg.SSServerKey, &cfg.DNSResolverAddr, &cfg.DNSResolverPort,
		scanTime(&cfg.CreatedAt), scanTime(&cfg.UpdatedAt),
	)
	if err != nil {
		return nil, fmt.Errorf("get config: %w", err)
	}
	return cfg, nil
}

// UpdateConfig updates the panel configuration. Only updates provided fields.
func (db *DB) UpdateConfig(cfg *PanelConfig) error {
	_, err := db.conn.Exec(`UPDATE panel_config SET
		admin_user = ?, admin_pass = ?, panel_base_path = ?, panel_port = ?, panel_domain = ?,
		acme_email = ?, dnstt_udp_addr = ?, dnstt_domain = ?, dnstt_privkey = ?,
		dnstt_pubkey = ?, dnstt_mtu = ?, ss_listen_addr = ?, ss_port = ?,
		ss_method = ?, ss_server_key = ?, dns_resolver_addr = ?, dns_resolver_port = ?,
		updated_at = ?
		WHERE id = 1`,
		cfg.AdminUser, cfg.AdminPass, cfg.PanelBasePath, cfg.PanelPort, cfg.PanelDomain,
		cfg.ACMEEmail, cfg.DNSTTUDPAddr, cfg.DNSTTDomain, cfg.DNSTTPrivkey,
		cfg.DNSTTPubkey, cfg.DNSTTMTU, cfg.SSListenAddr, cfg.SSPort,
		cfg.SSMethod, cfg.SSServerKey, cfg.DNSResolverAddr, cfg.DNSResolverPort,
		nowUTC(),
	)
	return err
}

// UpdateAdminPassword updates only the admin password hash.
func (db *DB) UpdateAdminPassword(passHash string) error {
	_, err := db.conn.Exec(`UPDATE panel_config SET admin_pass = ?, updated_at = ? WHERE id = 1`, passHash, nowUTC())
	return err
}

// --- Session management ---

// CreateSession stores a session token in the database.
func (db *DB) CreateSession(token, expiresAt string) error {
	_, err := db.conn.Exec(`INSERT OR REPLACE INTO panel_sessions (token, expires_at) VALUES (?, ?)`, token, expiresAt)
	return err
}

// ValidateSession checks if a session token is valid and not expired.
func (db *DB) ValidateSession(token string) (bool, error) {
	var count int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM panel_sessions WHERE token = ? AND expires_at > ?`, token, nowUTC()).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// DeleteSession removes a session token.
func (db *DB) DeleteSession(token string) error {
	_, err := db.conn.Exec(`DELETE FROM panel_sessions WHERE token = ?`, token)
	return err
}

// CleanExpiredSessions removes all expired sessions.
func (db *DB) CleanExpiredSessions() error {
	_, err := db.conn.Exec(`DELETE FROM panel_sessions WHERE expires_at <= ?`, nowUTC())
	return err
}
