package database

import (
	"database/sql"
	"fmt"
	"time"
)

// CreateUser inserts a new SS user.
func (db *DB) CreateUser(username, password string, trafficLimit int64, expireAt *time.Time) (*SSUser, error) {
	now := nowUTC()
	result, err := db.conn.Exec(`
		INSERT INTO ss_users (username, password, enabled, traffic_limit, expire_at, created_at, updated_at)
		VALUES (?, ?, 1, ?, ?, ?, ?)
	`, username, password, trafficLimit, expireAt, now, now)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	id, _ := result.LastInsertId()
	return &SSUser{
		ID:           id,
		Username:     username,
		Password:     password,
		Enabled:      true,
		TrafficLimit: trafficLimit,
		ExpireAt:     expireAt,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}, nil
}

// GetUser returns a user by ID.
func (db *DB) GetUser(id int64) (*SSUser, error) {
	u := &SSUser{}
	row := db.conn.QueryRow(`SELECT
		id, username, password, enabled, traffic_limit,
		traffic_used_up, traffic_used_down, expire_at, created_at, updated_at
		FROM ss_users WHERE id = ?`, id)
	err := row.Scan(
		&u.ID, &u.Username, &u.Password, &u.Enabled, &u.TrafficLimit,
		&u.TrafficUsedUp, &u.TrafficUsedDown, scanNullTime(&u.ExpireAt), scanTime(&u.CreatedAt), scanTime(&u.UpdatedAt),
	)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return u, nil
}

// ListUsers returns all SS users.
func (db *DB) ListUsers() ([]SSUser, error) {
	rows, err := db.conn.Query(`SELECT
		id, username, password, enabled, traffic_limit,
		traffic_used_up, traffic_used_down, expire_at, created_at, updated_at
		FROM ss_users ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []SSUser
	for rows.Next() {
		var u SSUser
		if err := rows.Scan(
			&u.ID, &u.Username, &u.Password, &u.Enabled, &u.TrafficLimit,
			&u.TrafficUsedUp, &u.TrafficUsedDown, scanNullTime(&u.ExpireAt), scanTime(&u.CreatedAt), scanTime(&u.UpdatedAt),
		); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// ListActiveUsers returns all active (enabled, not expired, not over-limit) SS users.
func (db *DB) ListActiveUsers() ([]SSUser, error) {
	rows, err := db.conn.Query(`SELECT
		id, username, password, enabled, traffic_limit,
		traffic_used_up, traffic_used_down, expire_at, created_at, updated_at
		FROM ss_users
		WHERE enabled = 1
		AND (expire_at IS NULL OR expire_at > ?)
		AND (traffic_limit = 0 OR (traffic_used_up + traffic_used_down) < traffic_limit)
		ORDER BY id`, nowUTC())
	if err != nil {
		return nil, fmt.Errorf("list active users: %w", err)
	}
	defer rows.Close()

	var users []SSUser
	for rows.Next() {
		var u SSUser
		if err := rows.Scan(
			&u.ID, &u.Username, &u.Password, &u.Enabled, &u.TrafficLimit,
			&u.TrafficUsedUp, &u.TrafficUsedDown, scanNullTime(&u.ExpireAt), scanTime(&u.CreatedAt), scanTime(&u.UpdatedAt),
		); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// UpdateUser updates a user's fields.
func (db *DB) UpdateUser(id int64, username, password string, enabled bool, trafficLimit int64, expireAt *time.Time) error {
	_, err := db.conn.Exec(`UPDATE ss_users SET
		username = ?, password = ?, enabled = ?, traffic_limit = ?,
		expire_at = ?, updated_at = ?
		WHERE id = ?`,
		username, password, enabled, trafficLimit, expireAt, nowUTC(), id,
	)
	return err
}

// DeleteUser deletes a user by ID.
func (db *DB) DeleteUser(id int64) error {
	_, err := db.conn.Exec(`DELETE FROM ss_users WHERE id = ?`, id)
	return err
}

// ToggleUser toggles a user's enabled status.
func (db *DB) ToggleUser(id int64) (*SSUser, error) {
	_, err := db.conn.Exec(`UPDATE ss_users SET enabled = NOT enabled, updated_at = ? WHERE id = ?`, nowUTC(), id)
	if err != nil {
		return nil, err
	}
	return db.GetUser(id)
}

// ResetTraffic resets a user's traffic counters.
func (db *DB) ResetTraffic(id int64) (*SSUser, error) {
	_, err := db.conn.Exec(`UPDATE ss_users SET traffic_used_up = 0, traffic_used_down = 0, updated_at = ? WHERE id = ?`, nowUTC(), id)
	if err != nil {
		return nil, err
	}
	return db.GetUser(id)
}

// IncrementTraffic adds bytes to a user's traffic counters.
func (db *DB) IncrementTraffic(id int64, bytesUp, bytesDown int64) error {
	_, err := db.conn.Exec(`UPDATE ss_users SET
		traffic_used_up = traffic_used_up + ?,
		traffic_used_down = traffic_used_down + ?
		WHERE id = ?`,
		bytesUp, bytesDown, id,
	)
	return err
}

// RecordTraffic inserts a traffic log entry.
func (db *DB) RecordTraffic(userID, bytesUp, bytesDown int64) error {
	_, err := db.conn.Exec(`INSERT INTO traffic_log (user_id, bytes_up, bytes_down, recorded_at) VALUES (?, ?, ?, ?)`,
		userID, bytesUp, bytesDown, nowUTC(),
	)
	return err
}

// GetUserCount returns the total number of users.
func (db *DB) GetUserCount() (int, error) {
	var count int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM ss_users`).Scan(&count)
	return count, err
}

// GetActiveUserCount returns the number of active users.
func (db *DB) GetActiveUserCount() (int, error) {
	var count int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM ss_users
		WHERE enabled = 1
		AND (expire_at IS NULL OR expire_at > ?)
		AND (traffic_limit = 0 OR (traffic_used_up + traffic_used_down) < traffic_limit)`,
		nowUTC(),
	).Scan(&count)
	return count, err
}

// GetTotalTraffic returns total traffic across all users.
func (db *DB) GetTotalTraffic() (up, down int64, err error) {
	err = db.conn.QueryRow(`SELECT COALESCE(SUM(traffic_used_up),0), COALESCE(SUM(traffic_used_down),0) FROM ss_users`).Scan(&up, &down)
	return
}

// UserExists checks if a username already exists, optionally excluding an ID.
func (db *DB) UserExists(username string, excludeID int64) (bool, error) {
	var count int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM ss_users WHERE username = ? AND id != ?`, username, excludeID).Scan(&count)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	return count > 0, nil
}
