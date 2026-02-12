package shadowsocks

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
	"github.com/sartoopjj/dnsttui/internal/database"
)

// Server manages a multi-user Shadowsocks 2022 server.
type Server struct {
	db       *database.DB
	mu       sync.RWMutex
	service  *shadowaead_2022.MultiService[int64]
	listener net.Listener
	cancel   context.CancelFunc

	// Active connection counter
	activeConns atomic.Int64

	// Traffic tracking
	trafficMu   sync.Mutex
	trafficUp   map[int64]int64 // user_id -> bytes
	trafficDown map[int64]int64
}

// NewServer creates a new Shadowsocks server.
func NewServer(db *database.DB) *Server {
	return &Server{
		db:          db,
		trafficUp:   make(map[int64]int64),
		trafficDown: make(map[int64]int64),
	}
}

// GenerateKey generates a random base64-encoded key suitable for SS2022.
// For aes-128-gcm the key is 16 bytes; for aes-256-gcm it is 32 bytes.
func GenerateKey(method string) (string, error) {
	var keyLen int
	switch method {
	case "2022-blake3-aes-128-gcm":
		keyLen = 16
	case "2022-blake3-aes-256-gcm":
		keyLen = 32
	default:
		keyLen = 16
	}
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// handler implements the sing shadowsocks handler interfaces.
type handler struct {
	server *Server
}

func (h *handler) NewConnection(ctx context.Context, conn net.Conn, m metadata.Metadata) error {
	destConn, err := net.DialTimeout("tcp", m.Destination.String(), 30*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", m.Destination, err)
	}
	defer destConn.Close()

	// userID is in context from sing-shadowsocks (via auth.ContextWithUser)
	userID := int64(0)
	if uid, ok := auth.UserFromContext[int64](ctx); ok {
		userID = uid
	}

	h.server.activeConns.Add(1)
	start := time.Now()
	log.Printf("ss: connect user=%d dest=%s", userID, m.Destination)
	defer func() {
		h.server.activeConns.Add(-1)
		log.Printf("ss: disconnect user=%d dest=%s duration=%s", userID, m.Destination, time.Since(start).Round(time.Second))
	}()

	// Bidirectional copy with traffic tracking
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(destConn, conn)
		if userID > 0 {
			h.server.addTraffic(userID, n, 0)
		}
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(conn, destConn)
		if userID > 0 {
			h.server.addTraffic(userID, 0, n)
		}
	}()
	wg.Wait()
	return nil
}

func (h *handler) NewPacketConnection(ctx context.Context, conn network.PacketConn, m metadata.Metadata) error {
	defer conn.Close()
	// UDP relay - simple implementation
	for {
		buff := buf.NewPacket()
		dest, err := conn.ReadPacket(buff)
		if err != nil {
			buff.Release()
			return err
		}
		// Forward UDP packet
		udpConn, err := net.DialTimeout("udp", dest.String(), 10*time.Second)
		if err != nil {
			buff.Release()
			continue
		}
		udpConn.Write(buff.Bytes())
		buff.Release()
		udpConn.Close()
	}
}

func (h *handler) NewError(ctx context.Context, err error) {
	if err != nil {
		log.Printf("shadowsocks error: %v", err)
	}
}

func (s *Server) addTraffic(userID, up, down int64) {
	s.trafficMu.Lock()
	defer s.trafficMu.Unlock()
	s.trafficUp[userID] += up
	s.trafficDown[userID] += down
}

// flushTraffic writes accumulated traffic to the database.
func (s *Server) flushTraffic() {
	s.trafficMu.Lock()
	up := s.trafficUp
	down := s.trafficDown
	s.trafficUp = make(map[int64]int64)
	s.trafficDown = make(map[int64]int64)
	s.trafficMu.Unlock()

	for userID, bytesUp := range up {
		bytesDown := down[userID]
		if bytesUp > 0 || bytesDown > 0 {
			if err := s.db.IncrementTraffic(userID, bytesUp, bytesDown); err != nil {
				log.Printf("flush traffic for user %d: %v", userID, err)
			}
		}
	}
	// Check for any users with only download traffic
	for userID, bytesDown := range down {
		if _, ok := up[userID]; !ok && bytesDown > 0 {
			if err := s.db.IncrementTraffic(userID, 0, bytesDown); err != nil {
				log.Printf("flush traffic for user %d: %v", userID, err)
			}
		}
	}
}

// Start starts the Shadowsocks server.
func (s *Server) Start(ctx context.Context, addr, method, serverKey string) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	// If no server key, generate one and save
	if serverKey == "" {
		var err error
		serverKey, err = GenerateKey(method)
		if err != nil {
			return fmt.Errorf("generate server key: %w", err)
		}
		// Save to DB
		cfg, err := s.db.GetConfig()
		if err == nil {
			cfg.SSServerKey = serverKey
			s.db.UpdateConfig(cfg)
		}
		log.Printf("generated Shadowsocks server key: %s", serverKey)
	}

	h := &handler{server: s}
	service, err := shadowaead_2022.NewMultiServiceWithPassword[int64](
		method,
		serverKey,
		500,
		h,
		nil,
	)
	if err != nil {
		return fmt.Errorf("create SS2022 service: %w", err)
	}

	s.mu.Lock()
	s.service = service
	s.mu.Unlock()

	// Load existing users
	if err := s.ReloadUsers(); err != nil {
		log.Printf("warning: could not load users: %v", err)
	}

	// Start traffic flush ticker
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				s.flushTraffic()
				return
			case <-ticker.C:
				s.flushTraffic()
			}
		}
	}()

	// Listen TCP
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen TCP %s: %w", addr, err)
	}
	s.listener = listener
	log.Printf("Shadowsocks listening on %s", addr)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("accept error: %v", err)
				continue
			}
		}
		go func() {
			if err := service.NewConnection(ctx, conn, metadata.Metadata{}); err != nil {
				log.Printf("connection error: %v", err)
			}
		}()
	}
}

// ReloadUsers reloads the user list from the database into the SS service.
func (s *Server) ReloadUsers() error {
	s.mu.RLock()
	service := s.service
	s.mu.RUnlock()

	if service == nil {
		return nil
	}

	users, err := s.db.ListActiveUsers()
	if err != nil {
		return fmt.Errorf("list active users: %w", err)
	}

	userIDs := make([]int64, len(users))
	userKeys := make([]string, len(users))
	for i, u := range users {
		userIDs[i] = u.ID
		userKeys[i] = u.Password
	}

	err = service.UpdateUsersWithPasswords(userIDs, userKeys)
	if err != nil {
		return fmt.Errorf("update SS users: %w", err)
	}

	log.Printf("loaded %d active Shadowsocks users", len(users))
	return nil
}

// Stop stops the Shadowsocks server.
func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	s.flushTraffic()
}

// ActiveConnections returns the number of active Shadowsocks connections.
func (s *Server) ActiveConnections() int64 {
	return s.activeConns.Load()
}
