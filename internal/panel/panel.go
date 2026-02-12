package panel

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/sartoopjj/dnsttui/internal/database"
	"github.com/sartoopjj/dnsttui/internal/panel/components"
	"github.com/sartoopjj/dnsttui/internal/shadowsocks"
)

// ErrRestart is returned by Start when the panel should be restarted.
var ErrRestart = errors.New("panel restart requested")

//go:embed static
var staticFS embed.FS

// Panel is the web management panel server.
type Panel struct {
	db        *database.DB
	ss        *shadowsocks.Server
	mux       *http.ServeMux
	basePath  string // e.g. "/a8f3b2c1"
	restartCh chan struct{}
}

// New creates a new Panel.
func New(db *database.DB, ss *shadowsocks.Server, basePath string) *Panel {
	p := &Panel{
		db:        db,
		ss:        ss,
		mux:       http.NewServeMux(),
		basePath:  basePath,
		restartCh: make(chan struct{}, 1),
	}
	p.setupRoutes()
	return p
}

func (p *Panel) setupRoutes() {
	// Static files
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("static fs: %v", err)
	}
	p.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Auth routes
	p.mux.HandleFunc("GET /login", p.handleLoginPage)
	p.mux.HandleFunc("POST /login", p.handleLogin)
	p.mux.HandleFunc("GET /logout", p.handleLogout)

	// Protected routes
	p.mux.HandleFunc("GET /", p.requireAuth(p.handleDashboard))
	p.mux.HandleFunc("GET /users", p.requireAuth(p.handleUsersPage))
	p.mux.HandleFunc("POST /users", p.requireAuth(p.handleCreateUser))
	p.mux.HandleFunc("GET /users/{id}/edit", p.requireAuth(p.handleEditUserForm))
	p.mux.HandleFunc("GET /users/{id}", p.requireAuth(p.handleGetUserRow))
	p.mux.HandleFunc("PUT /users/{id}", p.requireAuth(p.handleUpdateUser))
	p.mux.HandleFunc("DELETE /users/{id}", p.requireAuth(p.handleDeleteUser))
	p.mux.HandleFunc("GET /users/{id}/config", p.requireAuth(p.handleUserConfig))
	p.mux.HandleFunc("POST /users/{id}/toggle", p.requireAuth(p.handleToggleUser))
	p.mux.HandleFunc("POST /users/{id}/reset", p.requireAuth(p.handleResetTraffic))
	p.mux.HandleFunc("GET /settings", p.requireAuth(p.handleSettingsPage))
	p.mux.HandleFunc("POST /settings", p.requireAuth(p.handleUpdateSettings))
	p.mux.HandleFunc("POST /settings/password", p.requireAuth(p.handleChangePassword))
	p.mux.HandleFunc("POST /settings/restart", p.requireAuth(p.handleRestart))
	p.mux.HandleFunc("GET /diagnostics", p.requireAuth(p.handleDiagnosticsPage))
	p.mux.HandleFunc("GET /help", p.requireAuth(p.handleHelpPage))
}

// Start starts the panel HTTP server. If domain is set, uses ACME TLS.
func (p *Panel) Start(ctx context.Context, addr, domain, acmeEmail string) error {
	// Build the outer mux that mounts all panel routes under basePath
	outerMux := http.NewServeMux()

	// Wrap inner mux to inject basePath into request context and log access
	inner := accessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := components.WithBasePath(r.Context(), p.basePath)
		p.mux.ServeHTTP(w, r.WithContext(ctx))
	}))

	if p.basePath != "" {
		outerMux.Handle(p.basePath+"/", http.StripPrefix(p.basePath, inner))
		// Return 404 for any path outside the base path (security: don't reveal panel location)
		outerMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
	} else {
		outerMux.Handle("/", inner)
	}

	// Start session cleanup goroutine
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.db.CleanExpiredSessions()
			}
		}
	}()

	server := &http.Server{
		Addr:         addr,
		Handler:      outerMux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// restartErr captures whether shutdown was triggered by a restart request
	var restartErr error
	go func() {
		select {
		case <-ctx.Done():
		case <-p.restartCh:
			restartErr = ErrRestart
		}
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutCtx)
	}()

	if domain != "" {
		// Use certmagic for auto-TLS
		certmagic.DefaultACME.Email = acmeEmail
		certmagic.DefaultACME.Agreed = true

		tlsConfig, err := certmagic.TLS([]string{domain})
		if err != nil {
			log.Printf("certmagic TLS failed, falling back to HTTP: %v", err)
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				return err
			}
			return restartErr
		}

		server.TLSConfig = tlsConfig
		ln, err := tls.Listen("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("tls listen: %w", err)
		}

		// Also serve HTTP for ACME challenges
		go func() {
			httpServer := &http.Server{
				Addr: ":80",
				Handler: certmagic.DefaultACME.HTTPChallengeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, "https://"+r.Host+r.URL.String(), http.StatusMovedPermanently)
				})),
			}
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("ACME HTTP server: %v", err)
			}
		}()

		if err := server.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
			return err
		}
		return restartErr
	}

	// Plain HTTP
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return restartErr
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// accessLog is HTTP middleware that logs each request (skipping static files).
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		log.Printf("panel: %s %s %d %s [%s]", r.Method, r.URL.Path, rw.status, time.Since(start).Round(time.Millisecond), r.RemoteAddr)
	})
}
