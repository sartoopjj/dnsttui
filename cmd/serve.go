package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/sartoopjj/dnsttui/dns"
	dnsttserver "github.com/sartoopjj/dnsttui/dnstt-server"
	"github.com/sartoopjj/dnsttui/internal/database"
	"github.com/sartoopjj/dnsttui/internal/panel"
	"github.com/sartoopjj/dnsttui/internal/shadowsocks"
	"github.com/sartoopjj/dnsttui/noise"
	"github.com/sartoopjj/dnsttui/turbotunnel"
	"github.com/spf13/cobra"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	serveUDP       string
	servePanelAddr string
	serveDomain    string
	serveMTU       int
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the DNS tunnel, Shadowsocks, and management panel",
	Long: `Start all services: the dnstt DNS tunnel listener, the Shadowsocks 2022
multi-user server, and the web management panel.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		log.SetFlags(log.LstdFlags | log.LUTC)

		// Open database
		db, err := database.Open(dbPath)
		if err != nil {
			return fmt.Errorf("open database: %w", err)
		}
		defer db.Close()

		// Check if this is first run (no config row yet)
		exists, err := db.ConfigExists()
		if err != nil {
			return fmt.Errorf("check config: %w", err)
		}

		if !exists {
			// First run without 'config init': generate random credentials
			adminUser := randomHex(4) // 8-char username
			adminPass := randomHex(6) // 12-char password
			basePath := randomHex(4)  // 8-char path

			hash, err := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("hash password: %w", err)
			}

			if err := db.InitDefaultConfig(adminUser, string(hash), "/"+basePath); err != nil {
				return fmt.Errorf("init config: %w", err)
			}

			fmt.Println()
			fmt.Println("════════════════════════════════════════════════════")
			fmt.Println("  FIRST RUN — Save these credentials!")
			fmt.Println("════════════════════════════════════════════════════")
			fmt.Printf("  Username:   %s\n", adminUser)
			fmt.Printf("  Password:   %s\n", adminPass)
			fmt.Printf("  Panel path: /%s/\n", basePath)
			fmt.Println("════════════════════════════════════════════════════")
			fmt.Println("  Change via panel settings or:")
			fmt.Println("    dnsttui config set --admin-user X --admin-pass X")
			fmt.Println("  This message will NOT be shown again.")
			fmt.Println("════════════════════════════════════════════════════")
			fmt.Println()
		}

		// Load config from DB
		cfg, err := db.GetConfig()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		// Override from CLI flags if provided
		if serveUDP != "" {
			cfg.DNSTTUDPAddr = serveUDP
		}
		if serveDomain != "" {
			// Also update in DB for panel to see
			cfg.PanelDomain = serveDomain
		}
		if serveMTU > 0 {
			cfg.DNSTTMTU = serveMTU
		}
		if servePanelAddr != "" {
			// parse port from addr
			cfg.PanelPort = 8080 // default, will be parsed from addr
		}

		// Load or auto-generate private key
		var privkey []byte
		if cfg.DNSTTPrivkey != "" {
			privkey, err = noise.DecodeKey(cfg.DNSTTPrivkey)
			if err != nil {
				return fmt.Errorf("decode stored privkey: %w", err)
			}
		} else {
			log.Println("no existing keypair found, generating new one...")
			privkey, err = noise.GeneratePrivkey()
			if err != nil {
				return err
			}
			cfg.DNSTTPrivkey = noise.EncodeKey(privkey)
			cfg.DNSTTPubkey = noise.EncodeKey(noise.PubkeyFromPrivkey(privkey))
			if err := db.UpdateConfig(cfg); err != nil {
				return fmt.Errorf("save generated keypair: %w", err)
			}
			log.Println("keypair generated and saved to database")
		}

		log.Printf("pubkey %s", cfg.DNSTTPubkey)

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigCh)

		for {
			// Reload config each iteration (restart picks up changes)
			cfg, err = db.GetConfig()
			if err != nil {
				return fmt.Errorf("reload config: %w", err)
			}

			// Override from CLI flags if provided
			if serveUDP != "" {
				cfg.DNSTTUDPAddr = serveUDP
			}
			if serveDomain != "" {
				cfg.PanelDomain = serveDomain
			}
			if serveMTU > 0 {
				cfg.DNSTTMTU = serveMTU
			}

			ctx, cancel := context.WithCancel(context.Background())
			var wg sync.WaitGroup

			// Start Shadowsocks server
			ssServer := shadowsocks.NewServer(db)
			ssAddr := fmt.Sprintf("%s:%d", cfg.SSListenAddr, cfg.SSPort)
			wg.Add(1)
			go func() {
				defer wg.Done()
				log.Printf("starting Shadowsocks on %s (method: %s)", ssAddr, cfg.SSMethod)
				if err := ssServer.Start(ctx, ssAddr, cfg.SSMethod, cfg.SSServerKey); err != nil {
					log.Printf("shadowsocks server error: %v", err)
				}
			}()

			// Start DNS tunnel if domain and UDP addr are configured
			if cfg.DNSTTDomain != "" && cfg.DNSTTUDPAddr != "" {
				domain, err := dns.ParseName(cfg.DNSTTDomain)
				if err != nil {
					cancel()
					return fmt.Errorf("invalid domain %q: %w", cfg.DNSTTDomain, err)
				}

				upstream := ssAddr // forward to local SS server
				dnsttserver.MaxUDPPayload = cfg.DNSTTMTU

				wg.Add(1)
				go func() {
					defer wg.Done()
					dnsttserver.Running.Store(true)
					defer dnsttserver.Running.Store(false)
					log.Printf("starting DNS tunnel on %s for domain %s -> %s", cfg.DNSTTUDPAddr, cfg.DNSTTDomain, upstream)
					if err := runDNSTT(ctx, privkey, domain, upstream, cfg.DNSTTUDPAddr); err != nil {
						dnsttserver.LastError.Store(err.Error())
						log.Printf("dnstt server error: %v", err)
					}
				}()
			} else {
				log.Println("warning: dnstt domain or UDP addr not configured, DNS tunnel not started")
				log.Println("configure via the panel settings or CLI flags")
			}

			// Start web panel
			panelAddr := servePanelAddr
			if panelAddr == "" {
				panelAddr = fmt.Sprintf(":%d", cfg.PanelPort)
			}
			panelDone := make(chan error, 1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				latestCfg, err := db.GetConfig()
				if err != nil {
					log.Printf("reload config for panel: %v", err)
					panelDone <- err
					return
				}
				p := panel.New(db, ssServer, latestCfg.PanelBasePath)
				log.Printf("starting panel on %s", panelAddr)
				panelDone <- p.Start(ctx, panelAddr, latestCfg.PanelDomain, latestCfg.ACMEEmail)
			}()

			// Wait for interrupt or restart request
			restart := false
			select {
			case sig := <-sigCh:
				log.Printf("received %v, shutting down...", sig)
			case err := <-panelDone:
				if err == panel.ErrRestart {
					restart = true
					log.Println("restart requested, restarting all services...")
				} else if err != nil {
					log.Printf("panel server error: %v", err)
				}
			}

			cancel()
			wg.Wait()

			if !restart {
				return nil
			}
		}
	},
}

func runDNSTT(ctx context.Context, privkey []byte, domain dns.Name, upstream, udpAddr string) error {
	dnsConn, err := net.ListenPacket("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("opening UDP listener: %w", err)
	}
	defer dnsConn.Close()

	maxEncodedPayload := dnsttserver.ComputeMaxEncodedPayload(dnsttserver.MaxUDPPayload)
	mtu := maxEncodedPayload - 2
	if mtu < 80 {
		if mtu < 0 {
			mtu = 0
		}
		return fmt.Errorf("maximum UDP payload size of %d leaves only %d bytes for payload", dnsttserver.MaxUDPPayload, mtu)
	}
	log.Printf("effective MTU %d", mtu)

	ttConn := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, dnsttserver.IdleTimeout*2)
	ln, err := kcp.ServeConn(nil, 0, 0, ttConn)
	if err != nil {
		return fmt.Errorf("opening KCP listener: %w", err)
	}
	defer ln.Close()

	// Close connections when context is cancelled (enables clean shutdown on Ctrl+C)
	go func() {
		<-ctx.Done()
		dnsConn.Close()
		ln.Close()
		ttConn.Close()
	}()

	go func() {
		if err := dnsttserver.AcceptSessions(ln, privkey, mtu, upstream); err != nil {
			log.Printf("AcceptSessions: %v", err)
		}
	}()

	ch := make(chan *dnsttserver.Record, 100)
	defer close(ch)

	go func() {
		if err := dnsttserver.SendLoop(dnsConn, ttConn, ch, maxEncodedPayload); err != nil {
			log.Printf("SendLoop: %v", err)
		}
	}()

	return dnsttserver.RecvLoop(domain, dnsConn, ttConn, ch)
}

// randomHex returns a random hex string of n bytes (2n hex chars).
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func init() {
	serveCmd.Flags().StringVar(&serveUDP, "udp", "", "UDP address for DNS listener (e.g. :5300)")
	serveCmd.Flags().StringVar(&servePanelAddr, "panel-addr", "", "panel listen address (e.g. :8080)")
	serveCmd.Flags().StringVar(&serveDomain, "domain", "", "panel domain for ACME TLS")
	serveCmd.Flags().IntVar(&serveMTU, "mtu", 0, "maximum DNS response size (0 = use DB config)")
	rootCmd.AddCommand(serveCmd)
}
