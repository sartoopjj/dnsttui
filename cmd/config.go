package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/sartoopjj/dnsttui/internal/database"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

// --- config (parent) ---

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage panel configuration",
	Long:  `View or modify panel configuration stored in the database.`,
}

// --- config show ---

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display current configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := database.Open(dbPath)
		if err != nil {
			return fmt.Errorf("open database: %w", err)
		}
		defer db.Close()

		exists, err := db.ConfigExists()
		if err != nil {
			return err
		}
		if !exists {
			fmt.Println("No configuration found. Run 'dnsttui config init' or 'dnsttui serve' first.")
			return nil
		}

		cfg, err := db.GetConfig()
		if err != nil {
			return err
		}

		passDisplay := "(not set)"
		if cfg.AdminPass != "" {
			passDisplay = "********"
		}

		fmt.Println("═══════════════════════════════════════")
		fmt.Printf("  dnsttui %s\n", version)
		fmt.Println("═══════════════════════════════════════")
		fmt.Printf("  Admin User:       %s\n", cfg.AdminUser)
		fmt.Printf("  Admin Password:   %s\n", passDisplay)
		fmt.Printf("  Panel Base Path:  %s\n", cfg.PanelBasePath)
		fmt.Printf("  Panel Port:       %d\n", cfg.PanelPort)
		fmt.Printf("  Panel Domain:     %s\n", cfg.PanelDomain)
		fmt.Printf("  ACME Email:       %s\n", cfg.ACMEEmail)
		fmt.Println("───────────────────────────────────────")
		fmt.Printf("  DNSTT Domain:     %s\n", cfg.DNSTTDomain)
		fmt.Printf("  DNSTT UDP Addr:   %s\n", cfg.DNSTTUDPAddr)
		fmt.Printf("  DNSTT MTU:        %d\n", cfg.DNSTTMTU)
		fmt.Printf("  DNSTT Public Key: %s\n", cfg.DNSTTPubkey)
		fmt.Println("───────────────────────────────────────")
		fmt.Printf("  SS Listen Addr:   %s\n", cfg.SSListenAddr)
		fmt.Printf("  SS Port:          %d\n", cfg.SSPort)
		fmt.Printf("  SS Method:        %s\n", cfg.SSMethod)
		fmt.Println("───────────────────────────────────────")
		fmt.Printf("  DNS Resolver:     %s:%d\n", cfg.DNSResolverAddr, cfg.DNSResolverPort)
		fmt.Println("═══════════════════════════════════════")

		return nil
	},
}

// --- config init ---

var (
	initAdminUser string
	initAdminPass string
	initBasePath  string
	initPanelPort int
)

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration with admin credentials",
	Long: `Initialize the database with admin credentials. If the config already
exists, this command does nothing (use 'config set' to modify).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := database.Open(dbPath)
		if err != nil {
			return fmt.Errorf("open database: %w", err)
		}
		defer db.Close()

		exists, err := db.ConfigExists()
		if err != nil {
			return err
		}
		if exists {
			fmt.Println("Configuration already exists. Use 'dnsttui config set' to modify.")
			return nil
		}

		user := initAdminUser
		pass := initAdminPass
		basePath := initBasePath

		// Generate random values for anything not provided
		if user == "" {
			user = randomHexStr(4) // 8-char
			fmt.Printf("  Generated username: %s\n", user)
		}
		if pass == "" {
			pass = randomHexStr(6) // 12-char
			fmt.Printf("  Generated password: %s\n", pass)
		}
		if basePath == "" {
			basePath = "/" + randomHexStr(4) // /8-char
			fmt.Printf("  Generated base path: %s\n", basePath)
		}
		// Ensure basePath starts with /
		if basePath != "" && !strings.HasPrefix(basePath, "/") {
			basePath = "/" + basePath
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}

		if err := db.InitDefaultConfig(user, string(hash), basePath); err != nil {
			return fmt.Errorf("init config: %w", err)
		}

		// Set panel port if provided
		if initPanelPort > 0 {
			cfg, err := db.GetConfig()
			if err != nil {
				return fmt.Errorf("get config: %w", err)
			}
			cfg.PanelPort = initPanelPort
			if err := db.UpdateConfig(cfg); err != nil {
				return fmt.Errorf("set panel port: %w", err)
			}
		}

		portDisplay := "8080 (default)"
		if initPanelPort > 0 {
			portDisplay = fmt.Sprintf("%d", initPanelPort)
		}

		fmt.Println()
		fmt.Println("════════════════════════════════════════════════════")
		fmt.Println("  Configuration initialized!")
		fmt.Println("════════════════════════════════════════════════════")
		fmt.Printf("  Username:   %s\n", user)
		fmt.Printf("  Password:   %s\n", pass)
		fmt.Printf("  Panel path: %s/\n", basePath)
		fmt.Printf("  Panel port: %s\n", portDisplay)
		fmt.Println("════════════════════════════════════════════════════")
		return nil
	},
}

// --- config set ---

var (
	setAdminUser     string
	setAdminPass     string
	setBasePath      string
	setPanelDomain   string
	setACMEEmail     string
	setDNSTTDomain   string
	setDNSTTUDPAddr  string
	setDNSTTMTU      int
	setPanelPort     int
	setSSListenAddr  string
	setSSPort        int
	setDNSResolver   string
	setDNSResolvPort int
)

var configSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Update configuration values",
	Long:  `Update one or more configuration values in the database. Only provided flags are changed.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := database.Open(dbPath)
		if err != nil {
			return fmt.Errorf("open database: %w", err)
		}
		defer db.Close()

		exists, err := db.ConfigExists()
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("no configuration found — run 'dnsttui config init' first")
		}

		cfg, err := db.GetConfig()
		if err != nil {
			return err
		}

		changed := false

		if cmd.Flags().Changed("admin-user") {
			cfg.AdminUser = setAdminUser
			changed = true
			fmt.Printf("  admin-user → %s\n", setAdminUser)
		}
		if cmd.Flags().Changed("admin-pass") {
			hash, err := bcrypt.GenerateFromPassword([]byte(setAdminPass), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("hash password: %w", err)
			}
			cfg.AdminPass = string(hash)
			changed = true
			fmt.Println("  admin-pass → (updated)")
		}
		if cmd.Flags().Changed("base-path") {
			bp := setBasePath
			if bp != "" && !strings.HasPrefix(bp, "/") {
				bp = "/" + bp
			}
			cfg.PanelBasePath = bp
			changed = true
			fmt.Printf("  base-path → %s\n", bp)
		}
		if cmd.Flags().Changed("panel-domain") {
			cfg.PanelDomain = setPanelDomain
			changed = true
			fmt.Printf("  panel-domain → %s\n", setPanelDomain)
		}
		if cmd.Flags().Changed("panel-port") {
			cfg.PanelPort = setPanelPort
			changed = true
			fmt.Printf("  panel-port → %d\n", setPanelPort)
		}
		if cmd.Flags().Changed("acme-email") {
			cfg.ACMEEmail = setACMEEmail
			changed = true
			fmt.Printf("  acme-email → %s\n", setACMEEmail)
		}
		if cmd.Flags().Changed("dnstt-domain") {
			cfg.DNSTTDomain = setDNSTTDomain
			changed = true
			fmt.Printf("  dnstt-domain → %s\n", setDNSTTDomain)
		}
		if cmd.Flags().Changed("dnstt-udp") {
			cfg.DNSTTUDPAddr = setDNSTTUDPAddr
			changed = true
			fmt.Printf("  dnstt-udp → %s\n", setDNSTTUDPAddr)
		}
		if cmd.Flags().Changed("dnstt-mtu") {
			cfg.DNSTTMTU = setDNSTTMTU
			changed = true
			fmt.Printf("  dnstt-mtu → %d\n", setDNSTTMTU)
		}
		if cmd.Flags().Changed("ss-listen") {
			cfg.SSListenAddr = setSSListenAddr
			changed = true
			fmt.Printf("  ss-listen → %s\n", setSSListenAddr)
		}
		if cmd.Flags().Changed("ss-port") {
			cfg.SSPort = setSSPort
			changed = true
			fmt.Printf("  ss-port → %d\n", setSSPort)
		}
		if cmd.Flags().Changed("dns-resolver") {
			cfg.DNSResolverAddr = setDNSResolver
			changed = true
			fmt.Printf("  dns-resolver → %s\n", setDNSResolver)
		}
		if cmd.Flags().Changed("dns-resolver-port") {
			cfg.DNSResolverPort = setDNSResolvPort
			changed = true
			fmt.Printf("  dns-resolver-port → %d\n", setDNSResolvPort)
		}

		if !changed {
			fmt.Println("No flags provided. Use --help to see available options.")
			return nil
		}

		if err := db.UpdateConfig(cfg); err != nil {
			return fmt.Errorf("save config: %w", err)
		}

		fmt.Println("Configuration updated. Restart the service to apply changes.")
		return nil
	},
}

func randomHexStr(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func init() {
	// config init flags
	configInitCmd.Flags().StringVar(&initAdminUser, "admin-user", "", "admin username (random if empty)")
	configInitCmd.Flags().StringVar(&initAdminPass, "admin-pass", "", "admin password (random if empty)")
	configInitCmd.Flags().StringVar(&initBasePath, "base-path", "", "panel base path (random if empty)")
	configInitCmd.Flags().IntVar(&initPanelPort, "panel-port", 0, "panel listen port (default 8080)")

	// config set flags
	configSetCmd.Flags().StringVar(&setAdminUser, "admin-user", "", "admin username")
	configSetCmd.Flags().StringVar(&setAdminPass, "admin-pass", "", "admin password (will be bcrypt hashed)")
	configSetCmd.Flags().StringVar(&setBasePath, "base-path", "", "panel base path (e.g. /mypath)")
	configSetCmd.Flags().IntVar(&setPanelPort, "panel-port", 0, "panel listen port")
	configSetCmd.Flags().StringVar(&setPanelDomain, "panel-domain", "", "panel domain for ACME TLS")
	configSetCmd.Flags().StringVar(&setACMEEmail, "acme-email", "", "ACME email for TLS certs")
	configSetCmd.Flags().StringVar(&setDNSTTDomain, "dnstt-domain", "", "DNS tunnel domain")
	configSetCmd.Flags().StringVar(&setDNSTTUDPAddr, "dnstt-udp", "", "DNS tunnel UDP listen address")
	configSetCmd.Flags().IntVar(&setDNSTTMTU, "dnstt-mtu", 0, "DNS tunnel MTU")
	configSetCmd.Flags().StringVar(&setSSListenAddr, "ss-listen", "", "Shadowsocks listen address")
	configSetCmd.Flags().IntVar(&setSSPort, "ss-port", 0, "Shadowsocks port")
	configSetCmd.Flags().StringVar(&setDNSResolver, "dns-resolver", "", "DNS resolver address for clients")
	configSetCmd.Flags().IntVar(&setDNSResolvPort, "dns-resolver-port", 0, "DNS resolver port for clients")

	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configSetCmd)
	rootCmd.AddCommand(configCmd)
}
