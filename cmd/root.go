package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	dbPath  string
	version = "dev"
)

// SetVersion sets the application version (called from main).
func SetVersion(v string) {
	version = v
	rootCmd.Version = v
}

var rootCmd = &cobra.Command{
	Use:   "dnsttui",
	Short: "DNS tunnel server with Shadowsocks and management panel",
	Long: `dnsttui is a DNS tunnel server (dnstt) with integrated Shadowsocks 2022
support and a web-based management panel. It allows you to run a DNS tunnel
that forwards traffic through Shadowsocks with multi-user support.`,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "dnsttui.db", "path to SQLite database file")
}
