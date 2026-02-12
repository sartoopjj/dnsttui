package main

import "github.com/sartoopjj/dnsttui/cmd"

// Version is set at build time via -ldflags.
var Version = "dev"

func main() {
	cmd.SetVersion(Version)
	cmd.Execute()
}
