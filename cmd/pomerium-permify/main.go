// Package main is a thin wrapper around Pomerium's standard entry
// point that pulls in the Permify policy-engine adapter via a blank
// import. Building this binary instead of the upstream `pomerium`
// command makes the kind "permify" available for `policy_engine:`.
//
// Flag surface: only --config <path>; the same value can be supplied
// via the POMERIUM_CONFIG_FILE environment variable. All other
// configuration is read from the YAML config file just like upstream
// Pomerium.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cmd/pomerium"
	"github.com/pomerium/pomerium/pkg/envoy/files"

	// Side-effect import: registers kind "permify" with the authorize
	// policy-engine registry at init time.
	_ "github.com/abzcoding/pomerium-permify"
)

func main() {
	configFile := flag.String("config", os.Getenv("POMERIUM_CONFIG_FILE"), "Specify configuration file location")
	version := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *version {
		fmt.Printf("pomerium-permify (envoy %s)\n", files.Lockfile().Version)
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()

	src, err := config.NewFileOrEnvironmentSource(ctx, *configFile, files.Lockfile().Version)
	if err != nil {
		log.Fatalf("pomerium-permify: load config: %v", err)
	}

	if err := pomerium.Run(ctx, src); err != nil {
		log.Fatalf("pomerium-permify: %v", err)
	}
}
