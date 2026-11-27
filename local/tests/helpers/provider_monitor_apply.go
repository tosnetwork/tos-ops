// Local-only integration entry point for the production auto-pause API.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

func run() error {
	config := flag.String("config", "", "local provider configuration")
	execute := flag.Bool("execute", false, "allow the production API to sign local emergency pauses")
	flag.Parse()
	if !*execute || *config == "" || flag.NArg() != 0 {
		return fmt.Errorf("explicit --execute and --config are required")
	}
	c, err := servicebridge.LoadNodeConfig(*config)
	if err != nil {
		return err
	}
	if c.Network.NetworkID != "tos:global-id:3" ||
		c.Network.GenesisRootHash != "sha256:65735247a371030abe811aeac0afe357301ce90e161450d26f88b4beb5b4c366" ||
		c.Network.GenesisFileHash != "sha256:c3860fe196a2a1b5e4e74a9cf9448624a353ce68a8c4c5f6413347586d688769" {
		return fmt.Errorf("approved local genesis required")
	}
	for _, endpoint := range c.RPCEndpoints {
		if !strings.HasPrefix(endpoint, "http://127.0.0.1:") {
			return fmt.Errorf("local endpoints required")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// No encoder, injected state or signer override: the API verifies the
	// configured genesis, owner and release, and journals its own signed action.
	if err := servicebridge.CheckTokenSafety(ctx, c, servicebridge.TokenEnv{}); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"implementation": "CheckTokenSafety", "local_only": true, "completed": true})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
