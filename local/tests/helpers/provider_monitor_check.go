package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: provider-monitor-check CONFIG PRIVATE_STATE")
		os.Exit(2)
	}
	c, err := servicebridge.LoadNodeConfig(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if c.Network.GenesisRootHash != "sha256:65735247a371030abe811aeac0afe357301ce90e161450d26f88b4beb5b4c366" {
		fmt.Fprintln(os.Stderr, "local genesis required")
		os.Exit(2)
	}
	c.StateDir = os.Args[2]
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	env := servicebridge.TokenEnv{SetupEnv: servicebridge.SetupEnv{Runner: func(servicebridge.TOSCTLConfig, string) (servicebridge.TOSCTLRunner, error) {
		return nil, errors.New("read-only monitor check never signs")
	}}}
	if err = servicebridge.CheckTokenSafety(ctx, c, env); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"provider_monitor": "fresh", "asset_alarm": false, "signing_disabled": true, "implementation": "CheckTokenSafety"}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
