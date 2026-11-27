// Local-only, read-only entry point for the buyer's source-lock preview (T19).
// It reads the pinned issuer at a finalized source block through the production
// buyersdk.PreviewTokenLock and prints the preview. It never signs, reserves a
// budget or builds a transfer.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/tokenissuer"
)

func amount(name, text string) (*big.Int, error) {
	value, ok := new(big.Int).SetString(text, 10)
	if !ok || value.Sign() <= 0 || value.BitLen() > 120 || value.String() != text {
		return nil, fmt.Errorf("%s must be a canonical positive atomic amount", name)
	}
	return value, nil
}

func run() error {
	policyPath := flag.String("policy", "", "owner-pinned issuer policy (tokenissuer.Policy JSON)")
	master := flag.String("master", "", "wrapped asset master (0:hex)")
	actor := flag.String("actor", "", "actor address (0:hex)")
	nominal := flag.String("nominal", "", "nominal source lock amount, atomic")
	price := flag.String("price", "", "actor's exact quoted price, atomic")
	perCall := flag.String("max-per-call", "", "per-call asset budget, atomic")
	window := flag.String("max-window", "", "window asset budget, atomic")
	flag.Parse()
	if *policyPath == "" || flag.NArg() != 0 {
		return fmt.Errorf("--policy and every amount flag are required")
	}
	raw, err := os.ReadFile(*policyPath)
	if err != nil {
		return err
	}
	var policy tokenissuer.Policy
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return err
	}
	if !strings.HasPrefix(policy.RPCURL, "http://127.0.0.1:") || policy.ChainID != 1 {
		return fmt.Errorf("the local loopback source chain 1 is required")
	}
	values := map[string]*big.Int{}
	for name, text := range map[string]string{"nominal": *nominal, "price": *price, "max-per-call": *perCall, "max-window": *window} {
		value, err := amount(name, text)
		if err != nil {
			return err
		}
		values[name] = value
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	preview, err := buyersdk.PreviewTokenLock(ctx, policy, *master, *actor, values["nominal"], values["price"], new(big.Int),
		buyersdk.TokenAssetLimits{MaxPerCallAtomic: values["max-per-call"], MaxWindowAtomic: values["max-window"]})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(preview)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
