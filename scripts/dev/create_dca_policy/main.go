package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	vtypes "github.com/vultisig/verifier/types"

	"github.com/vultisig/plugin/plugin/dca"
)

var vaultName string
var stateDir string

func main() {
	flag.StringVar(&vaultName, "vault", "", "vault name")
	flag.StringVar(&stateDir, "state-dir", "", "state directory")
	flag.Parse()

	if vaultName == "" {
		panic("vault name is required")
	}

	if stateDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}

		stateDir = filepath.Join(homeDir, ".verifier", "vaults")
	}

	keyPath := filepath.Join(stateDir, vaultName, "public_key")
	rawKey, err := os.ReadFile(keyPath)
	if err != nil {
		panic(err)
	}

	key := string(rawKey)

	fmt.Printf("Public key for vault %s:\n%s\n", vaultName, key)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter source token contract address: ")
	sourceTokenContract, _ := reader.ReadString('\n')
	sourceTokenContract = sourceTokenContract[:len(sourceTokenContract)-1]

	fmt.Print("Enter destination contract address: ")
	destinationTokenContract, _ := reader.ReadString('\n')
	destinationTokenContract = destinationTokenContract[:len(destinationTokenContract)-1]

	fmt.Print("Enter the input amount for swap: ")
	swapAmountIn, _ := reader.ReadString('\n')
	swapAmountIn = swapAmountIn[:len(swapAmountIn)-1]

	fmt.Printf("Source Token Contract: %s\n", sourceTokenContract)
	fmt.Printf("Destination Token Contract: %s\n", destinationTokenContract)
	fmt.Printf("Input amount for swap: %s\n\n", swapAmountIn)

	fmt.Print("Enter schedule frequency: ")
	frequency, _ := reader.ReadString('\n')
	frequency = frequency[:len(frequency)-1]

	policyId := uuid.New()
	policy := vtypes.PluginPolicy{
		ID:            policyId,
		PublicKey:     key,
		PluginID:      vtypes.PluginVultisigDCA_0000,
		PluginVersion: "1.0.0",
		PolicyVersion: 1,
		Active:        true,
		Signature:     "0x0000000000000000000000000000000000000000000000000000000000000000",
	}

	dcaPolicy := dca.DCAPolicy{
		ChainID:            "1",
		SourceTokenID:      sourceTokenContract,
		DestinationTokenID: destinationTokenContract,
		TotalAmount:        swapAmountIn,
		TotalOrders:        "2",
		Schedule: dca.Schedule{
			Frequency: frequency,
			Interval:  "",
			StartTime: time.Now().UTC().Add(20 * time.Second).Format(time.RFC3339),
		},
	}

	policyBytes, err := json.Marshal(dcaPolicy)
	if err != nil {
		panic(err)
	}

	fmt.Println("DCA policy", string(policyBytes))

	pluginHost := fmt.Sprintf("http://%s:%d", "localhost", 8080)

	reqBytes, err := json.Marshal(policy)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Creating policy on plugin server: %s\n", pluginHost)

	resp, err := http.Post(fmt.Sprintf("%s/plugin/policy", pluginHost), "application/json", bytes.NewBuffer(reqBytes))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Request sent: %d\n", resp.StatusCode)
}
