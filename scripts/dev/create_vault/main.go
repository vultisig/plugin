package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/vultisig/vultiserver-plugin/common"
	"github.com/vultisig/vultiserver-plugin/config"
	"github.com/vultisig/vultiserver-plugin/internal/types"
	"github.com/vultisig/vultiserver-plugin/relay"
	"github.com/vultisig/vultiserver-plugin/service"
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
	if _, err := os.Stat(keyPath); err == nil {
		panic("vault already exists")
	}

	serverConfig, err := config.ReadConfig("config-verifier")
	if err != nil {
		panic(err)
	}

	pluginConfig, err := config.ReadConfig("config-plugin")
	if err != nil {
		panic(err)
	}

	createVaultRequest := &types.VaultCreateRequest{
		Name:               vaultName,
		SessionID:          uuid.New().String(),
		HexEncryptionKey:   "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		HexChainCode:       "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		LocalPartyId:       common.PluginPartyID,
		EncryptionPassword: "your-secure-password",
		Email:              "example@example.com",
		LibType:            types.DKLS,
	}

	serverHost := fmt.Sprintf("http://%s:%d", serverConfig.Server.Host, serverConfig.Server.Port)
	pluginHost := fmt.Sprintf("http://%s:%d", pluginConfig.Server.Host, pluginConfig.Server.Port)

	fmt.Printf("Creating vault on verifier server - http://%s:%d/vault/create", serverHost, serverConfig.Server.Port)
	reqBytes, err := json.Marshal(createVaultRequest)
	if err != nil {
		panic(err)
	}

	resp, err := http.Post(fmt.Sprintf("%s/vault/create", serverHost), "application/json", bytes.NewBuffer(reqBytes))
	if err != nil {
		panic(err)
	}
	fmt.Printf(" - %d\n", resp.StatusCode)

	fmt.Printf("Creating vault on plugin server - http://%s:%d/vault/create", pluginHost, pluginConfig.Server.Port)
	createVaultRequest.LocalPartyId = common.VerifierPartyID
	createVaultRequest.Parties = []string{common.PluginPartyID, common.VerifierPartyID}

	reqBytes, err = json.Marshal(createVaultRequest)
	if err != nil {
		panic(err)
	}

	resp, err = http.Post(fmt.Sprintf("%s/vault/create", pluginHost), "application/json", bytes.NewBuffer(reqBytes))
	if err != nil {
		panic(err)
	}
	fmt.Printf(" - %d\n", resp.StatusCode)

	fmt.Println("Please watch the logs on the worker nodes and retrieve the ECDSA public key")

	mpcWrapper := service.NewMPCWrapperImp(false)
	partyBytes := make([]byte, 0)
	for _, party := range createVaultRequest.Parties {
		partyBytes = append(partyBytes, []byte(party)...)
		partyBytes = append(partyBytes, byte(0))
	}
	partyBytes = partyBytes[:len(partyBytes)-1]

	setupMessage, err := mpcWrapper.KeygenSetupMsgNew(2, nil, partyBytes)
	if err != nil {
		panic(err)
	}

	base64SetupMessage := base64.StdEncoding.EncodeToString(setupMessage)

	relayClient := relay.NewRelayClient(serverConfig.Relay.Server)

	encryptedSetupMessage, err := common.EncryptGCM(base64SetupMessage, createVaultRequest.HexEncryptionKey)
	if err != nil {
		panic(err)
	}

	err = relayClient.UploadSetupMessage(createVaultRequest.SessionID, encryptedSetupMessage)
	if err != nil {
		panic(err)
	}

	err = relayClient.StartSession(createVaultRequest.SessionID, createVaultRequest.Parties)
	if err != nil {
		panic(err)
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the ECDSA public key: ")
	publicKey, _ := reader.ReadString('\n')
	publicKey = publicKey[:len(publicKey)-1]

	fmt.Printf("Saving vault %s with key %s\n", vaultName, publicKey)
	vaultPath := filepath.Join(stateDir, vaultName)
	if err := os.MkdirAll(vaultPath, 0755); err != nil {
		panic(err)
	}

	vaultFile, err := os.Create(filepath.Join(vaultPath, "public_key"))
	if err != nil {
		panic(err)
	}

	if _, err := vaultFile.WriteString(publicKey); err != nil {
		panic(err)
	}

	fmt.Println("Vault created successfully")
}
