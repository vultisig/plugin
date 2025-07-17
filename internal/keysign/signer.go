package keysign

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/verifier/common"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/verifier/vault"
	"github.com/vultisig/vultiserver/relay"
)

// Emitter
// e.g. verifier API /plugin-signer/sign endpoint which puts to verifier.worker queue
// e.g. queue for a plugin.worker
// check interface implementation usages for examples
type Emitter interface {
	Sign(ctx context.Context, req types.PluginKeysignRequest) error
}

type Signer struct {
	logger                *logrus.Logger
	relay                 *relay.Client
	emitters              []Emitter
	partiesPrefixes       []string
	storage               vault.Storage
	vaultEncryptionSecret string
}

func NewSigner(
	logger *logrus.Logger,
	relay *relay.Client,
	emitters []Emitter,
	partiesPrefixesRaw []string,
	storage vault.Storage,
	vaultEncryptionSecret string,
) *Signer {
	var partiesPrefixes []string
	for _, prefix := range partiesPrefixesRaw {
		partiesPrefixes = append(partiesPrefixes, prefix+"-")
	}

	return &Signer{
		logger:                logger,
		relay:                 relay,
		emitters:              emitters,
		partiesPrefixes:       partiesPrefixes,
		storage:               storage,
		vaultEncryptionSecret: vaultEncryptionSecret,
	}
}

func (s *Signer) getVault(publicKey, pluginID string) (*vaultType.Vault, error) {
	content, err := s.storage.GetVault(common.GetVaultBackupFilename(publicKey, pluginID))
	if err != nil {
		return nil, fmt.Errorf("s.storage.GetVault: %w", err)
	}

	vlt, err := common.DecryptVaultFromBackup(s.vaultEncryptionSecret, content)
	if err != nil {
		return nil, fmt.Errorf("common.DecryptVaultFromBackup: %w", err)
	}
	if vlt == nil {
		return nil, fmt.Errorf("vault is nil for publicKey: %s, pluginID: %s", publicKey, pluginID)
	}
	return vlt, nil
}

func (s *Signer) getKeyshareHandle(vlt *vaultType.Vault, isEdDSA bool) (vault.Handle, error) {
	if vlt == nil {
		return 0, fmt.Errorf("vault is nil")
	}

	publicKey := vlt.PublicKeyEcdsa
	if isEdDSA {
		publicKey = vlt.PublicKeyEddsa
	}

	for _, keyshare := range vlt.KeyShares {
		if keyshare.PublicKey == publicKey {
			bytes, err := base64.StdEncoding.DecodeString(keyshare.Keyshare)
			if err != nil {
				return 0, fmt.Errorf("base64.StdEncoding.DecodeString: %w", err)
			}
			handle, err := vault.NewMPCWrapperImp(isEdDSA).KeyshareFromBytes(bytes)
			if err != nil {
				return 0, fmt.Errorf("vault.NewMPCWrapperImp.KeyshareFromBytes: %w", err)
			}
			return handle, nil
		}
	}
	return 0, fmt.Errorf("keyshare not found for publicKey: %s", publicKey)
}

func (s *Signer) Sign(
	ctx context.Context,
	req types.PluginKeysignRequest,
) (map[string]tss.KeysignResponse, error) {
	for _, emitter := range s.emitters {
		err := emitter.Sign(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("emitter.Sign: %w", err)
		}
	}

	partyIDs, err := s.waitPartiesAndStart(ctx, req.SessionID, s.partiesPrefixes)
	if err != nil {
		return nil, fmt.Errorf("s.waitPartiesAndStart: %w", err)
	}

	vlt, err := s.getVault(req.PublicKey, req.PluginID)
	if err != nil {
		return nil, fmt.Errorf("s.getVault: %w", err)
	}

	var messageIDs []string
	for _, message := range req.Messages {
		handle, er := s.getKeyshareHandle(vlt, message.Chain.IsEdDSA())
		if er != nil {
			return nil, fmt.Errorf("s.getKeyshareHandle: %w", er)
		}

		mpc := vault.NewMPCWrapperImp(message.Chain.IsEdDSA())

		id, er := mpc.KeyshareKeyID(handle)
		if er != nil {
			return nil, fmt.Errorf("mpc.KeyshareKeyID: %w", er)
		}

		// message.Message is payload to sign (not message.Hash)
		// it actually both hashes but could be different,
		// message.Hash is unencrypted and only used as key for relay communication,
		// and key in resulting map[hash]sig
		hashToSign, er := hex.DecodeString(strings.TrimPrefix(message.Message, "0x"))
		if er != nil {
			return nil, fmt.Errorf("hex.DecodeString: %w", er)
		}

		setupMsg, er := mpc.SignSetupMsgNew(
			id,
			[]byte(message.Chain.GetDerivePath()),
			hashToSign,
			idsSlice(partyIDs),
		)
		if er != nil {
			return nil, fmt.Errorf("mpc.SignSetupMsgNew: %w", er)
		}

		wireMsg, er := common.EncryptGCM(base64.StdEncoding.EncodeToString(setupMsg), req.HexEncryptionKey)
		if er != nil {
			return nil, fmt.Errorf("common.EncryptGCM: %w", er)
		}

		er = s.relay.UploadSetupMessage(req.SessionID, message.Hash, wireMsg)
		if er != nil {
			return nil, fmt.Errorf("s.relay.UploadSetupMessage: %w", er)
		}

		messageIDs = append(messageIDs, message.Hash)
	}

	res, err := s.waitResult(ctx, req.SessionID, partyIDs, messageIDs)
	if err != nil {
		return nil, fmt.Errorf("s.waitResult: %w", err)
	}
	return res, nil
}

func (s *Signer) waitResult(
	ctx context.Context,
	sessionID string,
	partyIDs, messageIDs []string,
) (map[string]tss.KeysignResponse, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
			ok, err := s.relay.CheckCompletedParties(sessionID, partyIDs)
			if err != nil {
				return nil, fmt.Errorf("s.relay.CheckCompletedParties: %w", err)
			}
			if !ok {
				s.logger.WithFields(logrus.Fields{
					"sessionID": sessionID,
					"partyIDs":  partyIDs,
				}).Info("Waiting for parties to complete sign")
				continue
			}

			sigs := make(map[string]tss.KeysignResponse, len(messageIDs))
			for _, messageID := range messageIDs {
				sig, completeErr := s.relay.CheckKeysignComplete(sessionID, messageID)
				if completeErr != nil {
					s.logger.WithFields(logrus.Fields{
						"sessionID": sessionID,
						"messageID": messageID,
						"partyIDs":  partyIDs,
					}).WithError(completeErr).Info("continue polling: CheckKeysignComplete")
					continue
				}
				if sig == nil {
					return nil, fmt.Errorf(
						"unexpected empty sig: messageID: %s, sessionID: %s",
						messageID,
						sessionID,
					)
				}
				sigs[messageID] = *sig
			}
			return sigs, nil
		}
	}
}

func (s *Signer) waitPartiesAndStart(
	ctx context.Context,
	sessionID string,
	partiesPrefixes []string,
) ([]string, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
			partiesJoined, err := s.relay.GetSession(sessionID)
			if err != nil {
				return nil, fmt.Errorf("s.relay.GetSession: %w", err)
			}

			partiesIDs := filterIDsByPrefixes(partiesJoined, partiesPrefixes)
			if len(partiesIDs) < len(partiesPrefixes) {
				s.logger.WithFields(logrus.Fields{
					"sessionID":       sessionID,
					"partiesJoined":   partiesIDs,
					"partiesPrefixes": partiesPrefixes,
				}).Info("Waiting for more parties to join")
				continue
			}
			if len(partiesIDs) > len(partiesPrefixes) {
				return nil, fmt.Errorf(
					"too many parties joined: [%s], expected prefixes: [%s],"+
						"it may caused by bug in calling code",
					strings.Join(partiesIDs, ","),
					strings.Join(partiesPrefixes, ","),
				)
			}

			s.logger.WithFields(logrus.Fields{
				"sessionID":       sessionID,
				"partiesJoined":   partiesIDs,
				"partiesPrefixes": partiesPrefixes,
			}).Info("all expected parties joined")

			err = s.relay.StartSession(sessionID, partiesIDs)
			if err != nil {
				return nil, fmt.Errorf("s.relay.StartSession: %w", err)
			}
			return partiesIDs, nil
		}
	}
}

func filterIDsByPrefixes(fullIDs, prefixes []string) []string {
	seen := make(map[string]struct{})
	var result []string

	for _, id := range fullIDs {
		for _, prefix := range prefixes {
			if strings.HasPrefix(id, prefix) {
				if _, exists := seen[id]; !exists {
					seen[id] = struct{}{}
					result = append(result, id)
				}
				break
			}
		}
	}

	return result
}

func idsSlice(ids []string) []byte {
	return []byte(strings.Join(ids, "\x00"))
}
