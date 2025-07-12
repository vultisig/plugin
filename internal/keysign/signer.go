package keysign

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/verifier/types"
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
	logger          *logrus.Logger
	relay           *relay.Client
	emitters        []Emitter
	partiesPrefixes []string
}

func NewSigner(
	logger *logrus.Logger,
	relay *relay.Client,
	emitters []Emitter,
	partiesPrefixesRaw []string,
) *Signer {
	var partiesPrefixes []string
	for _, prefix := range partiesPrefixesRaw {
		partiesPrefixes = append(partiesPrefixes, prefix+"-")
	}

	return &Signer{
		logger:          logger,
		relay:           relay,
		emitters:        emitters,
		partiesPrefixes: partiesPrefixes,
	}
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

	var messageIDs []string
	for _, message := range req.Messages {
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

func (s *Signer) waitPartiesAndStart(ctx context.Context, sessionID string, partiesPrefixes []string) ([]string, error) {
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
