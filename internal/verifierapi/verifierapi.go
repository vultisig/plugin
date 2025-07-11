package verifierapi

import (
	"context"
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"
	"github.com/vultisig/plugin/internal/libhttp"
	"github.com/vultisig/verifier/types"
)

// APIResponse is a generic response type for the Verifier API.
type APIResponse[T any] struct {
	Data      T             `json:"data,omitempty"`
	Error     ErrorResponse `json:"error"`
	Status    int           `json:"status"`
	Timestamp string        `json:"timestamp"`
	Version   string        `json:"version"`
}

type ErrorResponse struct {
	Message          string `json:"message"`
	DetailedResponse string `json:"details,omitempty"`
}

// VerifierApi is a client for interacting with the Verifier API.
type VerifierApi struct {
	url    string
	token  string
	logger *logrus.Logger
}

func NewVerifierApi(url, token string, logger *logrus.Logger) *VerifierApi {
	return &VerifierApi{
		url:    url,
		token:  token,
		logger: logger,
	}
}

func (v *VerifierApi) get(endpoint string) (*http.Response, error) {
	r, err := http.Get(v.url + endpoint)
	if err != nil {
		if v.logger != nil {
			v.logger.WithFields(logrus.Fields{
				"method":   http.MethodGet,
				"url":      v.url,
				"endpoint": endpoint,
			}).WithError(err).Error("Failed to make GET request")
		}
		return nil, err
	}
	return r, nil
}

func (v *VerifierApi) Sign(ctx context.Context, req types.PluginKeysignRequest) (string, error) {
	endpoint := v.url + "/plugin-signer/sign"

	taskID, err := libhttp.Call[string](ctx, http.MethodPost, endpoint, map[string]string{
		"Authorization": "Bearer " + v.token,
		"Content-Type":  "application/json",
	}, req, nil)
	if err != nil {
		if v.logger != nil {
			v.logger.WithFields(logrus.Fields{
				"method":   http.MethodPost,
				"endpoint": endpoint,
				"request":  req,
			}).WithError(err).Error("Failed to make Sign request")
		}
		return "", fmt.Errorf("libhttp.Call: %w", err)
	}
	return taskID, nil
}
