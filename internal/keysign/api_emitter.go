package keysign

import (
	"context"
	"fmt"
	"net/http"

	"github.com/vultisig/plugin/internal/libhttp"
	"github.com/vultisig/verifier/types"
)

func NewVerifierEmitter(url, token string) Emitter {
	return newApiEmitter[string](
		http.MethodPost,
		url+"/plugin-signer/sign",
		map[string]string{
			"Authorization": "Bearer " + token,
			"Content-Type":  "application/json",
		},
	)
}

type apiEmitter[T comparable] struct {
	method   string
	endpoint string
	headers  map[string]string
}

// T is response type from the HTTP API call
func newApiEmitter[T comparable](method, endpoint string, headers map[string]string) *apiEmitter[T] {
	return &apiEmitter[T]{
		method:   method,
		endpoint: endpoint,
		headers:  headers,
	}
}

func (e *apiEmitter[T]) Sign(ctx context.Context, req types.PluginKeysignRequest) error {
	_, err := libhttp.Call[T](ctx, e.method, e.endpoint, e.headers, req, nil)
	if err != nil {
		return fmt.Errorf("libhttp.Call: %w", err)
	}
	return nil
}
