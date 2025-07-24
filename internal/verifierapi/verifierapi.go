package verifierapi

import (
	"net/http"

	"github.com/sirupsen/logrus"
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
	logger *logrus.Logger
	token  string // api key
	client *http.Client
}

func NewVerifierApi(url string, token string, logger *logrus.Logger) *VerifierApi {
	return &VerifierApi{
		url:    url,
		logger: logger,
		token:  token,
		client: &http.Client{},
	}
}

func (v *VerifierApi) get(endpoint string) (*http.Response, error) {
	return http.Get(v.url + endpoint)
}

func (v *VerifierApi) getAuth(endpoint string) (*http.Response, error) {
	r, err := http.NewRequest(http.MethodGet, v.url+endpoint, nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "Bearer "+v.token)
	return v.client.Do(r)
}
