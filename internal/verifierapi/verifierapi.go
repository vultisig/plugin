package verifierapi

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

/*
Verifier API Response types
*/
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

//Verifier API type

type VerifierApi struct {
	URL    string
	logger *logrus.Logger
}

func NewVerifierApi(url string, logger *logrus.Logger) *VerifierApi {
	return &VerifierApi{
		URL:    url,
		logger: logger,
	}
}

func (v VerifierApi) get(endpoint string) (*http.Response, error) {
	r, err := http.Get(v.URL + endpoint)
	if err != nil {
		if v.logger != nil {
			v.logger.WithFields(logrus.Fields{
				"method":   http.MethodGet,
				"url":      v.URL,
				"endpoint": endpoint,
			}).WithError(err).Error("Failed to make GET request")
		}
		return nil, err
	}
	return r, nil
}
