package libhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	stdurl "net/url"
)

func Call[T comparable](
	ctx context.Context,
	method, url string,
	headers map[string]string,
	body interface{},
	query map[string]string,
) (T, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return *new(T), fmt.Errorf("failed to marshal request json: %w", err)
	}

	var q string
	if query != nil {
		qurl := stdurl.Values{}
		for k, v := range query {
			qurl.Set(k, v)
		}
		q = "?" + qurl.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, url+q, bytes.NewReader(b))
	if err != nil {
		return *new(T), fmt.Errorf("failed to build http request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return *new(T), fmt.Errorf("failed to make http call: %w", err)
	}

	bodyBytes, err := io.ReadAll(res.Body)
	defer func() {
		_ = res.Body.Close()
	}()
	if err != nil {
		return *new(T), fmt.Errorf("failed to read response body: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return *new(T), fmt.Errorf("failed to get successful response: status_code: %d, res_body: %s", res.StatusCode, string(bodyBytes))
	}

	_, isString := any(new(T)).(string)
	if isString {
		// for string response type no need to unmarshal JSON
		return any(string(bodyBytes)).(T), nil
	}

	var r T
	err = json.Unmarshal(bodyBytes, &r)
	if err != nil {
		return *new(T), fmt.Errorf("failed to unmarshal response json: %w", err)
	}

	return r, nil
}
