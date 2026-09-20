package demo

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func httpClient() *http.Client {
	return &http.Client{Timeout: 4 * time.Second}
}

func newDemoRequest(url, token string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("X-Falcon-Token", token)
	}
	return req, nil
}

func decodeSwap(resp *http.Response) error {
	if resp.StatusCode >= 300 {
		return fmt.Errorf("demo swap HTTP %s", resp.Status)
	}
	var out struct {
		Profile string `json:"profile"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out); err != nil {
		return fmt.Errorf("demo swap: not a Falcon demo endpoint")
	}
	if out.Profile == "" {
		return fmt.Errorf("demo swap: empty profile")
	}
	return nil
}
