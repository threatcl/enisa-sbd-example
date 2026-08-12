package rollout

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Publisher hands a verified release manifest to the firmware CDN - the
// "publish signed image" flow (https) to the third_party trust zone.
type Publisher interface {
	Publish(ctx context.Context, m Manifest) error
}

// HTTPPublisher publishes over HTTPS to a CDN origin.
//
// The CDN is modelled as a third_party_dependency, not a trust anchor: it
// distributes an image whose signature devices verify for themselves before
// flashing. Transport security here protects the integrity of the publish
// call, not the authenticity of the firmware.
type HTTPPublisher struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewHTTPPublisher validates the origin and returns a publisher.
//
// A plaintext origin is refused rather than warned about: publishing a release
// over http would let anyone on the path substitute the manifest, and there is
// no legitimate configuration in which that is acceptable.
func NewHTTPPublisher(baseURL, token string) (*HTTPPublisher, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("rollout: parsing CDN url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("rollout: CDN url must be https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("rollout: CDN url %q has no host", baseURL)
	}
	if token == "" {
		return nil, fmt.Errorf("rollout: CDN credential is empty")
	}
	return &HTTPPublisher{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		token:   token,
		client:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (p *HTTPPublisher) Publish(ctx context.Context, m Manifest) error {
	body, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("rollout: encoding manifest: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/releases", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("rollout: building publish request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("rollout: publishing to CDN: %w", err)
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the connection can be reused, and so a
	// misbehaving CDN cannot stream an unbounded error body at us.
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("rollout: CDN rejected release %s: %s: %s",
			m.Version, resp.Status, strings.TrimSpace(string(snippet)))
	}
	return nil
}
