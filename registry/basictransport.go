package registry

import (
	"log"
	"net/http"
	"strings"
)

type BasicTransport struct {
	Transport http.RoundTripper
	URL       string
	Username  string
	Password  string
}

func (t *BasicTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasPrefix(req.URL.String(), t.URL) {
		if t.Username != "" || t.Password != "" {
			req.SetBasicAuth(t.Username, t.Password)
		}
	}
	log.Println("transport basic")

	resp, err := t.Transport.RoundTrip(req)
	return resp, err
}
