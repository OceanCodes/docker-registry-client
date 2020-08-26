package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"

	cdocker "github.com/OceanCodes/common/docker"
)

type TokenTransport struct {
	Transport http.RoundTripper
	Username  string
	Password  string
}

func (t *TokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.Transport.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	if authService, basic := isTokenDemand(resp); authService != nil {
		return t.authAndRetry(authService, req, basic)
	}
	return resp, err
}

type authToken struct {
	Token string `json:"token"`
}

func (t *TokenTransport) authAndRetry(authService *authService, req *http.Request, basic bool) (*http.Response, error) {
	token, authResp, err := t.auth(authService)
	if err != nil {
		return authResp, err
	}

	retryResp, err := t.retry(req, token, basic)
	return retryResp, err
}

func (t *TokenTransport) auth(authService *authService) (string, *http.Response, error) {
	if ecrImage, err := cdocker.ParseECRRegistry(authService.Realm); err != nil {
		authReq, err := authService.Request(t.Username, t.Password)
		if err != nil {
			return "", nil, err
		}

		client := http.Client{
			Transport: t.Transport,
		}

		response, err := client.Do(authReq)
		if err != nil {
			return "", nil, err
		}

		if response.StatusCode != http.StatusOK {
			return "", response, err
		}
		defer response.Body.Close()

		var authToken authToken
		decoder := json.NewDecoder(response.Body)
		err = decoder.Decode(&authToken)
		if err != nil {
			return "", nil, err
		}
		return authToken.Token, nil, nil
	} else {
		session, err := session.NewSession()
		if err != nil {
			return "", nil, err
		}

		e := ecr.New(session, aws.NewConfig().WithRegion(ecrImage.Region))
		authOutput, err := e.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{RegistryIds: []*string{&ecrImage.RegistryID}})
		if err != nil {
			return "", nil, err
		}

		return *authOutput.AuthorizationData[0].AuthorizationToken, nil, nil
	}
}

func (t *TokenTransport) retry(req *http.Request, token string, basic bool) (*http.Response, error) {
	scheme := "Bearer"
	if basic {
		scheme = "Basic"
	}

	req.Header.Set("Authorization", fmt.Sprintf("%s %s", scheme, token))
	resp, err := t.Transport.RoundTrip(req)
	return resp, err
}

type authService struct {
	Realm   string
	Service string
	Scope   string
}

func (authService *authService) Request(username, password string) (*http.Request, error) {
	url, err := url.Parse(authService.Realm)
	if err != nil {
		return nil, err
	}

	q := url.Query()
	q.Set("service", authService.Service)
	if authService.Scope != "" {
		q.Set("scope", authService.Scope)
	}
	url.RawQuery = q.Encode()

	request, err := http.NewRequest("GET", url.String(), nil)

	if username != "" || password != "" {
		request.SetBasicAuth(username, password)
	}

	return request, err
}

func isTokenDemand(resp *http.Response) (*authService, bool) {
	if resp == nil {
		return nil, false
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return nil, false
	}
	return parseOauthHeader(resp)
}

func parseOauthHeader(resp *http.Response) (*authService, bool) {

	challenges := parseAuthHeader(resp.Header)
	for _, challenge := range challenges {
		if challenge.Scheme == "bearer" {
			return &authService{
				Realm:   challenge.Parameters["realm"],
				Service: challenge.Parameters["service"],
				Scope:   challenge.Parameters["scope"],
			}, false
		} else if challenge.Scheme == "basic" {
			return &authService{
				Realm:   challenge.Parameters["realm"],
				Service: challenge.Parameters["service"],
				Scope:   challenge.Parameters["scope"],
			}, true
		}
	}
	return nil, false
}
