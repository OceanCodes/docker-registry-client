package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
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

	if authService := isTokenDemand(resp); authService != nil {
		resp, err = t.authAndRetry(authService, req)
	}
	return resp, err
}

type authToken struct {
	Token string `json:"token"`
}

func (t *TokenTransport) authAndRetry(authService *authService, req *http.Request) (*http.Response, error) {
	log.Println("authAndRetry started")
	token, authResp, err := t.auth(authService)
	log.Printf("authAndRetry token %s ", token)
	if err != nil {
		log.Println("error auth")
		return authResp, err
	}

	retryResp, err := t.retry(req, token)
	return retryResp, err
}

func (t *TokenTransport) auth(authService *authService) (string, *http.Response, error) {
	log.Printf("auth started realm: %s", authService.Realm)

	if registryID, region, err := parseECRRegistry(authService.Realm); err != nil {
		log.Println("Basic")
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
		log.Printf("auth token: %s", authToken.Token)
		return authToken.Token, nil, nil
	} else {
		log.Println("ECR")

		session, err := session.NewSession()
		if err != nil {
			return "", nil, err
		}

		e := ecr.New(session, aws.NewConfig().WithRegion(region))
		authOutput, err := e.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{RegistryIds: []*string{&registryID}})
		if err != nil {
			return "", nil, err
		}

		log.Printf("auth token: %s", *authOutput.AuthorizationData[0].AuthorizationToken)

		return *authOutput.AuthorizationData[0].AuthorizationToken, nil, nil
	}
}

func (t *TokenTransport) retry(req *http.Request, token string) (*http.Response, error) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
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

func isTokenDemand(resp *http.Response) *authService {
	if resp == nil {
		return nil
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return nil
	}
	return parseOauthHeader(resp)
}

func parseOauthHeader(resp *http.Response) *authService {
	challenges := parseAuthHeader(resp.Header)
	for _, challenge := range challenges {
		if challenge.Scheme == "bearer" {
			return &authService{
				Realm:   challenge.Parameters["realm"],
				Service: challenge.Parameters["service"],
				Scope:   challenge.Parameters["scope"],
			}
		}
	}
	return nil
}

func parseECRRegistry(image string) (registryID, region string, err error) {

	// 524950183868.dkr.ecr.us-east-1.amazonaws.com
	registryRegex := regexp.MustCompile(`^(\d+)\.dkr\.ecr\.(.+)\.amazonaws\.com`)
	matches := registryRegex.FindStringSubmatch(image)
	if len(matches) != 2 {
		err = errors.New("Not an ECR image")
		return
	}
	registryID = matches[1]
	region = matches[2]
	return
}
