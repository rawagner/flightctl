package k8s

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

const (
	caCertPath  = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	apiService  = "https://kubernetes.default.svc"
)

type K8sClient struct {
	apiUrl string
	token  string
	client *http.Client
}

func NewK8sClient(apiUrl string, tlsConfig *tls.Config) (*K8sClient, error) {
	if apiUrl == apiService {
		_, err := os.Stat(caCertPath)
		if err == nil {
			k8sCert, err := os.ReadFile(caCertPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read k8s ca.crt: %w", err)
			}
			if tlsConfig.RootCAs == nil {
				tlsConfig.RootCAs = x509.NewCertPool()
			}
			tlsConfig.RootCAs.AppendCertsFromPEM(k8sCert)
		}
	}

	token, err := os.ReadFile(saTokenPath)
	if err != nil {
		return nil, fmt.Errorf("reading token file: %v", err)
	}

	return &K8sClient{
		apiUrl: apiUrl,
		token:  string(token),
		client: &http.Client{Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		}},
	}, nil
}

func (c *K8sClient) Post(ctx context.Context, resourcePath string, body []byte, options ...Option) (*http.Response, error) {
	ssarUrl := c.apiUrl + resourcePath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ssarUrl, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	return c.do(req, options...)
}

func (c *K8sClient) do(req *http.Request, options ...Option) (*http.Response, error) {
	req.Header = map[string][]string{
		"Authorization": {"Bearer " + c.token},
		"Content-Type":  {"application/json"},
	}

	for _, opt := range options {
		opt(req)
	}
	return c.client.Do(req)
}

func ParseResponse(res *http.Response, resource any) error {
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, resource)
}

type Option func(*http.Request)

func WithToken(token string) Option {
	return func(req *http.Request) {
		req.Header["Authorization"] = []string{"Bearer " + token}
	}
}
