package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/flightctl/flightctl/internal/util"
	"sigs.k8s.io/yaml"
)

const (
	appName = "flightctl"

	k8sCACertPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	saTokenPath   = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	nsPath        = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

type Config struct {
	Database   *dbConfig         `json:"database,omitempty"`
	Service    *svcConfig        `json:"service,omitempty"`
	Queue      *queueConfig      `json:"queue,omitempty"`
	KV         *kvConfig         `json:"kv,omitempty"`
	Auth       *authConfig       `json:"auth,omitempty"`
	Prometheus *prometheusConfig `json:"prometheus,omitempty"`
}

type dbConfig struct {
	Type     string `json:"type,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Port     uint   `json:"port,omitempty"`
	Name     string `json:"name,omitempty"`
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
}

type svcConfig struct {
	Address              string   `json:"address,omitempty"`
	AgentEndpointAddress string   `json:"agentEndpointAddress,omitempty"`
	AgentGrpcAddress     string   `json:"agentGrpcAddress,omitempty"`
	CertStore            string   `json:"cert,omitempty"`
	BaseUrl              string   `json:"baseUrl,omitempty"`
	BaseAgentEndpointUrl string   `json:"baseAgentEndpointUrl,omitempty"`
	BaseAgentGrpcUrl     string   `json:"baseAgentGrpcUrl,omitempty"`
	BaseUIUrl            string   `json:"baseUIUrl,omitempty"`
	CaCertFile           string   `json:"caCertFile,omitempty"`
	CaKeyFile            string   `json:"caKeyFile,omitempty"`
	SrvCertFile          string   `json:"srvCertFile,omitempty"`
	SrvKeyFile           string   `json:"srvKeyFile,omitempty"`
	AltNames             []string `json:"altNames,omitempty"`
	LogLevel             string   `json:"logLevel,omitempty"`
}

type queueConfig struct {
	AmqpURL string `json:"amqpUrl,omitempty"`
}

type kvConfig struct {
	Hostname string `json:"hostname,omitempty"`
	Port     uint   `json:"port,omitempty"`
}

type authConfig struct {
	OpenShiftApiUrl         string `json:"openShiftApiUrl,omitempty"`
	InternalOpenShiftApiUrl string `json:"internalOpenShiftApiUrl,omitempty"`
	OIDCAuthority           string `json:"oidcAuthority,omitempty"`
	InternalOIDCAuthority   string `json:"internalOidcAuthority,omitempty"`
	CACert                  string `json:"caCert,omitempty"`
	InsecureSkipTlsVerify   bool   `json:"insecureSkipTlsVerify,omitempty"`
}

type prometheusConfig struct {
	Address        string    `json:"address,omitempty"`
	SloMax         float64   `json:"sloMax,omitempty"`
	ApiLatencyBins []float64 `json:"apiLatencyBins,omitempty"`
}

func ConfigDir() string {
	return filepath.Join(util.MustString(os.UserHomeDir), "."+appName)
}

func ConfigFile() string {
	return filepath.Join(ConfigDir(), "config.yaml")
}

func ClientConfigFile() string {
	return filepath.Join(ConfigDir(), "client.yaml")
}

func CertificateDir() string {
	return filepath.Join(ConfigDir(), "certs")
}

func NewDefault() *Config {
	c := &Config{
		Database: &dbConfig{
			Type:     "pgsql",
			Hostname: "localhost",
			Port:     5432,
			Name:     "flightctl",
			User:     "admin",
			Password: "adminpass",
		},
		Service: &svcConfig{
			Address:              ":3443",
			AgentEndpointAddress: ":7443",
			AgentGrpcAddress:     ":7444",
			CertStore:            CertificateDir(),
			BaseUrl:              "https://localhost:3443",
			BaseAgentEndpointUrl: "https://localhost:7443",
			BaseAgentGrpcUrl:     "grpcs://localhost:7444",
			LogLevel:             "info",
		},
		Queue: &queueConfig{
			AmqpURL: "amqp://localhost:5672",
		},
		KV: &kvConfig{
			Hostname: "localhost",
			Port:     6379,
		},
		Prometheus: &prometheusConfig{
			Address:        ":15690",
			SloMax:         4.0,
			ApiLatencyBins: []float64{1e-7, 1e-6, 1e-5, 1e-4, 1e-3, 1e-2, 1e-1, 1e0},
		},
	}
	return c
}

func NewFromFile(cfgFile string) (*Config, error) {
	cfg, err := Load(cfgFile)
	if err != nil {
		return nil, err
	}
	loadClusterDetails(cfg)
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func LoadOrGenerate(cfgFile string) (*Config, error) {
	if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(cfgFile), os.FileMode(0755)); err != nil {
			return nil, fmt.Errorf("creating directory for config file: %v", err)
		}
		if err := Save(NewDefault(), cfgFile); err != nil {
			return nil, err
		}
	}
	return NewFromFile(cfgFile)
}

func Load(cfgFile string) (*Config, error) {
	contents, err := os.ReadFile(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %v", err)
	}
	c := &Config{}
	if err := yaml.Unmarshal(contents, c); err != nil {
		return nil, fmt.Errorf("decoding config: %v", err)
	}
	return c, nil
}

func Save(cfg *Config, cfgFile string) error {
	contents, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encoding config: %v", err)
	}
	if err := os.WriteFile(cfgFile, contents, 0600); err != nil {
		return fmt.Errorf("writing config file: %v", err)
	}
	return nil
}

func Validate(cfg *Config) error {
	return nil
}

func (cfg *Config) String() string {
	contents, err := json.Marshal(cfg)
	if err != nil {
		return "<error>"
	}
	return string(contents)
}

type InfrastructureCR struct {
	Status struct {
		URL string `json:"apiServerURL"`
	} `json:"status"`
}

type Route struct {
	Spec struct {
		Host string `json:"host"`
	} `json:"spec"`
}

func fetchFromCluster(path string) ([]byte, error) {
	tlsConfig := &tls.Config{}
	_, err := os.Stat(k8sCACertPath)
	if err == nil {
		k8sCert, err := os.ReadFile(k8sCACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read k8s ca.crt: %w", err)
		}
		if tlsConfig.RootCAs == nil {
			tlsConfig.RootCAs = x509.NewCertPool()
		}
		tlsConfig.RootCAs.AppendCertsFromPEM(k8sCert)
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: tlsConfig,
	}}

	token, err := os.ReadFile(saTokenPath)
	if err != nil {
		return nil, fmt.Errorf("reading token file: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, fmt.Sprintf("https://kubernetes.default.svc/apis/%s", path), nil)
	if err != nil {
		return nil, err
	}

	req.Header = map[string][]string{
		"Authorization": {"Bearer " + string(token)},
		"Content-Type":  {"application/json"},
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return io.ReadAll(res.Body)

}

func loadClusterDetails(cfg *Config) error {
	if _, err := os.Stat(saTokenPath); err == nil {
		resp, err := fetchFromCluster("config.openshift.io/v1/infrastructures/cluster")
		if err != nil {
			return err
		}

		infrastructure := &InfrastructureCR{}
		if err := yaml.Unmarshal(resp, infrastructure); err != nil {
			return fmt.Errorf("decoding infrastructure cr: %v", err)
		}

		cfg.Auth.OpenShiftApiUrl = infrastructure.Status.URL

		ns, err := os.ReadFile(nsPath)
		if err != nil {
			return fmt.Errorf("failed to read ns: %v", err)
		}
		nsStr := string(ns)
		resp, err = fetchFromCluster(fmt.Sprintf("route.openshift.io/v1/namespaces/%s/routes/flightctl-api-route", nsStr))
		if err != nil {
			return err
		}

		routeCr := &Route{}
		if err := yaml.Unmarshal(resp, routeCr); err != nil {
			return fmt.Errorf("decoding route: %v", err)
		}

		appsDomain, _ := strings.CutPrefix(routeCr.Spec.Host, fmt.Sprintf("flightctl-api-route-%s.", nsStr))

		cfg.Service.AltNames = append(
			cfg.Service.AltNames,
			routeCr.Spec.Host,
			fmt.Sprintf("flightctl-api-route-agent-%s.%s", nsStr, appsDomain),
			fmt.Sprintf("flightctl-api-route-agent-grpc-%s.%s", nsStr, appsDomain),
		)
		cfg.Service.BaseUrl = fmt.Sprintf("https://%s", routeCr.Spec.Host)
		cfg.Service.BaseAgentEndpointUrl = fmt.Sprintf("https://flightctl-api-route-agent-%s.%s", nsStr, appsDomain)
		cfg.Service.BaseAgentGrpcUrl = fmt.Sprintf("grpcs://flightctl-api-route-agent-grpc-%s.%s", nsStr, appsDomain)
		cfg.Service.BaseUIUrl = fmt.Sprintf("https://console-openshift-console.%s", appsDomain)
	}
	return nil
}
