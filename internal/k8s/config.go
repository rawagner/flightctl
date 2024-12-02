package k8s

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
)

const (
	nsPath = SaPath + "/namespace"
)

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

func LoadClusterApi(ctx context.Context, k8sClient *K8sClient) (string, error) {
	resp, err := k8sClient.Get(ctx, "/apis/config.openshift.io/v1/infrastructures/cluster")
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", err
	}
	infrastructure := &InfrastructureCR{}
	err = ParseResponse(resp, infrastructure)
	if err != nil {
		return "", err
	}
	return infrastructure.Status.URL, nil
}

func LoadAppDomain(ctx context.Context, k8sClient *K8sClient, routeNs string) (string, error) {
	resp, err := k8sClient.Get(ctx, fmt.Sprintf("/apis/route.openshift.io/v1/namespaces/%s/routes/flightctl-api-route", routeNs))

	if err != nil || resp.StatusCode != http.StatusOK {
		return "", err
	}
	route := &Route{}
	err = ParseResponse(resp, route)
	if err != nil {
		return "", err
	}
	appsDomain, _ := strings.CutPrefix(route.Spec.Host, fmt.Sprintf("flightctl-api-route-%s.", routeNs))
	return appsDomain, nil
}

func GetCurrentNs() (string, error) {
	ns, err := os.ReadFile(nsPath)
	if err != nil {
		return "", fmt.Errorf("failed to read ns: %v", err)
	}
	return string(ns), nil
}
