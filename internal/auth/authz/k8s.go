package authz

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/flightctl/flightctl/internal/k8s"
	k8sAuthorizationV1 "k8s.io/api/authorization/v1"
)

type K8sAuthZ struct {
	K8sClient *k8s.K8sClient
}

func createSSAR(resource string, verb string) ([]byte, error) {
	ssar := k8sAuthorizationV1.SelfSubjectAccessReview{
		Spec: k8sAuthorizationV1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &k8sAuthorizationV1.ResourceAttributes{
				Verb:     verb,
				Group:    "flightctl.io",
				Resource: resource,
			},
		},
	}
	return json.Marshal(ssar)
}

func (k8sAuth K8sAuthZ) CheckPermission(ctx context.Context, k8sToken string, resource string, op string) (bool, error) {
	body, err := createSSAR(resource, op)
	if err != nil {
		return false, err
	}

	res, err := k8sAuth.K8sClient.Post(
		ctx,
		"/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
		body,
		k8s.WithToken(k8sToken),
	)
	if err != nil || res.StatusCode != http.StatusCreated {
		return false, err
	}

	ssar := &k8sAuthorizationV1.SelfSubjectAccessReview{}
	if err := k8s.ParseResponse(res, ssar); err != nil {
		return false, err
	}
	return ssar.Status.Allowed, nil
}
