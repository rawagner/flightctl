package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/flightctl/flightctl/internal/auth/common"
	"github.com/flightctl/flightctl/internal/k8s"
	k8sAuthenticationV1 "k8s.io/api/authentication/v1"
)

type K8sAuthN struct {
	k8sClient               *k8s.K8sClient
	externalOpenshiftApiUrl string
}

func NewK8sAuthN(k8sClient *k8s.K8sClient, externalOpenshiftApiUrl string) (*K8sAuthN, error) {
	authN := &K8sAuthN{
		k8sClient:               k8sClient,
		externalOpenshiftApiUrl: externalOpenshiftApiUrl,
	}
	return authN, nil
}

func (o K8sAuthN) ValidateToken(ctx context.Context, token string) (bool, error) {
	body, err := json.Marshal(k8sAuthenticationV1.TokenReview{
		Spec: k8sAuthenticationV1.TokenReviewSpec{
			Token: token,
		},
	})
	if err != nil {
		return false, fmt.Errorf("marshalling resource: %w", err)
	}
	res, err := o.k8sClient.Post(ctx, "/apis/authentication.k8s.io/v1/tokenreviews", body)
	if err != nil || res.StatusCode != http.StatusCreated {
		return false, err
	}

	review := &k8sAuthenticationV1.TokenReview{}
	if err := k8s.ParseResponse(res, review); err != nil {
		return false, err
	}
	return review.Status.Authenticated, nil
}

func (o K8sAuthN) GetAuthConfig() common.AuthConfig {
	return common.AuthConfig{
		Type: "k8s",
		Url:  o.externalOpenshiftApiUrl,
	}
}
