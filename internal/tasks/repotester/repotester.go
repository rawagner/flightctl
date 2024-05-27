package repotester

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	b64 "encoding/base64"
	"net/http"
	"regexp"
	"strings"

	api "github.com/flightctl/flightctl/api/v1alpha1"
	"github.com/flightctl/flightctl/internal/store"
	"github.com/flightctl/flightctl/internal/store/model"
	"github.com/flightctl/flightctl/pkg/log"
	"github.com/flightctl/flightctl/pkg/reqid"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/transport"
	gitclient "github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// Ref: https://github.com/git/git/blob/master/Documentation/urls.txt#L37
var scpLikeUrlRegExp = regexp.MustCompile(`^(?:(?P<user>[^@]+)@)?(?P<host>[^:\s]+):(?:(?P<port>[0-9]{1,5}):)?(?P<path>[^\\].*)$`)
var httpRepoRegExp = regexp.MustCompile(`https?:\/\/.*`)

type API interface {
	Test()
}

type RepoTester struct {
	log                    logrus.FieldLogger
	repoStore              store.Repository
	TypeSpecificRepoTester TypeSpecificRepoTester
}

func NewRepoTester(log logrus.FieldLogger, store store.Store) *RepoTester {
	return &RepoTester{
		log:                    log,
		repoStore:              store.Repository(),
		TypeSpecificRepoTester: &GitRepoTester{},
	}
}

func (r *RepoTester) TestRepositories() {
	reqid.OverridePrefix("repotester")
	requestID := reqid.NextRequestID()
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey, requestID)
	log := log.WithReqIDFromCtx(ctx, r.log)

	log.Info("Running RepoTester")

	repositories, err := r.repoStore.ListIgnoreOrg()
	if err != nil {
		log.Errorf("error fetching repositories: %s", err)
		return
	}

	for i := range repositories {
		repository := repositories[i]
		accessErr := r.TypeSpecificRepoTester.TestAccess(&repository)

		err := r.SetAccessCondition(repository, accessErr)
		if err != nil {
			log.Errorf("Failed to update repository status for %s: %v", repository.Name, err)
		}
	}
}

func configureRepoHTTPSClient(httpConfig api.RepositoryHttpConfig) error {
	tlsConfig := tls.Config{} //nolint:gosec
	if httpConfig.SkipServerVerification != nil {
		tlsConfig.InsecureSkipVerify = *httpConfig.SkipServerVerification //nolint:gosec
	}

	if httpConfig.TlsClientCertData != nil && httpConfig.TlsClientCertKey != nil {
		cert, err := b64.StdEncoding.DecodeString(*httpConfig.TlsClientCertData)
		if err != nil {
			return err
		}

		key, err := b64.StdEncoding.DecodeString(*httpConfig.TlsClientCertKey)
		if err != nil {
			return err
		}

		tlsPair, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return err
		}

		tlsConfig.Certificates = []tls.Certificate{tlsPair}
	}

	if httpConfig.RootCA != nil {
		ca, err := b64.StdEncoding.DecodeString(*httpConfig.RootCA)
		if err != nil {
			return err
		}

		rootCAs, _ := x509.SystemCertPool()
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		rootCAs.AppendCertsFromPEM(ca)
		tlsConfig.RootCAs = rootCAs
	}

	gitclient.InstallProtocol("https", githttp.NewClient(
		&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tlsConfig,
			},
		},
	))
	return nil
}

func GetAuth(repository *model.Repository) (transport.AuthMethod, error) {
	if httpRepoRegExp.MatchString(*repository.Spec.Data.Repo) && repository.Spec.Data.HttpConfig != nil {
		if strings.HasPrefix(*repository.Spec.Data.Repo, "https") {
			err := configureRepoHTTPSClient(*repository.Spec.Data.HttpConfig)
			if err != nil {
				return nil, err
			}
		}

		if repository.Spec.Data.HttpConfig.Username != nil && repository.Spec.Data.HttpConfig.Password != nil {
			auth := &githttp.BasicAuth{
				Username: *repository.Spec.Data.HttpConfig.Username,
				Password: *repository.Spec.Data.HttpConfig.Password,
			}
			return auth, nil
		}
	} else if scpLikeUrlRegExp.MatchString(*repository.Spec.Data.Repo) {
		if repository.Spec.Data.SshConfig != nil {

			sshPrivateKey, err := b64.StdEncoding.DecodeString(*repository.Spec.Data.SshConfig.SshPrivateKey)
			if err != nil {
				return nil, err
			}

			repoSubmatch := scpLikeUrlRegExp.FindStringSubmatch(*repository.Spec.Data.Repo)
			password := ""
			if repository.Spec.Data.SshConfig.PrivateKeyPassphrase != nil {
				password = *repository.Spec.Data.SshConfig.PrivateKeyPassphrase
			}
			auth, err := gitssh.NewPublicKeys(repoSubmatch[1], sshPrivateKey, password)
			if err != nil {
				return nil, err
			}
			if repository.Spec.Data.SshConfig.SkipServerVerification != nil && *repository.Spec.Data.SshConfig.SkipServerVerification {
				auth.HostKeyCallbackHelper = gitssh.HostKeyCallbackHelper{
					HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
				}
			}

			return auth, nil
		}
	}
	return nil, nil
}

type TypeSpecificRepoTester interface {
	TestAccess(repository *model.Repository) error
}

type GitRepoTester struct {
}

func (r *GitRepoTester) TestAccess(repository *model.Repository) error {
	remote := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name:  repository.Name,
		URLs:  []string{*repository.Spec.Data.Repo},
		Fetch: []config.RefSpec{"HEAD"},
	})

	listOps := &git.ListOptions{}
	auth, err := GetAuth(repository)
	if err != nil {
		return err
	}

	listOps.Auth = auth
	_, err = remote.List(listOps)
	return err
}

func (r *RepoTester) SetAccessCondition(repository model.Repository, err error) error {
	if repository.Status == nil {
		repository.Status = model.MakeJSONField(api.RepositoryStatus{Conditions: &[]api.Condition{}})
	}
	if repository.Status.Data.Conditions == nil {
		repository.Status.Data.Conditions = &[]api.Condition{}
	}
	changed := api.SetStatusConditionByError(repository.Status.Data.Conditions, api.RepositoryAccessible, "Accessible", "Inaccessible", err)
	if changed {
		return r.repoStore.UpdateStatusIgnoreOrg(&repository)
	}
	return nil
}
