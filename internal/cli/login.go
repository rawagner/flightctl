package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/flightctl/flightctl/internal/client"
	"github.com/spf13/cobra"
)

type LoginOptions struct {
	Token string
}

func NewCmdLogin() *cobra.Command {
	o := &LoginOptions{Token: ""}
	cmd := &cobra.Command{
		Use:   "login --token TOKEN",
		Short: "Login to flight control",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.Complete(cmd, args); err != nil {
				return err
			}
			if err := o.Validate(args); err != nil {
				return err
			}
			return o.Run(cmd.Context(), args)
		},
		SilenceUsage: true,
	}

	flags := cmd.Flags()
	flags.StringVarP(&o.Token, "token", "t", o.Token, "Bearer token for authentication to the API server")
	return cmd
}

func (o *LoginOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *LoginOptions) Validate(args []string) error {
	return nil
}

type OauthServerResponse struct {
	TokenEndpoint string `json:"token_endpoint"`
}

func (o *LoginOptions) Run(ctx context.Context, args []string) error {
	config, err := client.ParseConfigFile(defaultClientConfigFile)
	if err != nil {
		return err
	}

	if config.AuthInfo.K8sAuth != nil {
		return o.handleK8sAuth(ctx, config)
	}
	return errors.New("no authentication configured")
}

func (o *LoginOptions) handleK8sAuth(ctx context.Context, config *client.Config) error {
	if o.Token == "" {
		res, err := http.Get(config.AuthInfo.K8sAuth.ApiURL + "/.well-known/oauth-authorization-server")
		if err != nil {
			return err
		}
		oauthResponse := OauthServerResponse{}
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(bodyBytes, &oauthResponse); err != nil {
			return err
		}

		fmt.Printf("You must obtain an API token by visiting %s/request\n", oauthResponse.TokenEndpoint)
		fmt.Println("Then login via flightctl login --token=<token>")
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, config.AuthInfo.K8sAuth.ApiURL+"/apis/user.openshift.io/v1/users/~", nil)
	if err != nil {
		return err
	}

	req.Header = map[string][]string{
		"Authorization": {"Bearer " + o.Token},
		"Content-Type":  {"application/json"},
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if res.StatusCode != 200 {
		return errors.New("the token provided is invalid or expired")
	}

	config.AuthInfo.K8sAuth.Token = o.Token
	err = config.Persist(defaultClientConfigFile)
	if err != nil {
		return err
	}
	fmt.Println("Login successful.")
	return nil
}
