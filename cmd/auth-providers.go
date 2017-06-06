package cmd

import (
	"fmt"
	"sync"
)

type authProviders struct {
	sync.RWMutex
	SAML samlProvider `json:"saml"`
	// Add new auth providers.
}

const minioIAM = "arn:minio:iam:"

func (a *authProviders) GetAllAuthProviders() map[string]struct{} {
	authProviderArns := make(map[string]struct{})
	if a.SAML.Enable {
		// Construct the auth ARN.
		authARN := minioIAM + serverConfig.GetRegion() + ":1:saml"
		authProviderArns[authARN] = struct{}{}
	}
	return authProviderArns
}

func (a *authProviders) GetSAML() samlProvider {
	a.RLock()
	defer a.RUnlock()
	return a.SAML
}

type samlProvider struct {
	Enable  bool   `json:"enable"`
	IDPURL  string `json:"idp"`
	RootURL string `json:"sp"`
}

func (s samlProvider) Validate() error {
	if s.IDPURL != "" && s.RootURL != "" && s.Enable {
		return nil
	}
	return fmt.Errorf("Invalid saml provider configuration %#v", s)
}
