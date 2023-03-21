package ibmcloud

import (
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/ibm-cos-sdk-go/aws/awserr"
	"github.com/IBM/ibm-cos-sdk-go/aws/credentials"
	"github.com/IBM/ibm-cos-sdk-go/aws/credentials/ibmiam/token"
	"github.com/go-kit/log/level"
	log "github.com/grafana/loki/pkg/util/log"
)

const (
	trustedProfileProviderName = "TrustedProfileProviderNameIBM"
	tokenType                  = "Bearer"
)

// TrustedProfileProvider Struct
// This implements Provider interface from https://github.com/IBM/ibm-cos-sdk-go
type TrustedProfileProvider struct {
	// Name of Provider
	providerName string

	// Type of Provider - SharedCred, SharedConfig, etc.
	providerType string

	// Authenticator implements an IAM-based authentication schema
	authenticator *core.ContainerAuthenticator

	// Error
	ErrorStatus error
}

// NewTrustedProfileProvider allows the creation of a custom IBM IAM Provider
// Parameters:
//
//	Provider Name
//	AWS Config
//	Trusted Profile Name
//	Trusted Profile ID
//	Compute Resource Token File Path
//	IBM IAM Authentication Server Endpoint
//
// Returns:
//
//	TrustedProfileProvider
func NewTrustedProfileProvider(providerName string, trustedProfileName, trustedProfileID, crTokenFilePath,
	authEndPoint string) *TrustedProfileProvider {
	provider := new(TrustedProfileProvider)

	provider.providerName = providerName
	provider.providerType = "oauth"

	if trustedProfileName == "" && trustedProfileID == "" {
		provider.ErrorStatus = awserr.New("trustedProfileNotFound", "Trusted profile name or id not found", nil)
		level.Debug(log.Logger).Log("msg", provider.ErrorStatus)

		return provider
	}

	if crTokenFilePath == "" {
		provider.ErrorStatus = awserr.New("crTokenFilePathNotFound", "CR token file path not found", nil)
		level.Debug(log.Logger).Log("msg", provider.ErrorStatus)

		return provider
	}

	if authEndPoint == "" {
		authEndPoint = defaultCOSAuthEndpoint
		level.Debug(log.Logger).Log("msg", "using default auth endpoint", "endpoint", authEndPoint)
	}

	authenticator, err := core.NewContainerAuthenticatorBuilder().
		SetIAMProfileName(trustedProfileName).
		SetIAMProfileID(trustedProfileID).
		SetCRTokenFilename(crTokenFilePath).
		SetURL(authEndPoint).
		Build()
	if err != nil {
		provider.ErrorStatus = awserr.New("errCreatingAuthenticatorClient", "cannot setup new Authenticator client", err)
		level.Debug(log.Logger).Log("msg", provider.ErrorStatus)

		return provider
	}

	provider.authenticator = authenticator

	return provider
}

// IsValid ...
// Returns:
//
//	TrustedProfileProvider validation - boolean
func (p *TrustedProfileProvider) IsValid() bool {
	return nil == p.ErrorStatus
}

// Retrieve ...
// Returns:
//
//	Credential values
//	Error
func (p *TrustedProfileProvider) Retrieve() (credentials.Value, error) {
	if p.ErrorStatus != nil {
		level.Debug(log.Logger).Log("msg", p.ErrorStatus)

		return credentials.Value{ProviderName: p.providerName}, p.ErrorStatus
	}

	tokenValue, err := p.authenticator.GetToken()
	if err != nil {
		level.Debug(log.Logger).Log("msg", "error on get token", "err", err)
		returnErr := awserr.New("TokenGetError", "error on get token", nil)

		return credentials.Value{}, returnErr
	}

	return credentials.Value{
		Token: token.Token{
			AccessToken: tokenValue,
			TokenType:   tokenType,
		},
		ProviderName: p.providerName,
		ProviderType: p.providerType,
	}, nil
}

// IsExpired ...
//
// TrustedProfileProvider expired or not - boolean
// The GetToken function in Retrieve method is checking whether the token is expired
// or not before making the call to the server. Here we are skipping the expiry check
// since the token variable in authenticator is not an exported variable.
func (p *TrustedProfileProvider) IsExpired() bool {
	return true
}

// NewTPProvider constructor of the IBM IAM provider that uses trusted profile and CR token passed directly
// Returns: NewTrustedProfileProvider (AWS type)
func NewTPProvider(authEndPoint, trustedProfileName, trustedProfileID, crTokenFilePath string) *TrustedProfileProvider {
	return NewTrustedProfileProvider(trustedProfileProviderName, trustedProfileName, trustedProfileID, crTokenFilePath, authEndPoint)
}

// NewTrustedProfileCredentials constructor for IBM IAM that uses IAM credentials passed in
// Returns: credentials.NewCredentials(NewTPProvider()) (AWS type)
func NewTrustedProfileCredentials(authEndPoint, trustedProfileName, trustedProfileID, crTokenFilePath string) *credentials.Credentials {
	return credentials.NewCredentials(NewTPProvider(authEndPoint, trustedProfileName, trustedProfileID, crTokenFilePath))
}
