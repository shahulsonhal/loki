package ibmiam

import (
	"fmt"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/ibm-cos-sdk-go/aws"
	"github.com/IBM/ibm-cos-sdk-go/aws/awserr"
	"github.com/IBM/ibm-cos-sdk-go/aws/credentials"
	"github.com/IBM/ibm-cos-sdk-go/aws/credentials/ibmiam/token"
)

const TrusterProfileProviderName = "TrusterProfileProviderNameIBM"

// TrustedProfileProvider Struct
type TrustedProfileProvider struct {
	// Name of Provider
	providerName string

	// Type of Provider - SharedCred, SharedConfig, etc.
	providerType string

	// Token Manager Provider uses
	authenticator *core.ContainerAuthenticator

	// Error
	ErrorStatus error

	// Logger attributes
	logger   aws.Logger
	logLevel *aws.LogLevelType
}

// NewProvider allows the creation of a custom IBM IAM Provider
// Parameters:
//
//	Provider Name
//	AWS Config
//	API Key
//	IBM IAM Authentication Server Endpoint
//	Service Instance ID
//	Token Manager client
//
// Returns:
//
//	Provider
func NewTrustedProfileProvider(providerName string, config *aws.Config, trustedProfileName, crTokenFilePath, authEndPoint string) *TrustedProfileProvider { //linter complain about (provider *Provider) {
	provider := new(TrustedProfileProvider)

	provider.providerName = providerName
	provider.providerType = "oauth"

	logLevel := aws.LogLevel(aws.LogOff)
	if config != nil && config.LogLevel != nil && config.Logger != nil {
		logLevel = config.LogLevel
		provider.logger = config.Logger
	}
	provider.logLevel = logLevel

	if crTokenFilePath == "" {
		provider.ErrorStatus = awserr.New("crTokenFilePathNotFound", "CR token file path not found", nil)
		if provider.logLevel.Matches(aws.LogDebug) {
			provider.logger.Log(debugLog, "<IBM IAM PROVIDER BUILD>", provider.ErrorStatus)
		}

		return provider
	}

	if authEndPoint == "" {
		authEndPoint = defaultAuthEndPoint
		if provider.logLevel.Matches(aws.LogDebug) {
			provider.logger.Log(debugLog, "<IBM IAM PROVIDER BUILD>", "using default auth endpoint", authEndPoint)
		}
	}

	authenticator, err := core.NewContainerAuthenticatorBuilder().
		SetIAMProfileName(trustedProfileName).
		SetCRTokenFilename(crTokenFilePath).
		SetURL("").
		Build()
	if err != nil {
		fmt.Println("err", err)
	}

	provider.authenticator = authenticator

	return provider
}

// IsValid ...
// Returns:
//
//	Provider validation - boolean
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
		if p.logLevel.Matches(aws.LogDebug) {
			p.logger.Log(debugLog, ibmiamProviderLog, p.providerName, p.ErrorStatus)
		}
		return credentials.Value{ProviderName: p.providerName}, p.ErrorStatus
	}

	tokenValue, err := p.authenticator.RequestToken()
	if err != nil {
		var returnErr error
		if p.logLevel.Matches(aws.LogDebug) {
			p.logger.Log(debugLog, ibmiamProviderLog, p.providerName, "ERROR ON GET", err)
			returnErr = awserr.New("TokenManagerRetrieveError", "error retrieving the token", err)
		} else {
			returnErr = awserr.New("TokenManagerRetrieveError", "error retrieving the token", nil)
		}
		return credentials.Value{}, returnErr
	}
	if p.logLevel.Matches(aws.LogDebug) {
		p.logger.Log(debugLog, ibmiamProviderLog, p.providerName, "GET TOKEN", tokenValue)
	}

	token := token.Token{
		AccessToken:  tokenValue.AccessToken,
		RefreshToken: tokenValue.RefreshToken,
		TokenType:    tokenValue.TokenType,
		ExpiresIn:    tokenValue.ExpiresIn,
		Expiration:   tokenValue.Expiration,
	}

	return credentials.Value{Token: token, ProviderName: p.providerName, ProviderType: p.providerType}, nil
}

// IsExpired ...
//
//	Provider expired or not - boolean
func (p *TrustedProfileProvider) IsExpired() bool {
	return true
}

// NewStaticProvider constructor of the IBM IAM provider that uses IAM details passed directly
// Returns: New Provider (AWS type)
func NewTrusterProfileProvider(config *aws.Config, authEndPoint, trusterProfileName, crTokenFilePath string) *TrustedProfileProvider {
	return NewTrustedProfileProvider(TrusterProfileProviderName, config, trusterProfileName, crTokenFilePath, authEndPoint)
}

// NewStaticCredentials constructor for IBM IAM that uses IAM credentials passed in
// Returns: credentials.NewCredentials(newStaticProvider()) (AWS type)
func NewTrusterProfileCredentials(config *aws.Config, authEndPoint, trusterProfileName, crTokenFilePath string) *credentials.Credentials {
	return credentials.NewCredentials(NewTrusterProfileProvider(config, authEndPoint, trusterProfileName, crTokenFilePath))
}
