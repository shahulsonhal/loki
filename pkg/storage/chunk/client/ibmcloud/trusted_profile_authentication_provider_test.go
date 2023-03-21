package ibmcloud

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/IBM/ibm-cos-sdk-go/aws/credentials/ibmiam/token"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TrustedProfileProvider(t *testing.T) {
	tests := []struct {
		name,
		trustedProfileProviderName,
		authEndPoint,
		trustedProfileName,
		trustedProfileID,
		crTokenFilePath string
		token   string
		isValid bool
		wantErr error
	}{
		{
			"valid inputs",
			trustedProfileProviderName,
			"",
			"test-trusted-profile",
			"test-trusted-profile-id",
			"",
			"test-token",
			true,
			nil,
		},
		{
			"empty CR token file path",
			trustedProfileProviderName,
			"",
			"test-trusted-profile",
			"test-trusted-profile-id",
			"",
			"",
			false,
			errors.New("crTokenFilePathNotFound: CR token file path not found"),
		},
		{
			"empty profileName and profileID",
			trustedProfileProviderName,
			"",
			"",
			"",
			"",
			"",
			false,
			errors.New("trustedProfileNotFound: Trusted profile name or id not found"),
		},
	}

	for _, tt := range tests {

		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := token.Token{
				AccessToken:  tt.token,
				RefreshToken: "not-supported",
				TokenType:    tokenType,
				ExpiresIn:    int64((time.Hour * 24).Seconds()),
				Expiration:   time.Now().Add(time.Hour * 24).Unix(),
			}

			data, err := json.Marshal(token)
			require.NoError(t, err)

			w.WriteHeader(http.StatusAccepted)
			_, err = w.Write(data)
			require.NoError(t, err)
		}))

		if tt.isValid {
			file, err := createTempFile("crtoken", "test cr token")
			require.NoError(t, err)
			defer os.Remove(file.Name())
			tt.crTokenFilePath = file.Name()
		}

		prov := NewTrustedProfileProvider(tt.trustedProfileProviderName, tt.trustedProfileName, tt.trustedProfileID,
			tt.crTokenFilePath, authServer.URL)

		if !tt.isValid {
			assert.Equal(t, tt.crTokenFilePath, "", "cr token filepath did not match")
			assert.Equal(t, tt.wantErr.Error(), prov.ErrorStatus.Error())
		} else {
			assert.Equal(t, tt.trustedProfileName, prov.authenticator.IAMProfileName, "trusted profile name did not match")
			assert.Equal(t, tt.trustedProfileID, prov.authenticator.IAMProfileID, "trusted profile ID did not match")
			assert.Equal(t, authServer.URL, prov.authenticator.URL, "auth endpoint did not match")
			assert.Equal(t, tt.crTokenFilePath, prov.authenticator.CRTokenFilename, "cr token filepath did not match")
			assert.Equal(t, tt.trustedProfileProviderName, prov.providerName, "provider name did not match")
			assert.Equal(t, "oauth", prov.providerType)
		}

		isValid := prov.IsValid()
		assert.Equal(t, tt.isValid, isValid)

		isExpired := prov.IsExpired()
		assert.Equal(t, true, isExpired)

		cred, err := prov.Retrieve()
		if tt.wantErr != nil {
			require.Equal(t, tt.wantErr.Error(), err.Error())

			continue
		}

		assert.Equal(t, tt.token, cred.AccessToken)
		assert.Equal(t, tokenType, cred.TokenType)
	}
}

func createTempFile(name, fileContent string) (*os.File, error) {
	file, err := ioutil.TempFile(os.TempDir(), "crtoken")
	if err != nil {
		return nil, err
	}

	defer file.Close()
	_, err = file.Write([]byte("test cr token"))

	return file, err
}
