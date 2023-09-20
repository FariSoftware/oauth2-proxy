package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// DatevProvider represents a Datev based Identity Provider
type DatevProvider struct {
	*ProviderData
}

var _ Provider = (*DatevProvider)(nil)

// GetLoginURL makes the LoginURL with optional nonce support
func (p *DatevProvider) GetLoginURL(redirectURI, state, nonce string, extraParams url.Values) string {
	extraParams.Add("response_mode", "query")
	extraParams.Add("nonce", nonce)

	loginURL := makeLoginURL(p.Data(), redirectURI, state, extraParams)

	q := loginURL.Query()
	q.Del("approval_prompt")
	q.Del("response_type")
	q.Add("response_type", "code id_token")
	loginURL.RawQuery = q.Encode()

	return loginURL.String()
}

const (
	datevProviderName = "Datev"
	datevDefaultScope = "openid profile email"
)

var (
	// Default Login URL for Datev.
	// Pre-parsed URL of https://cloud.digitalocean.com/v1/oauth/authorize.
	datevDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "login.datev.de",
		Path:   "openidsandbox/authorize",
	}

	// Default Redeem URL for Datev.
	// Pre-parsed URL of  https://cloud.digitalocean.com/v1/oauth/token.
	datevDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "sandbox-api.datev.de",
		Path:   "token",
	}

	// Default Profile URL for Datev.
	// Pre-parsed URL of https://cloud.digitalocean.com/v2/account.
	datevDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "sandbox-api.datev.de",
		Path:   "userinfo",
	}
)

// NewDatevProvider initiates a new DatevProvider
func NewDatevProvider(p *ProviderData) *DatevProvider {
	p.setProviderDefaults(providerDefaults{
		name:        datevProviderName,
		loginURL:    datevDefaultLoginURL,
		redeemURL:   datevDefaultRedeemURL,
		profileURL:  datevDefaultProfileURL,
		validateURL: datevDefaultProfileURL,
		scope:       datevDefaultScope,
	})
	p.getAuthorizationHeaderFunc = makeOIDCHeader
	p.SupportedCodeChallengeMethods = []string{"S256"}

	return &DatevProvider{ProviderData: p}
}

func (p *DatevProvider) makeDatevHeader(accessToken string) http.Header {
	// extra headers required by the GitHub API when making authenticated requests
	extraHeaders := map[string]string{
		"X-DATEV-Client-Id": p.ClientID,
	}
	return makeAuthorizationHeader("Bearer", accessToken, extraHeaders)
}

// ValidateSession validates the AccessToken
func (p *DatevProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}

func (p *DatevProvider) getUserInfo(ctx context.Context, s *sessions.SessionState) error {
	if s.AccessToken == "" {
		return fmt.Errorf("missing access token")
	}

	// // Need and extra header while talking with MS Graph. For more context see
	// // https://docs.microsoft.com/en-us/graph/api/group-list-transitivememberof?view=graph-rest-1.0&tabs=http#request-headers
	// extraHeader := makeAzureHeader(s.AccessToken)
	// extraHeader.Add("ConsistencyLevel", "eventual")

	if datevDefaultProfileURL.String() != "" {
		jsonRequest := requests.New(datevDefaultProfileURL.String()).
			WithContext(ctx).
			WithHeaders(p.makeDatevHeader(s.AccessToken))

		json, err := jsonRequest.Do().
			UnmarshalSimpleJSON()
		if err != nil {
			return fmt.Errorf("unable to unmarshal userinfo response: %v", err)

		}
		email, err := json.Get("email").String()

		if err != nil {
			return err
		}
		s.Email = email
	}

	return nil
}

func (p *DatevProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	p.getUserInfo(ctx, s)
	return nil
}

func (p *DatevProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrMissingCode
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if codeVerifier != "" {
		params.Add("code_verifier", codeVerifier)
	}
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	auth := p.ClientID + ":" + p.ClientSecret
	// var authEncoded []byte
	authEncoded := base64.RawStdEncoding.EncodeToString([]byte(auth))

	result := requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("Authorization", "Basic "+authEncoded).
		Do()
	if result.Error() != nil {
		return nil, result.Error()
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = result.UnmarshalInto(&jsonResponse)
	if err == nil {
		return &sessions.SessionState{
			AccessToken: jsonResponse.AccessToken,
		}, nil
	}

	values, err := url.ParseQuery(string(result.Body()))
	if err != nil {
		return nil, err
	}
	// TODO (@NickMeves): Uses OAuth `expires_in` to set an expiration
	if token := values.Get("access_token"); token != "" {
		ss := &sessions.SessionState{
			AccessToken: token,
		}
		ss.CreatedAtNow()
		return ss, nil
	}

	return nil, fmt.Errorf("no access token found %s", result.Body())
}
