package hydra

import (
  "net/http"
  "bytes"
  "encoding/json"
  "io/ioutil"
  "errors"
  "fmt"
  "net/url"
  "golang.org/x/net/context"
  "golang.org/x/oauth2/clientcredentials"
)

// LOGIN STRUCT BEGIN

type LoginResponse struct {
  Skip        bool        `json:"skip"`
  RedirectTo  string      `json:"redirect_to"`
  Subject     string      `json:"subject"`
}

type LoginAcceptRequest struct {
  Subject     string      `json:"subject"`
  Remember    bool        `json:"remember,omitempty"`
  RememberFor int       `json:"remember_for,omitempty"`
}

type LoginAcceptResponse struct {
  RedirectTo  string      `json:"redirect_to"`
}

// LOGIN STRUCT END

// CONSENT STRUCT BEGIN

type ConsentResponse struct {
  Subject                      string                     `json:"subject"`
  Skip                         bool                       `json:"skip"`
  RedirectTo                   string                     `json:"redirect_to"`
  GrantAccessTokenAudience     string                     `json:"grant_access_token_audience"`
  RequestUrl                   string                     `json:"request_url"`
  RequestedAccessTokenAudience []string                   `json:"requested_access_token_audience"`
  RequestedScopes              []string                   `json:"requested_scope"`
}

type ConsentAcceptSession struct {
  AccessToken                  string                     `json:"access_token,omitempty"`
  IdToken                      string                     `json:"id_token,omitempty"`
}

type ConsentAcceptResponse struct {
  RedirectTo                   string                     `json:"redirect_to"`
}

type ConsentAcceptRequest struct {
  Subject                      string                     `json:"subject,omitempty"`
  GrantScope                   []string                   `json:"grant_scope"`
  Session                      ConsentAcceptSession  `json:"session" binding:"required"`
  GrantAccessTokenAudience     string                     `json:"grant_access_token_audience,omitempty" binding:"required"`
  Remember                     bool                       `json:"remember" binding:"required"`
  RememberFor                  int                        `json:"remember_for" binding:"required"`
}

type ConsentRejectResponse struct {
  RedirectTo string `json:"redirect_to"`
}

type ConsentRejectRequest struct {
  Error            string `json:"error"`
  ErrorDebug       string `json:"error_debug"`
  ErrorDescription string `json:"error_description"`
  ErrorHint        string `json:"error_hint"`
  StatusCode       int    `json:"status_code"`
}

// CONSENT STRUCT END

// LOGOUT STRUCT BEGIN

type LogoutResponse struct {
  RequestUrl string `json:"request_url"`
  RpInitiated bool `json:"rp_initiated"`
  Sid string `json:"sid"`
  Subject string `json:"subject"`
}

type LogoutAcceptRequest struct {

}

type LogoutAcceptResponse struct {
  RedirectTo string `json:"redirect_to"`
}

// LOGOUT STRUCT END

// OAUTH STRUCT BEGIN

type UserInfoResponse struct {
  Sub        string      `json:"sub"`
}

type IntrospectRequest struct {
  Token string `json:"token"`
  Scope string `json:"scope"`
}

type IntrospectResponse struct {
  Active string `json:"active"`
  Aud string `json:"aud"`
  ClientId string `json:"client_id"`
  Exp string `json:"exp"`
  Iat string `json:"iat"`
  Iss string `json:"iss"`
  Scope string `json:"scope"`
  Sub string `json:"sub"`
  TokenType string `json:"token_type"`
}

// OAUTH2 STRUCT END

type HydraClient struct {
  *http.Client
}

func NewHydraClient(config *clientcredentials.Config) *HydraClient {
  ctx := context.Background()
  client := config.Client(ctx)
  return &HydraClient{client}
}

// OAUTH FUNC BEGIN

func IntrospectToken(url string, client *HydraClient, introspectRequest IntrospectRequest) (IntrospectResponse, error) {
  var introspectResponse IntrospectResponse

  headers := map[string][]string{
    "Content-Type": []string{"application/x-www-form-urlencoded"},
    "Accept": []string{"application/json"},
  }

  values := url.Values{}
  values.Add("token", introspectRequest.Token)
  values.Add("scope", introspectRequest.Scope)
  body := values.Encode()

  request, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
  if err != nil {
    return introspectResponse, err
  }
  req.Header = headers

  response, err := client.Do(request)
  if err != nil {
    return introspectResponse, err
  }

  responseData, err := ioutil.ReadAll(response.Body)
  if err != nil {
    return introspectResponse, err
  }
  json.Unmarshal(responseData, &introspectResponse)

  return introspectResponse, nil
}

// config.Hydra.UserInfoUrl
func GetUserInfo(url string, client *HydraClient) (UserInfoResponse, error) {
  var hydraUserInfoResponse UserInfoResponse

  request, _ := http.NewRequest("GET", url, nil)

  response, err := client.Do(request)
  if err != nil {
    return hydraUserInfoResponse, err
  }

  responseData, err := ioutil.ReadAll(response.Body)
  if err != nil {
    return hydraUserInfoResponse, err
  }
  json.Unmarshal(responseData, &hydraUserInfoResponse)

  return hydraUserInfoResponse, nil
}

// OAUTH FUNC END

// LOGIN FUNC BEGIN

// config.Hydra.LoginRequestUrl
func GetLogin(url string, client *HydraClient, challenge string) (LoginResponse, error) {
  var hydraLoginResponse LoginResponse

  request, _ := http.NewRequest("GET", url, nil)

  query := request.URL.Query()
  query.Add("login_challenge", challenge)
  request.URL.RawQuery = query.Encode()

  response, err := client.Do(request)
  if err != nil {
    return hydraLoginResponse, err
  }

  responseData, err := ioutil.ReadAll(response.Body)
  if err != nil {
    return hydraLoginResponse, err
  }

  if response.StatusCode != 200 {
    return hydraLoginResponse, errors.New("Failed to retrive request from login_challenge, " + string(responseData))
  }

  json.Unmarshal(responseData, &hydraLoginResponse)

  return hydraLoginResponse, nil
}

// config.Hydra.LoginRequestAcceptUrl
func AcceptLogin(url string, client *HydraClient, challenge string, hydraLoginAcceptRequest LoginAcceptRequest) LoginAcceptResponse {
  var hydraLoginAcceptResponse LoginAcceptResponse

  body, _ := json.Marshal(hydraLoginAcceptRequest)

  request, _ := http.NewRequest("PUT", url, bytes.NewBuffer(body))

  query := request.URL.Query()
  query.Add("login_challenge", challenge)
  request.URL.RawQuery = query.Encode()

  response, _ := client.Do(request)
  responseData, _ := ioutil.ReadAll(response.Body)
  json.Unmarshal(responseData, &hydraLoginAcceptResponse)

  return hydraLoginAcceptResponse
}

// LOGIN FUNC END

// CONSENT FUNC BEGIN

// config.Hydra.ConsentRequestUrl
func GetConsent(url string, client *HydraClient, challenge string) (ConsentResponse, error) {
  var hydraConsentResponse ConsentResponse
  var err error

  request, _ := http.NewRequest("GET", url, nil)

  query := request.URL.Query()
  query.Add("consent_challenge", challenge)
  request.URL.RawQuery = query.Encode()

  response, _ := client.Do(request)

  statusCode := response.StatusCode

  if statusCode == 200 {
    responseData, _ := ioutil.ReadAll(response.Body)
    json.Unmarshal(responseData, &hydraConsentResponse)
    return hydraConsentResponse, nil
  }

  // Deny by default
  if ( statusCode == 404 ) {
    err = fmt.Errorf("Consent request not found for challenge %s", challenge)
  } else {
    err = fmt.Errorf("Consent request failed with status code %d for challenge %s", statusCode, challenge)
  }
  return hydraConsentResponse, err
}

// config.Hydra.ConsentRequestAcceptUrl
func AcceptConsent(url string, client *HydraClient, challenge string, hydraConsentAcceptRequest ConsentAcceptRequest) (ConsentAcceptResponse, error) {
  var hydraConsentAcceptResponse ConsentAcceptResponse

  body, _ := json.Marshal(hydraConsentAcceptRequest)

  request, _ := http.NewRequest("PUT", url, bytes.NewBuffer(body))

  query := request.URL.Query()
  query.Add("consent_challenge", challenge)
  request.URL.RawQuery = query.Encode()

  response, _ := client.Do(request)

  responseData, _ := ioutil.ReadAll(response.Body)

  json.Unmarshal(responseData, &hydraConsentAcceptResponse)

  return hydraConsentAcceptResponse, nil
}

// config.Hydra.ConsentRequestRejectUrl
func RejectConsent(url string, client *HydraClient, challenge string, hydraConsentRejectRequest ConsentRejectRequest) (ConsentRejectResponse, error) {
  var hydraConsentRejectResponse ConsentRejectResponse

  body, _ := json.Marshal(hydraConsentRejectRequest)

  request, _ := http.NewRequest("PUT", url, bytes.NewBuffer(body))

  query := request.URL.Query()
  query.Add("consent_challenge", challenge)
  request.URL.RawQuery = query.Encode()

  response, _ := client.Do(request)

  responseData, _ := ioutil.ReadAll(response.Body)

  json.Unmarshal(responseData, &hydraConsentRejectResponse)

  return hydraConsentRejectResponse, nil
}

// CONSENT FUNC END

// LOGOUT FUNC BEGIN

// config.Hydra.LogoutRequestUrl
func GetLogout(url string, client *HydraClient, challenge string) (LogoutResponse, error) {
  var hydraLogoutResponse LogoutResponse

  request, _ := http.NewRequest("GET", url, nil)

  query := request.URL.Query()
  query.Add("logout_challenge", challenge)
  request.URL.RawQuery = query.Encode()

  response, err := client.Do(request)
  if err != nil {
    return hydraLogoutResponse, err
  }

  responseData, _ := ioutil.ReadAll(response.Body)

  json.Unmarshal(responseData, &hydraLogoutResponse)

  return hydraLogoutResponse, nil
}

// config.Hydra.LogoutRequestAcceptUrl
func AcceptLogout(url string, client *HydraClient, challenge string, hydraLogoutAcceptRequest LogoutAcceptRequest) (LogoutAcceptResponse, error) {
  var hydraLogoutAcceptResponse LogoutAcceptResponse

  body, _ := json.Marshal(hydraLogoutAcceptRequest)

  request, _ := http.NewRequest("PUT", url, bytes.NewBuffer(body))

  query := request.URL.Query()
  query.Add("logout_challenge", challenge)
  request.URL.RawQuery = query.Encode()

  response, _ := client.Do(request)

  responseData, _ := ioutil.ReadAll(response.Body)
  json.Unmarshal(responseData, &hydraLogoutAcceptResponse)

  return hydraLogoutAcceptResponse, nil
}

// LOGOUT FUNC END
