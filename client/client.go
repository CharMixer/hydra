package client

import (
  "net/http"
  "bytes"
  "encoding/json"
  "io/ioutil"
  "errors"
  "net/url"
  "golang.org/x/net/context"
  "golang.org/x/oauth2/clientcredentials"
  "fmt"
  "time"
)

// LOGIN STRUCT BEGIN

type LoginResponse struct {
  Skip        bool        `json:"skip"`
  RedirectTo  string      `json:"redirect_to"`
  Subject     string      `json:"subject"`
}

type LoginAcceptRequest struct {
  Subject     string    `json:"subject" validate:"required"`
  Remember    bool      `json:"remember,omitempty"`
  RememberFor int       `json:"remember_for,omitempty"`
  ACR         string    `json:"acr,omitempty"`
}

type LoginAcceptResponse struct {
  RedirectTo  string      `json:"redirect_to"`
}

// LOGIN STRUCT END

// OAuth2 Client BEGIN
type Oauth2Client struct {
  ClientId string `form:"client_id" json:"client_id,omitempty"`
}
// Oauth2 Client END

// CONSENT STRUCT BEGIN

type ConsentResponse struct {
  Subject                      string                     `json:"subject"`
  Skip                         bool                       `json:"skip"`
  RedirectTo                   string                     `json:"redirect_to"`
  GrantAccessTokenAudience     string                     `json:"grant_access_token_audience"`
  RequestUrl                   string                     `json:"request_url"`
  RequestedAccessTokenAudience []string                   `json:"requested_access_token_audience"`
  RequestedScopes              []string                   `json:"requested_scope"`
  Client                       Oauth2Client               `json:"client"`
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
  GrantAccessTokenAudience     []string                   `json:"grant_access_token_audience,omitempty"`
  Session                      ConsentAcceptSession       `json:"session" binding:"required"`
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

// https://www.ory.sh/docs/hydra/sdk/api#schemaoauth2tokenintrospection
type IntrospectResponse struct {
  Active bool `json:"active"`
  Aud []string `json:"aud"`
  ClientId string `json:"client_id"`
  Exp int64 `json:"exp"`

  // Ext ...
  // "ext": {
  // "property1": {},
  // "property2": {}
  // }

  Iat int64 `json:"iat"`
  Iss string `json:"iss"`
  Nbf int64 `json:"nbf"`
  ObfuscatedSubject string `json:"obfuscated_subject"`
  Scope string `json:"scope"`
  Sub string `json:"sub"`
  TokenType string `json:"token_type"`
  Username string `json:"username"`
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

func parseResponse(res *http.Response) ([]byte, error) {

  resData, err := ioutil.ReadAll(res.Body)
  if err != nil {
    return nil, err
  }

  switch (res.StatusCode) {
  case 200:
    return resData, nil
  case 400:
    return nil, errors.New("Bad Request: " + string(resData))
  case 401:
    return nil, errors.New("Unauthorized: " + string(resData))
  case 403:
    return nil, errors.New("Forbidden: " + string(resData))
  case 404:
    return nil, errors.New("Not Found: " + string(resData))
  case 500:
    return nil, errors.New("Internal Server Error")
  default:
    return nil, errors.New("Unhandled error")
  }
}

// OAUTH FUNC BEGIN

func IntrospectToken(introspectUrl string, client *HydraClient, introspectRequest IntrospectRequest) (IntrospectResponse, error) {
  var introspectResponse IntrospectResponse

  //headers := map[string][]string{
    //"Content-Type": []string{"application/x-www-form-urlencoded"},
    //"Accept": []string{"application/json"},
  //}

  values := url.Values{}
  values.Add("token", introspectRequest.Token)
  values.Add("scope", introspectRequest.Scope)
  body := values.Encode()

  /*
  request, err := http.NewRequest("POST", introspectUrl, bytes.NewBufferString(body))
  if err != nil {
    return introspectResponse, err
  }
  request.Header = headers

  response, err := client.Do(request)
  if err != nil {
    return introspectResponse, err
  }
  defer response.Body.Close()
*/

  response, err := http.Post(introspectUrl, "application/x-www-form-urlencoded", bytes.NewBufferString(body))
  if err != nil {
    return introspectResponse, err
  }
  defer response.Body.Close()

  responseData, err := parseResponse(response)
  if err != nil {
    return introspectResponse, err
  }

  err = json.Unmarshal(responseData, &introspectResponse)
  if err != nil {
    return introspectResponse, err
  }

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
  defer response.Body.Close()

  responseData, err := parseResponse(response)
  if err != nil {
    return hydraUserInfoResponse, err
  }

  err = json.Unmarshal(responseData, &hydraUserInfoResponse)
  if err != nil {
    return hydraUserInfoResponse, err
  }

  return hydraUserInfoResponse, nil
}

// OAUTH FUNC END

// LOGIN FUNC BEGIN

// config.Hydra.LoginRequestUrl
func GetLogin(url string, client *HydraClient, challenge string) (LoginResponse, error) {
  var hydraLoginResponse LoginResponse

  request, err := http.NewRequest("GET", url, nil)
  if err != nil {
    return hydraLoginResponse, err
  }

  query := request.URL.Query()
  query.Add("login_challenge", challenge)
  request.URL.RawQuery = query.Encode()

  response, err := client.Do(request)
  if err != nil {
    return hydraLoginResponse, err
  }
  defer response.Body.Close()

  responseData, err := parseResponse(response)
  if err != nil {
    return hydraLoginResponse, err
  }

  err = json.Unmarshal(responseData, &hydraLoginResponse)
  if err != nil {
    return hydraLoginResponse, err
  }

  return hydraLoginResponse, nil
}


// config.Hydra.LoginRequestAcceptUrl
func AcceptLogin(url string, client *HydraClient, challenge string, hydraLoginAcceptRequest LoginAcceptRequest) (LoginAcceptResponse, error) {
  var hydraLoginAcceptResponse LoginAcceptResponse

  body, err := json.Marshal(hydraLoginAcceptRequest)
  if err != nil {
    return hydraLoginAcceptResponse, err
  }

  request, err := http.NewRequest("PUT", url, bytes.NewBuffer(body))
  if err != nil {
    return hydraLoginAcceptResponse, err
  }

  query := request.URL.Query()
  query.Add("login_challenge", challenge)
  request.URL.RawQuery = query.Encode()

  response, err := client.Do(request)
  if err != nil {
    return hydraLoginAcceptResponse, err
  }
  defer response.Body.Close()

  responseData, err := parseResponse(response)
  if err != nil {
    return hydraLoginAcceptResponse, err
  }

  err = json.Unmarshal(responseData, &hydraLoginAcceptResponse)
  if err != nil {
    return hydraLoginAcceptResponse, err
  }

  return hydraLoginAcceptResponse, nil
}

// LOGIN FUNC END

// CONSENT FUNC BEGIN

// config.Hydra.ConsentRequestUrl
func GetConsent(url string, client *HydraClient, challenge string) (ConsentResponse, error) {
  var hydraConsentResponse ConsentResponse
  var err error

  request, err := http.NewRequest("GET", url, nil)
  if err != nil {
    return hydraConsentResponse, err
  }

  query := request.URL.Query()
  query.Add("consent_challenge", challenge)
  request.URL.RawQuery = query.Encode()

  response, err := client.Do(request)
  if err != nil {
    return hydraConsentResponse, err
  }
  defer response.Body.Close()

  responseData, err := parseResponse(response)
  if err != nil {
    return hydraConsentResponse, err
  }

  err = json.Unmarshal(responseData, &hydraConsentResponse)
  if err != nil {
    return hydraConsentResponse, err
  }

  return hydraConsentResponse, nil
}

// config.Hydra.ConsentRequestAcceptUrl
func AcceptConsent(url string, client *HydraClient, challenge string, hydraConsentAcceptRequest ConsentAcceptRequest) (ConsentAcceptResponse, error) {
  var hydraConsentAcceptResponse ConsentAcceptResponse

  body, err := json.Marshal(hydraConsentAcceptRequest)
  if err != nil {
    return hydraConsentAcceptResponse, err
  }

  request, err := http.NewRequest("PUT", url, bytes.NewBuffer(body))
  if err != nil {
    return hydraConsentAcceptResponse, err
  }

  query := request.URL.Query()
  query.Add("consent_challenge", challenge)
  request.URL.RawQuery = query.Encode()

  response, err := client.Do(request)
  if err != nil {
    return hydraConsentAcceptResponse, err
  }
  defer response.Body.Close()

  responseData, err := parseResponse(response)
  if err != nil {
    return hydraConsentAcceptResponse, err
  }

  err = json.Unmarshal(responseData, &hydraConsentAcceptResponse)
  if err != nil {
    return hydraConsentAcceptResponse, err
  }

  return hydraConsentAcceptResponse, nil
}

// config.Hydra.ConsentRequestRejectUrl
func RejectConsent(url string, client *HydraClient, challenge string, hydraConsentRejectRequest ConsentRejectRequest) (ConsentRejectResponse, error) {
  var hydraConsentRejectResponse ConsentRejectResponse

  body, err := json.Marshal(hydraConsentRejectRequest)
  if err != nil {
    return hydraConsentRejectResponse, err
  }

  request, err := http.NewRequest("PUT", url, bytes.NewBuffer(body))
  if err != nil {
    return hydraConsentRejectResponse, err
  }

  query := request.URL.Query()
  query.Add("consent_challenge", challenge)
  request.URL.RawQuery = query.Encode()

  response, err := client.Do(request)
  if err != nil {
    return hydraConsentRejectResponse, err
  }
  defer response.Body.Close()

  responseData, err := parseResponse(response)
  if err != nil {
    return hydraConsentRejectResponse, err
  }

  err = json.Unmarshal(responseData, &hydraConsentRejectResponse)
  if err != nil {
    return hydraConsentRejectResponse, err
  }

  return hydraConsentRejectResponse, nil
}

// CONSENT FUNC END

// LOGOUT FUNC BEGIN

// config.Hydra.LogoutRequestUrl
func GetLogout(url string, client *HydraClient, challenge string) (LogoutResponse, error) {
  var hydraLogoutResponse LogoutResponse

  request, err := http.NewRequest("GET", url, nil)
  if err != nil {
    return hydraLogoutResponse, err
  }

  query := request.URL.Query()
  query.Add("logout_challenge", challenge)
  request.URL.RawQuery = query.Encode()

  response, err := client.Do(request)
  if err != nil {
    return hydraLogoutResponse, err
  }
  defer response.Body.Close()

  responseData, err := parseResponse(response)
  if err != nil {
    return hydraLogoutResponse, err
  }

  err = json.Unmarshal(responseData, &hydraLogoutResponse)
  if err != nil {
    return hydraLogoutResponse, err
  }

  return hydraLogoutResponse, nil
}

// config.Hydra.LogoutRequestAcceptUrl
func AcceptLogout(url string, client *HydraClient, challenge string, hydraLogoutAcceptRequest LogoutAcceptRequest) (LogoutAcceptResponse, error) {
  var hydraLogoutAcceptResponse LogoutAcceptResponse

  body, err := json.Marshal(hydraLogoutAcceptRequest)
  if err != nil {
    return hydraLogoutAcceptResponse, err
  }

  request, err := http.NewRequest("PUT", url, bytes.NewBuffer(body))
  if err != nil {
    return hydraLogoutAcceptResponse, err
  }

  query := request.URL.Query()
  query.Add("logout_challenge", challenge)
  request.URL.RawQuery = query.Encode()

  response, err := client.Do(request)
  if err != nil {
    return hydraLogoutAcceptResponse, err
  }
  defer response.Body.Close()

  responseData, err := parseResponse(response)
  if err != nil {
    return hydraLogoutAcceptResponse, err
  }

  err = json.Unmarshal(responseData, &hydraLogoutAcceptResponse)
  if err != nil {
    return hydraLogoutAcceptResponse, err
  }

  return hydraLogoutAcceptResponse, nil
}

// LOGOUT FUNC END
