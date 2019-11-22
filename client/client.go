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
)

// LOGIN STRUCT BEGIN

type LoginResponse struct {
  Skip        bool        `json:"skip"`
  RedirectTo  string      `json:"redirect_to"`
  Subject     string      `json:"subject"`
  Client      Oauth2Client `json:"client"`
}

type LoginAcceptRequest struct {
  Subject     string    `json:"subject" validate:"required"`
  Remember    bool      `json:"remember,omitempty"`
  RememberFor int       `json:"remember_for,omitempty"`
  ACR         string    `json:"acr,omitempty"`
  Context     map[string]string `json:"context,omitempty"`
}

type LoginAcceptResponse struct {
  RedirectTo  string      `json:"redirect_to"`
}

type LoginRejectResponse struct {
  RedirectTo  string      `json:"redirect_to"`
}
type LoginRejectRequest struct {
  Error            string `json:"error,omitempty"`
  ErrorDebug       string `json:"error_debug,omitempty"`
  ErrorDescription string `json:"error_description,omitempty"`
  ErrorHint        string `json:"error_hint,omitempty"`
  StatusCode       int64 `json:"status_code,omitempty"`
}

// LOGIN STRUCT END

// OAuth2 Client BEGIN
type Oauth2Client struct {
  ClientId string `form:"client_id" json:"client_id,omitempty"`
}
// Oauth2 Client END

// CLIENT STRUCTS BEGIN

type Client struct {
  Id string `json:"client_id,omitempty"`
  Name string `json:"client_name,omitempty"`
  Secret string `json:"client_secret,omitempty"`
  Scope string `json:"scope,omitempty"`
  GrantTypes []string `json:"grant_types,omitempty"`
  Audience []string `json:"audience,omitempty"`
  ResponseTypes []string `json:"response_types,omitempty"`
  RedirectUris []string `json:"redirect_uris,omitempty"`
  TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
  PostLogoutRedirectUris []string `json:"post_logout_redirect_uris,omitempty"`
}

type CreateClientRequest Client
type CreateClientResponse Client

type UpdateClientRequest Client
type UpdateClientResponse Client

type ReadClientResponse Client

// CLIENT STRUCTS END

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
  Context                      map[string]string          `json:"context"`
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

// SESSION STRUCT BEGIN
type DeleteLoginSessionResponse struct {
  Debug            string `json:"debug"`
  Error            string `json:"error"`
  ErrorDescription string `json:"error_description"`
  StatusCode       int64  `json:"status_code"`
}
type DeleteLoginSessionRequest struct {
  Subject string `json:"subject"`
}
// SESSION STRUCT END

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

  values := url.Values{}
  values.Add("token", introspectRequest.Token)
  values.Add("scope", introspectRequest.Scope)
  body := values.Encode()

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

// config.Hydra.LoginRequestRejectUrl
func RejectLogin(url string, client *HydraClient, challenge string, hydraLoginAcceptRequest LoginRejectRequest) (hydraLoginRejectResponse LoginRejectResponse, err error) {

  body, err := json.Marshal(hydraLoginAcceptRequest)
  if err != nil {
    return hydraLoginRejectResponse, err
  }

  request, err := http.NewRequest("PUT", url, bytes.NewBuffer(body))
  if err != nil {
    return hydraLoginRejectResponse, err
  }

  query := request.URL.Query()
  query.Add("login_challenge", challenge)
  request.URL.RawQuery = query.Encode()

  response, err := client.Do(request)
  if err != nil {
    return hydraLoginRejectResponse, err
  }
  defer response.Body.Close()

  responseData, err := parseResponse(response)
  if err != nil {
    return hydraLoginRejectResponse, err
  }

  err = json.Unmarshal(responseData, &hydraLoginRejectResponse)
  if err != nil {
    return hydraLoginRejectResponse, err
  }

  return hydraLoginRejectResponse, nil
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


// CLIENTS FUNC BEGIN

func CreateClient(url string, createClientRequest CreateClientRequest) (createClientResponse CreateClientResponse, err error) {
  body, err := json.Marshal(createClientRequest)
  if err != nil {
    return CreateClientResponse{}, err
  }

  response, err := http.Post(url, "application/json", bytes.NewBuffer(body))
  if err != nil {
    return CreateClientResponse{}, err
  }

  responseData, err := parseResponse(response)
  if err != nil {
    return CreateClientResponse{}, err
  }

  err = json.Unmarshal(responseData, &createClientResponse)
  if err != nil {
    return CreateClientResponse{}, err
  }

  return createClientResponse, nil
}

func UpdateClient(url string, client_id string, updateClientRequest UpdateClientRequest) (updateClientResponse UpdateClientResponse, err error) {
  client := &http.Client{}

  url = url + "/" + client_id

  body, err := json.Marshal(updateClientRequest)
  if err != nil {
    return UpdateClientResponse{}, err
  }

  request, err := http.NewRequest("PUT", url, bytes.NewBuffer(body))
  if err != nil {
    return UpdateClientResponse{}, err
  }

  response, err := client.Do(request)
  if err != nil {
    return UpdateClientResponse{}, err
  }

  responseData, err := parseResponse(response)
  if err != nil {
    return UpdateClientResponse{}, err
  }

  err = json.Unmarshal(responseData, &updateClientResponse)
  if err != nil {
    return UpdateClientResponse{}, err
  }

  return updateClientResponse, nil
}

func DeleteClient(url string, client_id string) (err error) {
  client := &http.Client{}

  url = url + "/" + client_id

  request, err := http.NewRequest("DELETE", url, nil)
  if err != nil {
    return err
  }

  response, err := client.Do(request)
  if err != nil {
    return err
  }

  _, err = parseResponse(response)
  if err != nil {
    return err
  }

  return nil
}

func ReadClient(url string, client_id string) (readClientResponse ReadClientResponse, err error) {
  client := &http.Client{}

  url = url + "/" + client_id

  request, err := http.NewRequest("GET", url, nil)
  if err != nil {
    return ReadClientResponse{},err
  }

  response, err := client.Do(request)
  if err != nil {
    return ReadClientResponse{}, err
  }

  responseData, err := parseResponse(response)
  if err != nil {
    return ReadClientResponse{}, err
  }

  err = json.Unmarshal(responseData, &readClientResponse)
  if err != nil {
    return ReadClientResponse{}, err
  }

  return readClientResponse, nil
}

// CLIENTS FUNC END

// SESSION FUNC BEGIN
// config.Hydra.LogoutRequestAcceptUrl
func DeleteLoginSessions(url string, client *HydraClient, deleteLoginSessionsRequest DeleteLoginSessionRequest) (DeleteLoginSessionResponse, error) {
  var deleteLoginSessionsResponse DeleteLoginSessionResponse

  request, err := http.NewRequest("DELETE", url, nil)
  if err != nil {
    return deleteLoginSessionsResponse, err
  }

  query := request.URL.Query()
  query.Add("subject", deleteLoginSessionsRequest.Subject)
  request.URL.RawQuery = query.Encode()

  response, err := client.Do(request)
  if err != nil {
    return deleteLoginSessionsResponse, err
  }
  defer response.Body.Close()

  responseData, err := parseResponse(response)
  if err != nil {
    return deleteLoginSessionsResponse, err
  }

  err = json.Unmarshal(responseData, &deleteLoginSessionsResponse)
  if err != nil {
    return deleteLoginSessionsResponse, err
  }

  return deleteLoginSessionsResponse, nil
}
// SESSION FUNC END
