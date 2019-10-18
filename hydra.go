package hydra

import (
  "log"
  "os"
  "net/url"
  "golang.org/x/net/context"
  "golang.org/x/oauth2/clientcredentials"
  oidc "github.com/coreos/go-oidc"
  "github.com/charmixer/hydra/client"
)

func main() {

  provider, err := oidc.NewProvider(context.Background(), os.Getenv("HYDRA_URL"))
  if err != nil {
    log.Panic(err)
    return
  }

  hydraConfig := &clientcredentials.Config{
    ClientID:     os.Getenv("CLIENT_ID"),
    ClientSecret: os.Getenv("CLIENT_SECRET"),
    TokenURL:     provider.Endpoint().TokenURL,
    Scopes:       []string{"openid"},
    EndpointParams: url.Values{"audience": {"hydra"}},
  }

  _ = client.NewHydraClient(hydraConfig)
}
