package main

import (
	"context"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
	"io/ioutil"
	"net/http"
	"os"
)

var (
	oauthConfig *oauth2.Config
)

var ctx = context.Background()

func init() {
	oauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/callback",
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		Scopes:       []string{"54f98af6-5da1-4d54-8610-8fad122aa628/.default", "openid", "profile", "email"},
		Endpoint:     endpoints.AzureAD("a1a72d9c-49e6-4f6d-9af6-5aafa1183bfd"),
	}
}
func main() {
	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/private/external", handleCallback)
	http.HandleFunc("/callback", handleCallback)
	http.ListenAndServe(":8080", nil)
}

func handleMain(w http.ResponseWriter, r *http.Request) {
	var htmlIndex = `<html>
<body>
	 <a href="/private/info">show token info</a>
		<br><a href="/login">login</a>
		<br><a href="/logout">logout</a>
		<br><a href="/private/external">call external service</a>
		<br><a href="/private/only-with-role">only with role</a>
</body>
</html>`
	fmt.Fprintf(w, htmlIndex)
}

var (
	// TODO: randomize it
	oauthStateString = "pseudo-random"
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
	url := oauthConfig.AuthCodeURL(oauthStateString, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	content, err := getUserInfo(r.FormValue("state"), r.FormValue("code"))
	if err != nil {
		fmt.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	//fmt.Fprintf(w, "Content: %s\n", content)
	fmt.Fprintf(w, string(content))
}
func getUserInfo(state string, code string) ([]byte, error) {
	if state != oauthStateString {
		return nil, fmt.Errorf("invalid oauth state")
	}
	token, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %s", err.Error())
	}
	client := oauthConfig.Client(ctx, token)
	response, err := client.Get("https://gateway.hub.db.de/bizhub-api-secured-with-jwt")

	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %s", err.Error())
	}
	return contents, nil
}
