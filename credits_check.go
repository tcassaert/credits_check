package credits_check

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

// The plugin configuration.
type config struct {
	CreditsCheckBackend string `json:"credits_check_backend"`
}

type creditsCheck struct {
	client http.Client
	name   string
	next   http.Handler
	url    string
}

type userPermission struct {
	Execution bool `json:"execution"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *config {
	return &config{}
}

// Initialize plugin.
func New(ctx context.Context, next http.Handler, config *config, name string) (http.Handler, error) {
	client := http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &creditsCheck{
		client: client,
		next:   next,
		name:   name,
		url:    config.CreditsCheckBackend,
	}, nil
}

func (cc *creditsCheck) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if len(req.Header.Get("Authorization")) == 0 {
		rw.WriteHeader(401)
		return
	} else {
		// Get the bearer token
		if strings.Contains(req.Header.Get("Authorization"), "Bearer ") {
			token := strings.Split(req.Header.Get("Authorization"), "Bearer ")[1]

			returnCode := getUserPermission(token, cc.url)

			if returnCode == 200 {
				rw.WriteHeader(returnCode)
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
				cc.next.ServeHTTP(rw, req)
			} else {
				rw.WriteHeader(returnCode)
			}
		} else {
			rw.WriteHeader(401)
		}
	}
}

func getUserPermission(token, url string) int {
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/user/permissions", url), nil)

	if err != nil {
		log.Fatal("Unable to get the user permissions")
		return 200
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req)

	if err != nil {
		log.Fatal("Unable to get the user permissions")
		return 200
	}

	if resp.StatusCode != 200 {
		return resp.StatusCode
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Fatal("Unable to get the user permissions")
		return 200
	}

	var userPermission userPermission

	jsonErr := json.Unmarshal(body, &userPermission)

	if jsonErr != nil {
		log.Fatal("Unable to get the user permissions")
		return 200
	}

	if userPermission.Execution {
		return 200
	} else {
		return 402
	}
}
