package handler

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

const Version = "0.0.1"

const SHUTDOWN_TIMEOUT = 5 * time.Second
const DEFAULT_SCOPE = "https://mail.google.com/"

type Handler struct {
	verbose   bool
	Flows     map[string]*Flow
	shutdown  chan struct{}
	server    http.Server
	client    APIClient
	Domain    string
	Usernames map[string]string
}

func NewHandler() (*Handler, error) {

	hostname, err := os.Hostname()
	if err != nil {
		return nil, Fatal(err)
	}
	_, domain, ok := strings.Cut(hostname, ".")
	if ok {
		ViperSetDefault("domain", domain)
	}

	apiClient, err := NewAPIClient("", "", "", "", "", nil)
	if err != nil {
		return nil, Fatal(err)
	}

	domain = ViperGetString("domain")

	ViperSetDefault("scope", DEFAULT_SCOPE)
	ViperSetDefault("frontend_uri", fmt.Sprintf("https://webmail.%s/oauth/", domain))

	h := Handler{
		verbose:  ViperGetBool("verbose"),
		Flows:    make(map[string]*Flow),
		shutdown: make(chan struct{}, 1),
		Domain:   ViperGetString("domain"),
		client:   apiClient,
	}

	err = h.ReadFlows()
	if err != nil {
		return nil, Fatal(err)
	}

	err = h.setUsernames()
	if err != nil {
		return nil, Fatal(err)
	}

	return &h, nil
}

type Response struct {
	Success bool   `json:"Success"`
	User    string `json:"User"`
	Message string `json:"Message"`
	Request string `json:"Request"`
}

type AuthenticateRequest struct {
	Username string
	Gmail    string
	JWT      string
}

func (h *Handler) ReadFlows() error {
	flows, err := ReadFlowMap()
	if err != nil {
		return Fatal(err)
	}
	h.Flows = flows
	log.Printf("ReadFlowState: flow count=%d\n", len(h.Flows))
	return nil
}

func (h *Handler) WriteFlows() error {
	if h.verbose {
		log.Printf("WriteFlows: flow count=%d\n", len(h.Flows))
	}
	err := WriteFlowMap(h.Flows)
	if err != nil {
		return Fatal(err)
	}
	return nil
}

func (h *Handler) fail(w http.ResponseWriter, request, message string, status int) {
	result := Response{
		Success: false,
		User:    "TOKEN_DAEMON",
		Request: request,
		Message: message,
	}
	h.logResponse(status, message, &result)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) failInternal(w http.ResponseWriter, request string, err error) {
	log.Printf("%s: %v\n", request, err)
	status := http.StatusInternalServerError
	result := Response{
		Success: false,
		User:    "TOKEN_DAEMON",
		Request: request,
		Message: "internal failure",
	}
	h.logResponse(status, result.Message, &result)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) succeed(w http.ResponseWriter, message string, result interface{}) {
	status := http.StatusOK
	h.logResponse(status, message, result)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) logResponse(status int, message string, result interface{}) {
	log.Printf("<--[%d] %s\n", status, message)
	if h.verbose {
		log.Println(FormatJSON(result))
	}
}

func (h *Handler) validateRequest(w http.ResponseWriter, r *http.Request, request interface{}) (string, map[string]string, bool) {
	// FIXME: authenticate request
	endpoint := r.URL.Path
	log.Printf("%s --> %s %s %s\n", r.Host, r.Proto, r.Method, endpoint)
	defer r.Body.Close()
	if r.Method == http.MethodPost {
		bodyData, err := io.ReadAll(r.Body)
		if err != nil {
			h.failInternal(w, endpoint, Fatal(err))
			return "", nil, false
		}
		if len(bodyData) > 0 {
			if request == nil {
				Warning("cannot unmarshall request body into: %v", request)
				request = make(map[string]any)
			}
			err := json.Unmarshal(bodyData, request)
			if err != nil {
				h.failInternal(w, endpoint, Fatal(err))
				return "", nil, false
			}
			if h.verbose {
				log.Printf("requestBody: %s\n", FormatJSON(request))
			}
		} else {

		}
	}
	params := parseQueryParams(r.URL)
	if h.verbose {
		log.Printf("queryParams: %s\n", FormatJSON(params))
	}
	return endpoint, params, true
}

func (h *Handler) handleAuthenticateRequest(w http.ResponseWriter, r *http.Request) {
	var request AuthenticateRequest
	endpoint, _, ok := h.validateRequest(w, r, &request)
	if !ok {
		return
	}
	if request.Username == "" {
		h.fail(w, endpoint, "missing username", http.StatusBadRequest)
		return
	}

	if !strings.HasPrefix(request.Username, "gmail.") {
		h.fail(w, endpoint, fmt.Sprintf("username %s missing 'gmail.' prefix", request.Username), http.StatusBadRequest)
		return
	}

	if !strings.HasSuffix(request.Username, "@"+h.Domain) {
		h.fail(w, endpoint, fmt.Sprintf("username %s domain mismatch", request.Username), http.StatusBadRequest)
		return
	}

	_, ok = h.Usernames[request.Username]
	if !ok {
		h.fail(w, endpoint, fmt.Sprintf("username %s is unknown", request.Username), http.StatusNotFound)
		return
	}

	flow, err := h.NewFlow(request.Username)
	if err != nil {
		h.failInternal(w, endpoint, Fatal(err))
		return
	}

	params := map[string]string{}
	params["scope"] = ViperGetString("scope")
	params["access_type"] = "offline"
	params["include_granted_scopes"] = "true"
	params["response_type"] = "code"
	params["state"] = flow.Nonce.Text
	params["redirect_uri"] = ViperGetString("authenticated_redirect_uri")
	params["client_id"] = ViperGetString("client_id")
	params["prompt"] = "select_account consent"

	authURI, err := h.buildURI(ViperGetString("auth_uri"), params)
	if err != nil {
		h.failInternal(w, endpoint, Fatal(err))
		return
	}

	// respond with the OAUTH2 auth URI
	var response Response
	response.Success = true
	response.User = request.Username
	response.Request = endpoint
	response.Message = authURI.String()
	h.succeed(w, response.Message, &response)
}

func (h *Handler) handleDeauthenticateRequest(w http.ResponseWriter, r *http.Request) {
	var request AuthenticateRequest
	endpoint, _, ok := h.validateRequest(w, r, &request)
	if !ok {
		return
	}

	if request.Username == "" {
		h.fail(w, endpoint, "missing username", http.StatusBadRequest)
		return
	}

	endpoint = fmt.Sprintf("deauthenticate %s", request.Username)

	if !strings.HasPrefix(request.Username, "gmail.") {
		h.fail(w, endpoint, "username requires 'gmail.' prefix", http.StatusBadRequest)
		return
	}

	if !strings.HasSuffix(request.Username, "@"+h.Domain) {
		h.fail(w, endpoint, fmt.Sprintf("domain must be %s", h.Domain), http.StatusBadRequest)
		return
	}

	_, ok = h.Usernames[request.Username]
	if !ok {
		h.fail(w, endpoint, fmt.Sprintf("unknown username: %s", request.Username), http.StatusNotFound)
		return
	}

	var deauthState string
	var deauthFlow *Flow
	for state, flow := range h.Flows {
		if flow.Local == request.Username {
			deauthState = state
			deauthFlow = flow
			break
		}
	}

	if deauthState == "" {
		h.fail(w, endpoint, fmt.Sprintf("no authorization found for: %s", request.Username), http.StatusNotFound)
	}

	delete(h.Flows, deauthState)
	states, err := ListFlowStates()
	if err != nil {
		h.failInternal(w, endpoint, Fatal(err))
		return
	}

	if slices.Contains(states, deauthState) {
		err := DeleteFlow(deauthFlow)
		if err != nil {
			h.failInternal(w, endpoint, Fatal(err))
			return
		}
	}

	var response Response
	response.Success = true
	response.User = request.Username
	response.Request = endpoint
	response.Message = fmt.Sprintf("OAUTH2 gmail tokens deleted for %s;  IMPORTANT: You must also remove the 3rd-party authorizations on your Google account.", request.Username)
	h.succeed(w, response.Message, &response)
}

func (h *Handler) buildURI(base string, params map[string]string) (*url.URL, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, Fatal(err)
	}
	q := u.Query()
	for key, value := range params {
		q.Set(key, value)
	}
	u.RawQuery = q.Encode()
	return u, nil
}

func parseQueryParams(uri *url.URL) map[string]string {
	params := map[string]string{}
	for key, value := range uri.Query() {
		switch len(value) {
		case 1:
			params[key] = value[0]
		default:
			params[key] = strings.Join(value, ",")
		}
	}
	return params
}

func (h *Handler) handleAuthenticatedCallback(w http.ResponseWriter, r *http.Request) {
	endpoint, authParams, ok := h.validateRequest(w, r, nil)
	if !ok {
		return
	}

	if r.Method != http.MethodGet {
		h.failInternal(w, endpoint, Fatalf("unexpected method: %s", r.Method))
		return
	}

	state := authParams["state"]
	flow, ok := h.Flows[state]
	if !ok {
		fmt.Printf("unknown OAUTH flow: state=%s\n", state)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	flow.Code = authParams["code"]
	relayParams := map[string]string{}
	relayParams["state"] = authParams["state"]
	relayParams["authentication"] = "success"
	relayParams["authorization"] = "pending"
	redirectURI, err := h.buildURI(ViperGetString("frontend_uri"), relayParams)
	if err != nil {
		h.failInternal(w, endpoint, Fatal(err))
		return
	}
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

func (h *Handler) handleAuthorizeRequest(w http.ResponseWriter, r *http.Request) {
	var request map[string]any
	endpoint, _, ok := h.validateRequest(w, r, &request)
	if !ok {
		return
	}
	state := request["state"].(string)
	flow, ok := h.Flows[state]
	if !ok {
		fmt.Printf("%s: unknown OAUTH flow: state=%s\n", endpoint, state)
		h.fail(w, endpoint, "unauthorized", http.StatusUnauthorized)
		return
	}

	requestHeader := map[string]string{
		"Content-Type":                     "application/json",
		"Access-Control-Allow-Origin":      "https://webmail.mailcapsule.io",
		"Access-Control-Allow-Methods":     "GET, POST, OPTIONS",
		"Access-Control-Allow-Credentials": "true",
	}

	requestData := map[string]string{
		"client_id":     ViperGetString("client_id"),
		"client_secret": ViperGetString("client_secret"),
		"code":          flow.Code,
		"grant_type":    "authorization_code",
		"redirect_uri":  ViperGetString("authenticated_redirect_uri"),
	}

	var responseData map[string]any
	_, err := h.client.Post(ViperGetString("token_uri"), &requestData, &responseData, &requestHeader)
	if err != nil {
		log.Printf("%s failed posting access request: %v", endpoint, Fatal(err))
		h.fail(w, endpoint, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("responseData: %s\n", FormatJSON(responseData))

	token, err := NewToken(responseData)
	if err != nil {
		h.failInternal(w, endpoint, Fatal(err))
		return
	}

	flow.Token = token
	gmailAddress := token.JWT["email"]
	flow.Gmail = gmailAddress
	h.Usernames[flow.Local] = gmailAddress

	var response Response
	response.Success = true
	response.User = flow.Local
	response.Request = endpoint
	response.Message = fmt.Sprintf("incoming mail to %s will be fetched to %s and outgoing mail will route via gmail", flow.Gmail, flow.Local)
	h.succeed(w, response.Message, &response)
}

func (h *Handler) handleAuthorizedCallback(w http.ResponseWriter, r *http.Request) {
	var requestData map[string]any
	_, _, ok := h.validateRequest(w, r, &requestData)
	if !ok {
		return
	}
	Warning("unexpected callback: %s", r.URL.String())
}

func (h *Handler) NewFlow(address string) (*Flow, error) {
	flow, err := NewFlow()
	if err != nil {
		return nil, Fatal(err)
	}
	flow.Local = address
	h.Flows[flow.Nonce.Text] = flow
	return flow, nil
}

/*
func (h *Handler) handleNonceRequest(w http.ResponseWriter, r *http.Request) {
	endpoint, ok := h.validateRequest(w, r, nil)
	flow, err := h.NewFlow("")
	if err != nil {
		h.failInternal(w, endpoint, Fatal(err))
		return
	}
	_, err = w.Write([]byte(flow.Nonce.Text))
	if err != nil {
		h.failInternal(w, endpoint, Fatal(err))
		return
	}
	w.WriteHeader(200)
	if h.verbose {
		log.Printf("New Flow: %s\n", FormatJSON(flow))
	}
}
*/

func (h *Handler) handleUsernamesRequest(w http.ResponseWriter, r *http.Request) {
	endpoint, _, ok := h.validateRequest(w, r, nil)
	if !ok {
		return
	}
	h.succeed(w, endpoint, &h.Usernames)
}

func (h *Handler) Run() error {
	err := h.Start()
	if err != nil {
		return err
	}
	err = h.Wait()
	if err != nil {
		return err
	}
	return nil
}

func (h *Handler) Start() error {

	log.Printf("tokend v%s uid=%d gid=%d started as PID %d", Version, os.Getuid(), os.Getgid(), os.Getpid())

	addr := ViperGetString("addr")
	port := ViperGetInt("port")
	h.server = http.Server{
		Addr:        fmt.Sprintf("%s:%d", addr, port),
		IdleTimeout: 5 * time.Second,
	}

	http.HandleFunc("POST /oauth/authenticate/", h.handleAuthenticateRequest)
	http.HandleFunc("POST /oauth/deauthenticate/", h.handleDeauthenticateRequest)
	http.HandleFunc("/oauth/authenticated/", h.handleAuthenticatedCallback)
	http.HandleFunc("POST /oauth/authorize/", h.handleAuthorizeRequest)
	http.HandleFunc("/oauth/authorized/", h.handleAuthorizedCallback)
	//http.HandleFunc("GET /oauth/nonce/", h.handleNonceRequest)
	http.HandleFunc("GET /oauth/usernames/", h.handleUsernamesRequest)

	go func() {
		log.Printf("listening for HTTP requests on %s\n", h.server.Addr)
		defer log.Println("exiting HTTP request handler")
		err := h.server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Printf("%s\n", Fatalf("ListenAndServe failed: %v", err))
		}
	}()

	return nil
}

func (h *Handler) Wait() error {

	if h.verbose {
		log.Println("Wait: waiting...")
	}

	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, syscall.SIGINT)
	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGTERM)
	if h.verbose {
		fmt.Println("CTRL-C to exit")
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-sigint:
				log.Println("received SIGINT")
				return
			case <-sigterm:
				log.Println("received SIGTERM")
				return
			case <-h.shutdown:
				log.Println("received shutdown request")
				return
			}
		}
	}()

	wg.Wait()

	if h.verbose {
		log.Println("Wait: initiating shutdown")
	}

	ctx, cancel := context.WithTimeout(context.Background(), SHUTDOWN_TIMEOUT)
	defer cancel()

	err := h.server.Shutdown(ctx)
	if err != nil {
		return Fatal(err)
	}

	err = h.WriteFlows()
	if err != nil {
		return Fatal(err)
	}

	if h.verbose {
		log.Println("Wait: shutdown complete")
	}
	return nil
}

func (h *Handler) Stop() error {
	if h.verbose {
		log.Println("Stop: requesting shutdown")
	}
	h.shutdown <- struct{}{}
	err := h.Wait()
	if err != nil {
		return Fatal(err)
	}
	if h.verbose {
		log.Println("Stop: stopped")
	}
	return nil
}

func (h *Handler) setUsernames() error {
	ifp, err := os.Open("/etc/passwd")
	if err != nil {
		return Fatal(err)
	}
	defer ifp.Close()

	defaultUsers := []string{}
	scanner := bufio.NewScanner(ifp)
	for scanner.Scan() {
		text := scanner.Text()
		if strings.HasPrefix(text, "gmail.") {
			user, _, ok := strings.Cut(text, ":")
			if ok {
				defaultUsers = append(defaultUsers, user)
			}
		}
	}
	err = scanner.Err()
	if err != nil {
		return Fatal(err)
	}

	ViperSet("usernames", defaultUsers)
	h.Usernames = make(map[string]string)
	for _, username := range ViperGetStringSlice("usernames") {
		address := username + "@" + h.Domain
		h.Usernames[address] = h.authorizedGmailAddress(address)
	}
	return nil
}

func (h *Handler) authorizedGmailAddress(address string) string {
	for _, flow := range h.Flows {
		if flow.Local == address {
			return flow.Gmail
		}
	}
	return ""
}
