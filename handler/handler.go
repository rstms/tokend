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
	"strings"
	"sync"
	"syscall"
	"time"
)

const Version = "0.0.1"

const SHUTDOWN_TIMEOUT = 5 * time.Second

type Handler struct {
	verbose   bool
	Flows     map[string]*Flow
	Tokens    map[string]*Token
	Usernames map[string]string
	shutdown  chan struct{}
	server    http.Server
	client    APIClient
	apiKey    string
	Domain    string
}

func NewHandler() (*Handler, error) {

	log.Printf("tokend v%s uid=%d gid=%d started as PID %d", Version, os.Getuid(), os.Getgid(), os.Getpid())

	hostname, err := os.Hostname()
	if err != nil {
		return nil, Fatal(err)
	}
	_, domain, ok := strings.Cut(hostname, ".")
	if ok {
		ViperSetDefault("domain", domain)
	}
	domain = ViperGetString("domain")

	ViperSetDefault("scopes", []string{"https://mail.google.com/"})
	ViperSetDefault("frontend_uri", fmt.Sprintf("https://webmail.%s/oauth/", domain))
	ViperSetDefault("auth_uri", "https://accounts.google.com/o/oauth2/auth")
	ViperSetDefault("token_uri", "https://oauth2.googleapis.com/token")
	ViperSetDefault("authenticated_redirect_uri", fmt.Sprintf("https://webmail.%s/oauth/authenticated/", domain))
	ViperSetDefault("authorized_redirect_uri", fmt.Sprintf("https://webmail.%s/oauth/authorized/", domain))
	ViperSetDefault("auth_provider_x509_cert_url", "https://www.googleapis.com/oauth2/v1/certs")

	apiClient, err := NewAPIClient("", "", "", "", "", nil)
	if err != nil {
		return nil, Fatal(err)
	}

	for _, key := range []string{"client_id", "client_secret", "api_key"} {
		if ViperGetString(key) == "" {
			return nil, Fatalf("missing config value: '%s'", key)
		}
	}

	h := Handler{
		verbose:  ViperGetBool("verbose"),
		shutdown: make(chan struct{}, 1),
		Domain:   domain,
		client:   apiClient,
		apiKey:   ViperGetString("api_key"),
	}

	err = h.ReadFlows()
	if err != nil {
		return nil, Fatal(err)
	}

	err = h.ReadTokens()
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
	Local string `json:"local"`
	Gmail string `json:"gmail"`
}

type AuthenticateResponse struct {
	Response
	URI string
}

type AuthorizeRequest struct {
	State string `json:"state"`
}

type AuthorizedResponse struct {
	Response
	Text []string
}

type TokenResponse struct {
	Local string
	Gmail string
	Token string
}

func (h *Handler) ReadFlows() error {
	flows, err := ReadFlowMap()
	if err != nil {
		return Fatal(err)
	}
	h.Flows = flows
	log.Printf("read in %d flows\n", len(h.Flows))
	if h.verbose {
		log.Println(FormatJSON(h.Flows))
	}
	return nil
}

func (h *Handler) ExpireFlows() error {
	expired := make(map[string]*Flow)
	for id, flow := range h.Flows {
		if flow.IsExpired() {
			expired[id] = flow
		}
	}
	for id, flow := range expired {
		err := DeleteFlow(flow)
		if err != nil {
			return Fatal(err)
		}
		delete(h.Flows, id)
	}
	return nil
}

func (h *Handler) WriteFlows() error {
	log.Printf("writing out %d flows\n", len(h.Flows))
	if h.verbose {
		log.Println(FormatJSON(h.Flows))
	}
	err := WriteFlowMap(h.Flows)
	if err != nil {
		return Fatal(err)
	}
	return nil
}

func (h *Handler) ReadTokens() error {
	tokens, err := ReadTokenMap()
	if err != nil {
		return Fatal(err)
	}
	h.Tokens = tokens
	log.Printf("read in %d tokens\n", len(h.Tokens))
	if h.verbose {
		LogTokens(h.Tokens)
	}
	return nil
}

func (h *Handler) WriteTokens() error {
	log.Printf("writing out %d tokens\n", len(h.Tokens))
	if h.verbose {
		LogTokens(h.Tokens)
	}
	err := WriteTokenMap(h.Tokens)
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
	log.Printf("<--response [%d] %s\n", status, message)
	if h.verbose && result != nil {
		log.Printf("response body: %s\n", FormatJSON(result))
	}
}

func (h *Handler) validateRequest(w http.ResponseWriter, r *http.Request, request interface{}) (string, map[string]string, bool) {
	// FIXME: require request remote IP address present in iplsd client whitelist
	endpoint := r.URL.Path
	log.Printf("request--> %s %s %s %s %s\n", r.RemoteAddr, r.Header.Get("X-Real-IP"), r.Proto, r.Method, endpoint)
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
			log.Printf("raw request body: %s\n", string(bodyData))
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

func (h *Handler) validateLocalAddress(w http.ResponseWriter, endpoint, local string) bool {

	if local == "" {
		h.fail(w, endpoint, "missing username", http.StatusBadRequest)
		return false
	}

	if !strings.HasPrefix(local, "gmail.") {
		h.fail(w, endpoint, fmt.Sprintf("username %s missing 'gmail.' prefix", local), http.StatusBadRequest)
		return false
	}

	if !strings.HasSuffix(local, "@"+h.Domain) {
		h.fail(w, endpoint, fmt.Sprintf("username %s domain mismatch", local), http.StatusBadRequest)
		return false
	}

	_, ok := h.Usernames[local]
	if !ok {
		h.fail(w, endpoint, fmt.Sprintf("username %s is unknown", local), http.StatusNotFound)
		return false
	}

	return true
}

func (h *Handler) handleAuthenticateRequest(w http.ResponseWriter, r *http.Request) {
	var request AuthenticateRequest
	endpoint, _, ok := h.validateRequest(w, r, &request)
	if !ok {
		return
	}

	if !h.validateLocalAddress(w, endpoint, request.Local) {
		return
	}

	flow, err := h.NewFlow(request.Local)
	if err != nil {
		h.failInternal(w, endpoint, Fatal(err))
		return
	}

	params := map[string]string{}
	params["scopes"] = strings.Join(ViperGetStringSlice("scopes"), " ")
	params["access_type"] = "offline"
	params["include_granted_scopes"] = "true"
	params["response_type"] = "code"
	params["state"] = flow.Id
	params["redirect_uri"] = ViperGetString("authenticated_redirect_uri")
	params["client_id"] = ViperGetString("client_id")
	params["prompt"] = "select_account consent"

	authURI, err := h.buildURI(ViperGetString("auth_uri"), params)
	if err != nil {
		h.failInternal(w, endpoint, Fatal(err))
		return
	}

	// respond with the OAUTH2 auth URI
	var response AuthenticateResponse
	response.Success = true
	response.User = request.Local
	response.Request = endpoint
	response.Message = "generated authenticate URI"
	response.URI = authURI.String()
	h.succeed(w, response.Message, &response)
}

func (h *Handler) handleDeauthenticateRequest(w http.ResponseWriter, r *http.Request) {
	var request AuthenticateRequest
	endpoint, _, ok := h.validateRequest(w, r, &request)
	if !ok {
		return
	}

	if !h.validateLocalAddress(w, endpoint, request.Local) {
		return
	}

	deauthTokens := make(map[string]*Token)
	var found bool
	for id, token := range h.Tokens {
		if token.LocalAddress == request.Local {
			deauthTokens[id] = token
			found = true
		}
	}

	if !found {
		h.fail(w, endpoint, fmt.Sprintf("no token found for: %s", request.Local), http.StatusNotFound)
		return
	}

	for id, token := range deauthTokens {
		delete(h.Tokens, id)
		err := DeleteToken(token)
		if err != nil {
			h.failInternal(w, endpoint, Fatal(err))
			return
		}
	}
	h.Usernames[request.Local] = ""

	var response Response
	response.Success = true
	response.User = request.Local
	response.Request = endpoint
	response.Message = fmt.Sprintf("removed gmail authorization for %s", request.Local)
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

	// store the code in the Flow for a later call from the frontend with this state
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
	log.Printf("redirecting to frontend with query params: %s\n", FormatJSON(relayParams))
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
	// We could send a GET request to google now, but we redirect so the frontend
	// can call us back to make the GET request and display the edited result
}

func (h *Handler) handleAuthorizeRequest(w http.ResponseWriter, r *http.Request) {
	var request AuthorizeRequest
	endpoint, _, ok := h.validateRequest(w, r, &request)
	if !ok {
		return
	}
	flow, ok := h.Flows[request.State]
	if !ok {
		fmt.Printf("%s: unknown OAUTH flow: state=%s\n", endpoint, request.State)
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

	//log.Printf("responseData: %s\n", FormatJSON(responseData))

	token, err := NewToken(flow.LocalAddress, responseData)
	if err != nil {
		h.failInternal(w, endpoint, Fatal(err))
		return
	}

	h.Tokens[token.Id] = token
	h.Usernames[flow.LocalAddress] = token.GmailAddress

	var response AuthorizedResponse
	response.Success = true
	response.User = flow.LocalAddress
	response.Request = endpoint
	response.Message = "authorization token received"
	response.Text = []string{
		fmt.Sprintf("incoming gmail to %s will be fetched into local %s inbox", token.GmailAddress, token.LocalAddress),
		fmt.Sprintf("mail sent from local %s will be routed via gmail from %s", token.LocalAddress, token.GmailAddress),
	}
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
	flow, err := NewFlow(address)
	if err != nil {
		return nil, Fatal(err)
	}
	h.Flows[flow.Id] = flow
	return flow, nil
}

func (h *Handler) handleUsernamesRequest(w http.ResponseWriter, r *http.Request) {
	endpoint, _, ok := h.validateRequest(w, r, nil)
	if !ok {
		return
	}
	h.succeed(w, endpoint, &h.Usernames)
}

func (h *Handler) handleGetToken(w http.ResponseWriter, r *http.Request) {
	// FIXME: require X-Api-Key header
	// FIXME: require valid client certificate
	endpoint, _, ok := h.validateRequest(w, r, nil)
	if !ok {
		return
	}
	address := r.PathValue("address")

	_, ok = h.Usernames[address]
	if !ok {
		domainAddress := address + "@" + h.Domain
		_, ok = h.Usernames[domainAddress]
		if !ok {
			h.fail(w, endpoint, fmt.Sprintf("unknown username: %s", address), http.StatusNotFound)
			return
		}
		address = domainAddress
	}

	var token *Token
	for _, t := range h.Tokens {
		if t.LocalAddress == address {
			token = t
			break
		}
	}
	if token == nil {
		h.fail(w, endpoint, fmt.Sprintf("no token found for: %s", address), http.StatusNotFound)
		return
	}

	if token.IsAccessTokenExpired() {

		requestHeader := map[string]string{
			"Content-Type":                     "application/json",
			"Access-Control-Allow-Origin":      "https://webmail.mailcapsule.io",
			"Access-Control-Allow-Methods":     "GET, POST, OPTIONS",
			"Access-Control-Allow-Credentials": "true",
		}

		requestData := map[string]string{
			"client_id":     ViperGetString("client_id"),
			"client_secret": ViperGetString("client_secret"),
			"grant_type":    "refresh_token",
			"refresh_token": token.RefreshToken,
		}

		var responseData map[string]any
		_, err := h.client.Post(ViperGetString("token_uri"), &requestData, &responseData, &requestHeader)
		if err != nil {
			h.failInternal(w, endpoint, Fatal(err))
			return
		}

		//log.Printf("refresh response: %s\n", FormatJSON(responseData))

		err = token.ParseResponse(responseData)
		if err != nil {
			h.failInternal(w, endpoint, Fatal(err))
			return
		}

		err = WriteToken(token)
		if err != nil {
			h.failInternal(w, endpoint, Fatal(err))
			return
		}

	}

	h.succeed(w, "access_token", &TokenResponse{Local: token.LocalAddress, Gmail: token.GmailAddress, Token: token.AccessToken})
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
	http.HandleFunc("GET /oauth/usernames/", h.handleUsernamesRequest)
	http.HandleFunc("GET /oauth/token/{address}/", h.handleGetToken)

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

	err = h.WriteTokens()
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

	ViperSetDefault("usernames", defaultUsers)
	h.Usernames = make(map[string]string)
	for _, username := range ViperGetStringSlice("usernames") {
		address := username + "@" + h.Domain
		h.Usernames[address] = h.authorizedGmailAddress(address)
	}

	if h.verbose {
		log.Printf("usernames: %s\n", FormatJSON(h.Usernames))
	}

	return nil
}

func (h *Handler) authorizedGmailAddress(address string) string {
	for _, token := range h.Tokens {
		if token.LocalAddress == address {
			return token.GmailAddress
		}
	}
	return ""
}
