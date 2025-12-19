package handler

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
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

func (h *Handler) fail(w http.ResponseWriter, user, request, message string, status int) {
	log.Printf("  [%d] %s", status, message)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{User: user, Request: request, Success: false, Message: message})
}

func (h *Handler) succeed(w http.ResponseWriter, message string, result interface{}) {
	status := http.StatusOK
	log.Printf("  [%d] %s", status, message)
	if h.verbose {
		dump, err := json.MarshalIndent(result, "", "  ")
		if err != nil {

			log.Fatalln("failure marshalling response:", err)
		}
		log.Println(string(dump))
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) handleAuthenticateRequest(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// FIXME: authenticate request

	// TODO: check that X-Real-IP is listed in /etc/iplsd/ip
	/*
			sourceIp := r.Header["X-Real-Ip"]
			if len(sourceIp) != 1 || sourceIp[0] != "127.0.0.1" {
				h.fail(w, "system", "rescand", "unauthorized", http.StatusUnauthorized)
				return
			}

		var origin string
		if len(r.Header["Origin"]) > 0 {
			origin = r.Header["Origin"][0]
		}
		log.Printf("origin: %s\n", origin)
		expectedOrigin := "https://webmail." + domain
		if origin != expectedOrigin {
			log.Printf("unauthorized origin: expected %s, got %s\n", expectedOrigin, origin)
			h.fail(w, "system", "gmail_auth", "unauthorized", http.StatusUnauthorized)
		}

		log.Printf("RemoteAddr: %s\n", r.RemoteAddr)
		sourceIp, _, ok := strings.Cut(r.RemoteAddr, ":")
		if !ok || sourceIp != "127.0.0.1" {
			h.fail(w, "system", "gmail_auth", "unauthorized", http.StatusUnauthorized)
		}

	*/

	var request AuthenticateRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		h.fail(w, "TOKEN_DAEMON", "authenticate_request", fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		return
	}

	if request.Username == "" {
		h.fail(w, "TOKEN_DAEMON", "authenticate_request", "missing username", http.StatusBadRequest)
		return
	}

	requestString := fmt.Sprintf("authenticate %s", request.Username)

	if !strings.HasPrefix(request.Username, "gmail.") {
		h.fail(w, "TOKEN_DAEMON", requestString, "username requires 'gmail.' prefix", http.StatusBadRequest)
		return
	}

	if !strings.HasSuffix(request.Username, "@"+h.Domain) {
		h.fail(w, "TOKEN_DAEMON", requestString, fmt.Sprintf("domain must be %s", h.Domain), http.StatusBadRequest)
		return
	}

	_, ok := h.Usernames[request.Username]
	if !ok {
		h.fail(w, request.Username, requestString, fmt.Sprintf("unknown username: %s", request.Username), http.StatusNotFound)
		return
	}

	flow, err := h.NewFlow(request.Username)
	if err != nil {
		log.Printf("%v\n", Fatal(err))
		h.fail(w, "TOKEN_DAEMON", "authenticate_request", "server failure", http.StatusInternalServerError)
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
		log.Printf("%v\n", Fatal(err))
		h.fail(w, "TOKEN_DAEMON", "authenticate_request", "server failure", http.StatusInternalServerError)
		return
	}

	// respond with the OAUTH2 auth URI
	var response Response
	response.Success = true
	response.User = request.Username
	response.Request = requestString
	response.Message = authURI.String()
	h.succeed(w, response.Message, &response)
}

func (h *Handler) handleDeauthenticateRequest(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// FIXME: authenticate request

	requestString := "deauthenticate_request"
	var request AuthenticateRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		h.fail(w, "TOKEN_DAEMON", requestString, fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		return
	}

	if request.Username == "" {
		h.fail(w, "TOKEN_DAEMON", requestString, "missing username", http.StatusBadRequest)
		return
	}

	requestString = fmt.Sprintf("deauthenticate %s", request.Username)

	if !strings.HasPrefix(request.Username, "gmail.") {
		h.fail(w, "TOKEN_DAEMON", requestString, "username requires 'gmail.' prefix", http.StatusBadRequest)
		return
	}

	if !strings.HasSuffix(request.Username, "@"+h.Domain) {
		h.fail(w, "TOKEN_DAEMON", requestString, fmt.Sprintf("domain must be %s", h.Domain), http.StatusBadRequest)
		return
	}

	_, ok := h.Usernames[request.Username]
	if !ok {
		h.fail(w, request.Username, requestString, fmt.Sprintf("unknown username: %s", request.Username), http.StatusNotFound)
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
		h.fail(w, "TOKEN_DAEMON", requestString, fmt.Sprintf("no authorization found for: %s", request.Username), http.StatusNotFound)
	}

	delete(h.Flows, deauthState)
	states, err := ListFlowStates()
	if err != nil {
		log.Printf("ListFlowStates failed with:%v\n", Fatal(err))
		h.fail(w, "TOKEN_DAEMON", requestString, "server failure", http.StatusInternalServerError)
		return
	}

	if slices.Contains(states, deauthState) {
		err := DeleteFlow(deauthFlow)
		if err != nil {
			log.Printf("DeleteFlow failed with: %v\n", Fatal(err))
			h.fail(w, "TOKEN_DAEMON", requestString, "server failure", http.StatusInternalServerError)
			return
		}
	}

	var response Response
	response.Success = true
	response.User = request.Username
	response.Request = requestString
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

func logRequest(label string, request map[string]any) {
	log.Printf("BEGIN %s\n", label)
	for k, v := range request {
		log.Printf("%s: %+v\n", k, v)
	}
	log.Printf("END %s\n", label)
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
	// FIXME: authenticate request
	log.Printf("%s /oauth/authenticated/\n", r.Method)
	requestString := "authenticated_callback"
	defer r.Body.Close()
	var authParams map[string]string
	switch r.Method {
	case "POST":
		var request map[string]any
		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			h.fail(w, "TOKEN_DAEMON", requestString, fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		}
		return
		logRequest(requestString, request)
	case "GET":
		authParams = parseQueryParams(r.URL)
		log.Printf("queryParams: %s\n", FormatJSON(authParams))
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
		log.Printf("%v\n", Fatal(err))
		h.fail(w, "TOKEN_DAEMON", requestString, fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

func (h *Handler) handleAuthorizeRequest(w http.ResponseWriter, r *http.Request) {
	// FIXME: authenticate request
	requestString := "authorize_request"
	defer r.Body.Close()
	var request map[string]any
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		h.fail(w, "TOKEN_DAEMON", requestString, fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		return
	}
	logRequest(requestString, request)

	state := request["state"].(string)
	flow, ok := h.Flows[state]
	if !ok {
		fmt.Printf("%s: unknown OAUTH flow: state=%s\n", requestString, state)
		h.fail(w, "TOKEN_DAEMON", requestString, "unauthorized", http.StatusUnauthorized)
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
	_, err = h.client.Post(ViperGetString("token_uri"), &requestData, &responseData, &requestHeader)
	if err != nil {
		log.Printf("%s failed posting access request: %v", requestString, Fatal(err))
		h.fail(w, "TOKEN_DAEMON", requestString, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("responseData: %s\n", FormatJSON(responseData))

	token, err := NewToken(responseData)
	if err != nil {
		log.Printf("%s failed parsing access token data: %v", requestString, Fatal(err))
		h.fail(w, "TOKEN_DAEMON", requestString, "internal error", http.StatusInternalServerError)
		return
	}

	flow.Token = token
	gmailAddress := token.JWT["email"]
	flow.Gmail = gmailAddress
	h.Usernames[flow.Local] = gmailAddress

	var response Response
	response.Success = true
	response.User = flow.Local
	response.Request = requestString
	response.Message = fmt.Sprintf("incoming mail to %s will be fetched to %s and outgoing mail will route via gmail", flow.Gmail, flow.Local)
	h.succeed(w, response.Message, &response)
}

func (h *Handler) handleAuthorizedCallback(w http.ResponseWriter, r *http.Request) {
	// FIXME: authenticate request
	log.Printf("%s /oauth/authorized/\n", r.Method)
	requestString := "authorized_callback"
	var accessParams map[string]string
	switch r.Method {
	case "POST":
		defer r.Body.Close()
		var request map[string]any
		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			h.fail(w, "TOKEN_DAEMON", requestString, fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
			return
		}
	case "GET":
		accessParams = parseQueryParams(r.URL)
		log.Printf("accessParams: %s\n", FormatJSON(accessParams))
	}
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

func (h *Handler) handleNonceRequest(w http.ResponseWriter, r *http.Request) {
	//FIXME: authenticate request
	log.Printf("get nonce: %+v\n", *r)
	defer r.Body.Close()
	flow, err := h.NewFlow("")
	if err != nil {
		log.Printf("%v\n", Fatal(err))
		h.fail(w, "TOKEN_DAEMON", "get nonce", "internal failure", http.StatusInternalServerError)
		return
	}
	_, err = w.Write([]byte(flow.Nonce.Text))
	if err != nil {
		log.Printf("%v\n", Fatal(err))
		h.fail(w, "TOKEN_DAEMON", "write nonce", "internal failure", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(200)
	if h.verbose {
		log.Printf("New Flow: %s\n", FormatJSON(flow))
	}
}

func (h *Handler) handleUsernamesRequest(w http.ResponseWriter, r *http.Request) {
	//FIXME: authenticate request
	h.succeed(w, "usernames", &h.Usernames)
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
	http.HandleFunc("GET /oauth/nonce/", h.handleNonceRequest)
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
