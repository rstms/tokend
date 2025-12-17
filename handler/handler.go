package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
	verbose  bool
	Flows    map[string]*Flow
	shutdown chan struct{}
	server   http.Server
}

func NewHandler() (*Handler, error) {
	h := Handler{
		verbose:  ViperGetBool("verbose"),
		Flows:    make(map[string]*Flow),
		shutdown: make(chan struct{}, 1),
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

	// TODO: check that X-Real-IP is listed in /etc/iplsd/ip
	/*
		sourceIp := r.Header["X-Real-Ip"]
		if len(sourceIp) != 1 || sourceIp[0] != "127.0.0.1" {
			h.fail(w, "system", "rescand", "unauthorized", http.StatusUnauthorized)
			return
		}
	*/

	_, domain, ok := strings.Cut(ViperGetString("mail_domain"), ".")
	if !ok {
		log.Printf("domain config failed: %s\n", domain)
		h.fail(w, "system", "gmail_auth", "configuration failure", 500)
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

	var request AuthenticateRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		h.fail(w, "system", "gmail_auth", fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		return
	}

	localAddress := fmt.Sprintf("%s@%s", request.Username, domain)
	requestString := fmt.Sprintf("authorize %s as %s", localAddress, request.Gmail)

	if !strings.HasPrefix(localAddress, "gmail.") {
		h.fail(w, localAddress, requestString, "local username requires 'gmail.' prefix", http.StatusBadRequest)
		return
	}
	if request.Username == "" {
		h.fail(w, localAddress, requestString, "missing username", http.StatusBadRequest)
		return
	}
	if request.Gmail == "" {
		h.fail(w, localAddress, requestString, "missing gmail address", http.StatusBadRequest)
	}

	log.Printf("localAddress: %s\n", localAddress)
	log.Printf("gmailAddress: %s\n", request.Gmail)
	log.Printf("JWT=%s\n", request.JWT)

	// determine if user is valid
	/*
		var dumpResponse UserDumpResponse
		_, err = filterctl.Get(fmt.Sprintf("/filterctl/dump/%s/", localAddress), &dumpResponse)
		if err != nil {
			h.fail(w, localAddress, requestString, "local account validation failed", 500)
			return
		}
		if dumpResponse.User != localAddress || len(dumpResponse.Password) == 0 {
			h.fail(w, localAddress, requestString, fmt.Sprintf("%s is not a valid address", localAddress), 404)
			return
		}
	*/

	//TODO: upload the JWT to the mailqueue to configure fetchmail

	var response Response
	response.Success = true
	response.Request = requestString
	response.Message = fmt.Sprintf("received gmail credential: %s == %s", localAddress, request.Gmail)
	h.succeed(w, response.Message, &response)
}

func logRequest(label string, request map[string]any) {
	log.Printf("BEGIN %s\n", label)
	for k, v := range request {
		log.Printf("%s: %+v\n", k, v)
	}
	log.Println("END %s\n", label)
}

func (h *Handler) handleAuthorizeRequest(w http.ResponseWriter, r *http.Request) {
	log.Printf("authenticate callback: %+v\n", *r)
	defer r.Body.Close()
	var request map[string]any
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		h.fail(w, "oauth2", "authenticate_callback", fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		return
	}
}

func (h *Handler) handleAuthenticateCallback(w http.ResponseWriter, r *http.Request) {
	log.Printf("authenticate callback: %+v\n", *r)
	defer r.Body.Close()
	var request map[string]any
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		h.fail(w, "oauth2", "authenticate_callback", fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		return
	}
	logRequest("authenticateCallback", request)
	w.WriteHeader(200)
}

func (h *Handler) handleAuthorizeCallback(w http.ResponseWriter, r *http.Request) {
	log.Printf("authorize callback: %+v\n", *r)
	defer r.Body.Close()
	var request map[string]any
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		h.fail(w, "oauth2", "authorize_callback", fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		return
	}
	logRequest("authorize callback", request)
	w.WriteHeader(200)
}

func (h *Handler) NewFlow() (*Flow, error) {
	flow, err := NewFlow()
	if err != nil {
		return nil, Fatal(err)
	}
	h.Flows[flow.Nonce.Text] = flow
	return flow, nil
}

func (h *Handler) handleNonceRequest(w http.ResponseWriter, r *http.Request) {
	log.Printf("get nonce: %+v\n", *r)
	defer r.Body.Close()
	flow, err := h.NewFlow()
	if err != nil {
		fmt.Printf("%v\n", Fatal(err))
		h.fail(w, "tokend", "get nonce", "internal failure", http.StatusInternalServerError)
		return
	}
	_, err = w.Write([]byte(flow.Nonce.Text))
	if err != nil {
		fmt.Printf("%v\n", Fatal(err))
		h.fail(w, "tokend", "write nonce", "internal failure", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(200)
	if h.verbose {
		fmt.Printf("New Flow: %s\n", FormatJSON(flow))
	}
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

	http.HandleFunc("POST /authenticate", h.handleAuthenticateRequest)
	http.HandleFunc("GET /authenticated", h.handleAuthenticateCallback)
	http.HandleFunc("POST /authorize", h.handleAuthorizeRequest)
	http.HandleFunc("GET /authorized", h.handleAuthorizeCallback)
	http.HandleFunc("GET /nonce", h.handleNonceRequest)

	go func() {
		log.Printf("listening for HTTP requests on %s\n", h.server.Addr)
		defer log.Println("exiting HTTP request handler")
		err := h.server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Printf("%s\n", Fatalf("ListenAndServe failed: ", err))
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
