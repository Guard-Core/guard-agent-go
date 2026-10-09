// Command demo_app serves the Guard Agent demo container: a small stdlib
// HTTP server that starts guard-agent-go, ships one test event on boot, and
// exposes the agent lifecycle over three routes (/ : service info, /health :
// agent status, POST /events : emit a test event). It mirrors the Python
// agent's examples/demo_app.
//
// Set GUARD_AGENT_API_KEY (required by the ingestion API), and optionally
// GUARD_AGENT_ENDPOINT, GUARD_AGENT_PROJECT_ID, GUARD_AGENT_SIGNING_SECRET,
// and PORT before running.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	guardagent "github.com/rennf93/guard-agent-go/v3"
)

const demoEventType = "custom_request_check"

type demoServer struct {
	agent     *guardagent.Agent
	endpoint  string
	projectID string
}

func buildTestEvent() guardagent.SecurityEvent {
	return guardagent.SecurityEvent{
		Timestamp:   time.Now().UTC(),
		EventType:   demoEventType,
		IPAddress:   "192.168.1.100",
		ActionTaken: "logged",
		Reason:      "Guard Agent demo container test event",
		Endpoint:    "/demo/test-event",
		Method:      "POST",
		Metadata:    map[string]any{"source": "guard-agent-demo-container"},
	}
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *demoServer) handleRoot(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"service":   "guard-agent-demo",
		"endpoint":  s.endpoint,
		"projectID": s.projectID,
	})
}

func (s *demoServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": s.agent.Status().State})
}

func (s *demoServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	event := buildTestEvent()
	// SendEvent never blocks on delivery: the agent buffers and flushes.
	if err := s.agent.SendEvent(r.Context(), event); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"emitted": event.EventType})
}

func main() {
	logger := log.New(os.Stderr, "guard-agent-demo ", log.LstdFlags)

	endpoint := envOr("GUARD_AGENT_ENDPOINT", "https://api.guard-core.com")
	projectID := envOr("GUARD_AGENT_PROJECT_ID", "demo-project")

	agent, err := guardagent.New(guardagent.Config{
		APIKey:         envOr("GUARD_AGENT_API_KEY", "demo-api-key-12345"),
		Endpoint:       endpoint,
		ProjectID:      projectID,
		SigningSecret:  os.Getenv("GUARD_AGENT_SIGNING_SECRET"),
		BufferSize:     10,
		FlushInterval:  5 * time.Second,
		GuardVersion:   "demo",
		GuardCoreVersion: "4.3.2",
	})
	if err != nil {
		logger.Fatalf("agent: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := agent.Start(ctx); err != nil {
		logger.Fatalf("start: %v", err)
	}

	server := &demoServer{agent: agent, endpoint: endpoint, projectID: projectID}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", server.handleRoot)
	mux.HandleFunc("GET /health", server.handleHealth)
	mux.HandleFunc("/events", server.handleEvents)

	addr := "0.0.0.0:" + envOr("PORT", "8080")
	httpServer := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	// Boot-time test event, like the Python demo's lifespan startup.
	if err := agent.SendEvent(ctx, buildTestEvent()); err != nil {
		logger.Printf("boot event: %v", err)
	}

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdown); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("http shutdown: %v", err)
		}
		if err := agent.Stop(shutdown); err != nil {
			logger.Printf("agent stop: %v", err)
		}
	}()

	logger.Printf("guard-agent demo listening on %s (endpoint %s, project %s)", addr, endpoint, projectID)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Fatalf("serve: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
