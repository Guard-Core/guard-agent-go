package guardagent

import "log"

// Error hook stages passed as the first argument to Config.OnError,
// matching the Python agent's on_error stage names exactly.
const (
	// StageTransportSend fires when a batch send ultimately fails: retry
	// attempts exhausted, a 413 that persists even as a singleton, or a
	// permanent 4xx rejection that durably drops the batch.
	StageTransportSend = "transport_send"
	// StageEncryption fires when batch serialization or AES-GCM encryption
	// fails on the encrypted-ingest path.
	StageEncryption = "encryption"
	// StageFlushEvents fires when an events flush cycle fails and the
	// batch is requeued.
	StageFlushEvents = "flush_events"
	// StageFlushMetrics fires when a metrics flush cycle fails and the
	// batch is requeued.
	StageFlushMetrics = "flush_metrics"
)

// fireErrorHook invokes the user's on_error callback, if any, without ever
// letting it take the agent down: a panicking hook is recovered and logged,
// mirroring guard_agent.utils.fire_error_hook. Best effort by contract.
func fireErrorHook(
	hook func(stage string, err error, context map[string]any),
	logger *log.Logger,
	stage string,
	err error,
	context map[string]any,
) {
	if hook == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			logger.Printf("guardagent: on_error hook raised while handling '%s': %v", stage, r)
		}
	}()
	hook(stage, err, context)
}
