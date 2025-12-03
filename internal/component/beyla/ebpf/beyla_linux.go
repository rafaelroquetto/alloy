//go:build (linux && arm64) || (linux && amd64)

package beyla

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/common/model"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"golang.org/x/sync/errgroup" //nolint:depguard

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/discovery"
	"github.com/grafana/alloy/internal/featuregate"
	"github.com/grafana/alloy/internal/runtime/logging/level"
	http_service "github.com/grafana/alloy/internal/service/http"
)

func init() {
	component.Register(component.Registration{
		Name:      "beyla.ebpf",
		Stability: featuregate.StabilityGenerallyAvailable,
		Args:      Arguments{},
		Exports:   Exports{},

		Build: func(opts component.Options, args component.Arguments) (component.Component, error) {
			return New(opts, args.(Arguments))
		},
	})
}

type Component struct {
	opts       component.Options
	mut        sync.Mutex
	args       Arguments
	argsUpdate chan Arguments

	// Subprocess-specific fields
	subprocessPort int       // Port where Beyla subprocess listens
	subprocessAddr string    // Full address (http://localhost:PORT)
	subprocessCmd  *exec.Cmd // The running subprocess
	beylaExePath   string    // Path to extracted Beyla binary
	configPath     string    // Path to config file
	cleanupFuncs   []func()  // Cleanup functions for temp files

	// OTLP receiver for traces (when Output is configured)
	otlpReceiverPort int         // Port where OTLP receiver listens for traces from Beyla
	otlpServer       *http.Server // HTTP server for OTLP receiver

	// Restart tracking
	restartCount    int
	lastRestartTime time.Time
	restartBackoff  time.Duration

	healthMut sync.RWMutex
	health    component.Health
}

var _ component.HealthComponent = (*Component)(nil)

const (
	SamplerAlwaysOn                = "always_on"
	SamplerAlwaysOff               = "always_off"
	SamplerTraceIDRatio            = "traceidratio"
	SamplerParentBasedAlwaysOn     = "parentbased_always_on"
	SamplerParentBasedAlwaysOff    = "parentbased_always_off"
	SamplerParentBasedTraceIDRatio = "parentbased_traceidratio"
)

func New(opts component.Options, args Arguments) (*Component, error) {
	c := &Component{
		opts:       opts,
		args:       args,
		argsUpdate: make(chan Arguments, 1),
	}

	if err := c.Update(args); err != nil {
		return nil, err
	}
	return c, nil
}

// logDeprecationWarnings logs warnings for deprecated configuration fields
func (c *Component) logDeprecationWarnings() {
	// Deprecated top-level fields
	if c.args.Port != "" {
		level.Warn(c.opts.Logger).Log("msg", "The 'open_port' field is deprecated. Use 'discovery.services' instead.")
	}
	if c.args.ExecutableName != "" {
		level.Warn(c.opts.Logger).Log("msg", "The 'executable_name' field is deprecated. Use 'discovery.services' instead.")
	}

	// Deprecated discovery fields
	if len(c.args.Discovery.Services) > 0 {
		level.Warn(c.opts.Logger).Log("msg", "discovery.services is deprecated, use discovery.instrument instead")
	}
	if len(c.args.Discovery.ExcludeServices) > 0 {
		level.Warn(c.opts.Logger).Log("msg", "discovery.exclude_services is deprecated, use discovery.exclude_instrument instead")
	}
	if len(c.args.Discovery.DefaultExcludeServices) > 0 {
		level.Warn(c.opts.Logger).Log("msg", "discovery.default_exclude_services is deprecated, use discovery.default_exclude_instrument instead")
	}
}

// drainPendingArgsUpdates drains any pending args updates from initialization
// This prevents race conditions where multiple updates arrive before subprocess starts
func (c *Component) drainPendingArgsUpdates() {
	select {
	case latestArgs := <-c.argsUpdate:
		// Get all pending updates
		latestArgs = getLatestArgsFromChannel(c.argsUpdate, latestArgs)
		c.mut.Lock()
		c.args = latestArgs
		c.mut.Unlock()
	default:
		// No pending updates
	}
}

// Run implements component.Component.
func (c *Component) Run(ctx context.Context) error {
	c.logDeprecationWarnings()

	// Initialize restart backoff
	c.mut.Lock()
	c.restartBackoff = 1 * time.Second
	c.mut.Unlock()

	c.drainPendingArgsUpdates()

	var cancel context.CancelFunc
	var cancelG *errgroup.Group
	restartTimer := time.NewTimer(0) // Start immediately
	defer restartTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			if cancel != nil {
				cancel()
			}
			return nil

		case newArgs := <-c.argsUpdate:
			c.handleArgsUpdate(newArgs, cancel, cancelG, restartTimer)

		case <-restartTimer.C:
			var err error
			cancel, cancelG, err = c.handleSubprocessStart(ctx, cancel, cancelG, restartTimer)
			if err != nil {
				continue
			}
		}
	}
}

// scheduleRestart schedules a subprocess restart with exponential backoff
func (c *Component) scheduleRestart(timer *time.Timer) {
	c.mut.Lock()
	defer c.mut.Unlock()

	// Exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s (max)
	backoff := c.restartBackoff
	c.restartBackoff = c.restartBackoff * 2
	if c.restartBackoff > 30*time.Second {
		c.restartBackoff = 30 * time.Second
	}

	level.Info(c.opts.Logger).Log("msg", "scheduling subprocess restart", "backoff", backoff, "restart_count", c.restartCount)
	timer.Reset(backoff)
}

// handleArgsUpdate handles configuration updates
func (c *Component) handleArgsUpdate(newArgs Arguments, cancel context.CancelFunc, cancelG *errgroup.Group, restartTimer *time.Timer) {
	newArgs = getLatestArgsFromChannel(c.argsUpdate, newArgs)
	c.args = newArgs

	if cancel != nil {
		// cancel any previously running Beyla subprocess
		cancel()
		level.Info(c.opts.Logger).Log("msg", "waiting for Beyla subprocess to terminate")
		if err := cancelG.Wait(); err != nil {
			level.Error(c.opts.Logger).Log("msg", "Beyla subprocess terminated with error", "err", err)
			c.reportUnhealthy(err)
		}
		// Cleanup previous temp files
		c.cleanup()
	}

	// Reset restart tracking on config change
	c.mut.Lock()
	c.restartCount = 0
	c.restartBackoff = 1 * time.Second
	c.mut.Unlock()

	// Trigger immediate restart with new config
	restartTimer.Reset(0)
}

// handleSubprocessStart starts or restarts the Beyla subprocess
func (c *Component) handleSubprocessStart(ctx context.Context, cancel context.CancelFunc, cancelG *errgroup.Group, restartTimer *time.Timer) (context.CancelFunc, *errgroup.Group, error) {
	// Stop previous subprocess if running
	if cancel != nil {
		cancel()
		level.Info(c.opts.Logger).Log("msg", "waiting for Beyla subprocess to terminate before restart")
		if err := cancelG.Wait(); err != nil {
			level.Error(c.opts.Logger).Log("msg", "Beyla subprocess terminated with error", "err", err)
		}
		c.cleanup()
	}

	// Log start/restart
	c.mut.Lock()
	restartCount := c.restartCount
	c.restartCount++
	c.lastRestartTime = time.Now()
	c.mut.Unlock()

	if restartCount > 0 {
		level.Info(c.opts.Logger).Log("msg", "restarting Beyla subprocess", "restart_count", restartCount)
	} else {
		level.Info(c.opts.Logger).Log("msg", "starting Beyla subprocess")
	}

	// Create new context for subprocess
	newCtx, cancelFunc := context.WithCancel(ctx)

	// Setup subprocess: extract binary, start OTLP receiver, allocate port, write config
	if err := c.setupSubprocess(restartTimer); err != nil {
		cancelFunc()
		return cancel, cancelG, err
	}

	// Start subprocess and health checker
	g, launchCtx := errgroup.WithContext(newCtx)

	g.Go(func() error {
		return c.runSubprocess(launchCtx)
	})

	g.Go(func() error {
		return c.healthCheckLoop(launchCtx)
	})

	// Monitor subprocess in background
	go func() {
		err := g.Wait()
		// Only restart if context is not cancelled (not a graceful shutdown)
		if ctx.Err() == nil && err != nil {
			level.Error(c.opts.Logger).Log("msg", "Beyla subprocess crashed, scheduling restart", "err", err)
			c.reportUnhealthy(err)
			c.scheduleRestart(restartTimer)
		}
	}()

	return cancelFunc, g, nil
}

// setupSubprocess prepares the subprocess environment (extract binary, start OTLP, allocate port, write config)
func (c *Component) setupSubprocess(restartTimer *time.Timer) error {
	// Extract embedded Beyla binary
	exePath, cleanupBinary, err := c.extractBeylaExecutable()
	if err != nil {
		level.Error(c.opts.Logger).Log("msg", "failed to extract Beyla binary", "err", err)
		c.reportUnhealthy(err)
		c.scheduleRestart(restartTimer)
		return err
	}

	c.mut.Lock()
	c.beylaExePath = exePath
	c.cleanupFuncs = append(c.cleanupFuncs, cleanupBinary)
	c.mut.Unlock()

	// Start OTLP receiver if trace output is configured
	if err := c.startOTLPReceiver(); err != nil {
		level.Error(c.opts.Logger).Log("msg", "failed to start OTLP receiver", "err", err)
		c.reportUnhealthy(err)
		c.cleanup()
		c.scheduleRestart(restartTimer)
		return err
	}

	// Allocate port for subprocess
	port, err := findFreePort()
	if err != nil {
		level.Error(c.opts.Logger).Log("msg", "failed to allocate port", "err", err)
		c.reportUnhealthy(err)
		c.cleanup()
		c.scheduleRestart(restartTimer)
		return err
	}

	c.mut.Lock()
	c.subprocessPort = port
	c.subprocessAddr = fmt.Sprintf("http://localhost:%d", port)
	c.mut.Unlock()

	// Write config to temporary file
	configPath, cleanupConfig, err := c.writeConfigFile()
	if err != nil {
		level.Error(c.opts.Logger).Log("msg", "failed to write config", "err", err)
		c.reportUnhealthy(err)
		c.cleanup()
		c.scheduleRestart(restartTimer)
		return err
	}

	c.mut.Lock()
	c.configPath = configPath
	c.cleanupFuncs = append(c.cleanupFuncs, cleanupConfig)
	c.mut.Unlock()

	return nil
}

func getLatestArgsFromChannel[A any](ch chan A, current A) A {
	for {
		select {
		case x := <-ch:
			current = x
		default:
			return current
		}
	}
}

// Update implements component.Component.
func (c *Component) Update(args component.Arguments) error {
	c.mut.Lock()
	defer c.mut.Unlock()
	baseTarget, err := c.baseTarget()
	if err != nil {
		return err
	}
	c.opts.OnStateChange(Exports{
		Targets: []discovery.Target{baseTarget},
	})

	newArgs := args.(Arguments)
	c.argsUpdate <- newArgs
	return nil
}

// baseTarget returns the base target for the component which includes metrics of the instrumented services.
func (c *Component) baseTarget() (discovery.Target, error) {
	data, err := c.opts.GetServiceData(http_service.ServiceName)
	if err != nil {
		return discovery.EmptyTarget, fmt.Errorf("failed to get HTTP information: %w", err)
	}
	httpData := data.(http_service.Data)

	return discovery.NewTargetFromMap(map[string]string{
		model.AddressLabel:     httpData.MemoryListenAddr,
		model.SchemeLabel:      "http",
		model.MetricsPathLabel: path.Join(httpData.HTTPPathForComponent(c.opts.ID), "metrics"),
		"instance":             defaultInstance(),
		"job":                  "beyla",
	}), nil
}

func (c *Component) reportUnhealthy(err error) {
	c.healthMut.Lock()
	defer c.healthMut.Unlock()
	c.health = component.Health{
		Health:     component.HealthTypeUnhealthy,
		Message:    err.Error(),
		UpdateTime: time.Now(),
	}
}

func (c *Component) reportHealthy() {
	c.healthMut.Lock()
	defer c.healthMut.Unlock()
	c.health = component.Health{
		Health:     component.HealthTypeHealthy,
		UpdateTime: time.Now(),
	}
}

func (c *Component) CurrentHealth() component.Health {
	c.healthMut.RLock()
	defer c.healthMut.RUnlock()
	return c.health
}

func (c *Component) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mut.Lock()
		addr := c.subprocessAddr
		c.mut.Unlock()

		if addr == "" {
			http.Error(w, "Beyla subprocess not started", http.StatusServiceUnavailable)
			return
		}

		// Build proxy URL
		target, err := url.Parse(addr)
		if err != nil {
			level.Error(c.opts.Logger).Log("msg", "failed to parse subprocess URL", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Create reverse proxy
		proxy := httputil.NewSingleHostReverseProxy(target)

		// Add error handler
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			level.Error(c.opts.Logger).Log("msg", "proxy error", "err", err)
			http.Error(w, "subprocess unavailable", http.StatusBadGateway)
		}

		proxy.ServeHTTP(w, r)
	})
}

func defaultInstance() string {
	hostname := os.Getenv("HOSTNAME")
	if hostname != "" {
		return hostname
	}

	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// cleanup runs all cleanup functions
func (c *Component) cleanup() {
	// Stop OTLP receiver first (doesn't need lock)
	c.stopOTLPReceiver()

	c.mut.Lock()
	defer c.mut.Unlock()

	for _, cleanupFunc := range c.cleanupFuncs {
		cleanupFunc()
	}
	c.cleanupFuncs = nil
	c.beylaExePath = ""
	c.configPath = ""
	c.otlpReceiverPort = 0
}

// extractBeylaExecutable extracts the embedded Beyla binary to a temporary location
func (c *Component) extractBeylaExecutable() (string, func(), error) {
	tmpDir, err := os.MkdirTemp("", "alloy-beyla-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	if err := os.Chmod(tmpDir, 0700); err != nil {
		os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("failed to set directory permissions: %w", err)
	}

	binPath := filepath.Join(tmpDir, "beyla")

	if err := os.WriteFile(binPath, beylaEmbeddedBinary, 0755); err != nil {
		os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("failed to write binary: %w", err)
	}

	level.Debug(c.opts.Logger).Log("msg", "extracted Beyla binary", "path", binPath, "size", len(beylaEmbeddedBinary))

	cleanup := func() {
		level.Debug(c.opts.Logger).Log("msg", "cleaning up Beyla binary", "path", binPath)
		os.RemoveAll(tmpDir)
	}

	return binPath, cleanup, nil
}

// findFreePort finds an available TCP port
func findFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

// runSubprocess starts and manages the Beyla subprocess using the extracted binary
func (c *Component) runSubprocess(ctx context.Context) error {
	c.mut.Lock()
	exePath := c.beylaExePath
	configPath := c.configPath
	port := c.subprocessPort
	c.mut.Unlock()

	if exePath == "" {
		return fmt.Errorf("Beyla executable path not set")
	}

	if configPath == "" {
		return fmt.Errorf("config path not set")
	}

	// Build command using extracted binary
	cmd := exec.CommandContext(ctx, exePath,
		"-config", configPath,
	)

	// Ensure Beyla subprocess gets killed when Alloy dies (even with SIGKILL)
	// PR_SET_PDEATHSIG sends SIGKILL to child when parent terminates
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
	}

	// Redirect logs to Alloy's logger
	cmd.Stdout = &logWriter{logger: c.opts.Logger, level: "info"}
	cmd.Stderr = &logWriter{logger: c.opts.Logger, level: "error"}

	// Set working directory to temp dir
	cmd.Dir = filepath.Dir(exePath)

	c.mut.Lock()
	c.subprocessCmd = cmd
	c.mut.Unlock()

	level.Info(c.opts.Logger).Log(
		"msg", "starting Beyla subprocess",
		"binary", exePath,
		"port", port,
		"config", configPath,
	)

	if err := cmd.Start(); err != nil {
		level.Error(c.opts.Logger).Log("msg", "failed to start Beyla subprocess", "err", err)
		c.reportUnhealthy(err)
		return fmt.Errorf("failed to start subprocess: %w", err)
	}

	level.Info(c.opts.Logger).Log(
		"msg", "Beyla subprocess started",
		"pid", cmd.Process.Pid,
		"binary_size", len(beylaEmbeddedBinary),
	)

	// Wait for subprocess to exit
	err := cmd.Wait()

	if err != nil && ctx.Err() == nil {
		// Subprocess exited unexpectedly (not due to context cancellation)
		level.Error(c.opts.Logger).Log("msg", "Beyla subprocess exited unexpectedly", "err", err)
		c.reportUnhealthy(err)
		return err
	}

	level.Info(c.opts.Logger).Log("msg", "Beyla subprocess stopped")
	return nil
}

// healthCheckLoop periodically checks if the subprocess is healthy
func (c *Component) healthCheckLoop(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Initial wait for subprocess to start
	time.Sleep(2 * time.Second)

	consecutiveSuccesses := 0
	const successesNeededToResetBackoff = 3

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := c.checkSubprocessHealth(); err != nil {
				level.Warn(c.opts.Logger).Log("msg", "subprocess health check failed", "err", err)
				c.reportUnhealthy(err)
				consecutiveSuccesses = 0
			} else {
				c.reportHealthy()
				consecutiveSuccesses++

				// Reset backoff after successful health checks
				if consecutiveSuccesses >= successesNeededToResetBackoff {
					c.mut.Lock()
					if c.restartBackoff > 1*time.Second {
						level.Debug(c.opts.Logger).Log("msg", "resetting restart backoff after successful health checks")
						c.restartBackoff = 1 * time.Second
						c.restartCount = 0
					}
					c.mut.Unlock()
					consecutiveSuccesses = 0 // Reset counter
				}
			}
		}
	}
}

// checkSubprocessHealth checks if the subprocess is responding
func (c *Component) checkSubprocessHealth() error {
	c.mut.Lock()
	addr := c.subprocessAddr
	c.mut.Unlock()

	if addr == "" {
		return fmt.Errorf("subprocess not started")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", addr+"/metrics", nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("subprocess not responding: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("subprocess returned status %d", resp.StatusCode)
	}

	return nil
}

// logWriter adapts io.Writer to Alloy's logger
type logWriter struct {
	logger log.Logger
	level  string
}

func (w *logWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSuffix(string(p), "\n")
	if w.level == "error" {
		level.Error(w.logger).Log("msg", msg, "source", "beyla-subprocess")
	} else {
		level.Info(w.logger).Log("msg", msg, "source", "beyla-subprocess")
	}
	return len(p), nil
}

// startOTLPReceiver starts an HTTP server to receive OTLP traces from Beyla subprocess
// and forwards them to the configured Output consumer
func (c *Component) startOTLPReceiver() error {
	if c.args.Output == nil || len(c.args.Output.Traces) == 0 {
		// No trace output configured, skip OTLP receiver
		return nil
	}

	// Allocate port for OTLP receiver
	port, err := findFreePort()
	if err != nil {
		return fmt.Errorf("failed to allocate OTLP receiver port: %w", err)
	}

	c.mut.Lock()
	c.otlpReceiverPort = port
	c.mut.Unlock()

	level.Info(c.opts.Logger).Log("msg", "starting OTLP receiver for traces", "port", port)

	// Create HTTP handler for OTLP traces
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/traces", c.handleOTLPTraces)

	server := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Handler: mux,
	}

	c.mut.Lock()
	c.otlpServer = server
	c.mut.Unlock()

	// Start server in background
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			level.Error(c.opts.Logger).Log("msg", "OTLP receiver server error", "err", err)
		}
	}()

	return nil
}

// stopOTLPReceiver stops the OTLP receiver server
func (c *Component) stopOTLPReceiver() {
	c.mut.Lock()
	server := c.otlpServer
	c.otlpServer = nil
	c.mut.Unlock()

	if server != nil {
		level.Debug(c.opts.Logger).Log("msg", "stopping OTLP receiver")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			level.Warn(c.opts.Logger).Log("msg", "error shutting down OTLP receiver", "err", err)
		}
	}
}

// handleOTLPTraces handles incoming OTLP/HTTP trace requests from Beyla
func (c *Component) handleOTLPTraces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		level.Error(c.opts.Logger).Log("msg", "failed to read OTLP request body", "err", err)
		http.Error(w, "failed to read request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse OTLP request
	req := ptraceotlp.NewExportRequest()

	// Determine content type and unmarshal accordingly
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		err = req.UnmarshalJSON(body)
	} else {
		// Default to protobuf
		err = req.UnmarshalProto(body)
	}

	if err != nil {
		level.Error(c.opts.Logger).Log("msg", "failed to unmarshal OTLP traces", "err", err)
		http.Error(w, "failed to parse OTLP request", http.StatusBadRequest)
		return
	}

	// Get traces from request
	traces := req.Traces()

	// Forward to all configured trace consumers
	c.mut.Lock()
	consumers := c.args.Output.Traces
	c.mut.Unlock()

	// Send to each consumer
	for _, consumer := range consumers {
		if err := consumer.ConsumeTraces(r.Context(), traces); err != nil {
			level.Error(c.opts.Logger).Log("msg", "failed to forward traces to consumer", "err", err)
			http.Error(w, "failed to process traces", http.StatusInternalServerError)
			return
		}
	}

	// Send success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// OTLP spec requires empty JSON object on success
	w.Write([]byte("{}"))
}
