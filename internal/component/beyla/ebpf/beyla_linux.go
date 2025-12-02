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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/common/model"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"golang.org/x/sync/errgroup" //nolint:depguard
	"gopkg.in/yaml.v3"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/discovery"
	"github.com/grafana/alloy/internal/featuregate"
	"github.com/grafana/alloy/internal/runtime/logging/level"
	http_service "github.com/grafana/alloy/internal/service/http"
)

func init() {
	setupBeylaEnvironment()
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

// setupBeylaEnvironment duplicates any BEYLA_ prefixed environment variables with the OTEL_EBPF_ prefix.
// This allows the Beyla subprocess to recognize Beyla-specific environment variables.
func setupBeylaEnvironment() {
	// Note: We no longer override OBI globals since we generate YAML config directly.
	// The Beyla subprocess will handle its own internal configuration from the YAML we provide.
	// Environment variable duplication is handled by Beyla itself when it starts.
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

var validInstrumentations = map[string]struct{}{
	"*": {}, "http": {}, "grpc": {}, "redis": {}, "kafka": {}, "sql": {}, "gpu": {}, "mongo": {},
}

func (args SamplerConfig) Validate() error {
	if args.Name == "" {
		return nil // Empty name is valid, will use default
	}

	validSamplers := map[string]bool{
		SamplerAlwaysOn:                true,
		SamplerAlwaysOff:               true,
		SamplerTraceIDRatio:            true,
		SamplerParentBasedAlwaysOn:     true,
		SamplerParentBasedAlwaysOff:    true,
		SamplerParentBasedTraceIDRatio: true,
	}

	if !validSamplers[args.Name] {
		return fmt.Errorf("invalid sampler name %q. Valid values are: %s, %s, %s, %s, %s, %s", args.Name,
			SamplerAlwaysOn, SamplerAlwaysOff, SamplerTraceIDRatio,
			SamplerParentBasedAlwaysOn, SamplerParentBasedAlwaysOff, SamplerParentBasedTraceIDRatio)
	}

	// Validate arg for ratio-based samplers
	if args.Name == SamplerTraceIDRatio || args.Name == SamplerParentBasedTraceIDRatio {
		if args.Arg == "" {
			return fmt.Errorf("sampler %q requires an arg parameter with a ratio value between 0 and 1", args.Name)
		}

		ratio, err := strconv.ParseFloat(args.Arg, 64)
		if err != nil {
			return fmt.Errorf("invalid arg %q for sampler %q: must be a valid decimal number", args.Arg, args.Name)
		}

		if ratio < 0 || ratio > 1 {
			return fmt.Errorf("invalid arg %q for sampler %q: ratio must be between 0 and 1 (inclusive)", args.Arg, args.Name)
		}
	}

	return nil
}

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

// Run implements component.Component.
func (c *Component) Run(ctx context.Context) error {
	// Add deprecation warnings at the start of Run
	if c.args.Port != "" {
		level.Warn(c.opts.Logger).Log("msg", "The 'open_port' field is deprecated. Use 'discovery.services' instead.")
	}
	if c.args.ExecutableName != "" {
		level.Warn(c.opts.Logger).Log("msg", "The 'executable_name' field is deprecated. Use 'discovery.services' instead.")
	}

	// Add deprecation warnings for legacy discovery fields
	if len(c.args.Discovery.Services) > 0 {
		level.Warn(c.opts.Logger).Log("msg", "discovery.services is deprecated, use discovery.instrument instead")
	}
	if len(c.args.Discovery.ExcludeServices) > 0 {
		level.Warn(c.opts.Logger).Log("msg", "discovery.exclude_services is deprecated, use discovery.exclude_instrument instead")
	}
	if len(c.args.Discovery.DefaultExcludeServices) > 0 {
		level.Warn(c.opts.Logger).Log("msg", "discovery.default_exclude_services is deprecated, use discovery.default_exclude_instrument instead")
	}

	// Initialize restart backoff
	c.mut.Lock()
	c.restartBackoff = 1 * time.Second
	c.mut.Unlock()

	// Drain any pending args updates from initialization
	// This prevents race conditions where multiple updates arrive before subprocess starts
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

		case <-restartTimer.C:
			// Start or restart subprocess
			if cancel != nil {
				// This is a restart - wait for previous subprocess to stop
				cancel()
				level.Info(c.opts.Logger).Log("msg", "waiting for Beyla subprocess to terminate before restart")
				if err := cancelG.Wait(); err != nil {
					level.Error(c.opts.Logger).Log("msg", "Beyla subprocess terminated with error", "err", err)
				}
				c.cleanup()
			}

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

			newCtx, cancelFunc := context.WithCancel(ctx)
			cancel = cancelFunc

			// Extract embedded Beyla binary
			exePath, cleanupBinary, err := c.extractBeylaExecutable()
			if err != nil {
				level.Error(c.opts.Logger).Log("msg", "failed to extract Beyla binary", "err", err)
				c.reportUnhealthy(err)
				c.scheduleRestart(restartTimer)
				continue
			}

			c.mut.Lock()
			c.beylaExePath = exePath
			c.cleanupFuncs = append(c.cleanupFuncs, cleanupBinary)
			c.mut.Unlock()

			// Start OTLP receiver if trace output is configured
			if err := c.startOTLPReceiver(newCtx); err != nil {
				level.Error(c.opts.Logger).Log("msg", "failed to start OTLP receiver", "err", err)
				c.reportUnhealthy(err)
				c.cleanup()
				c.scheduleRestart(restartTimer)
				continue
			}

			// Allocate port for subprocess
			port, err := findFreePort()
			if err != nil {
				level.Error(c.opts.Logger).Log("msg", "failed to allocate port", "err", err)
				c.reportUnhealthy(err)
				c.cleanup()
				c.scheduleRestart(restartTimer)
				continue
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
				continue
			}

			c.mut.Lock()
			c.configPath = configPath
			c.cleanupFuncs = append(c.cleanupFuncs, cleanupConfig)
			c.mut.Unlock()

			g, launchCtx := errgroup.WithContext(newCtx)
			cancelG = g

			// Start Beyla subprocess
			g.Go(func() error {
				return c.runSubprocess(launchCtx)
			})

			// Start health checker
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

func (args Metrics) hasNetworkFeature() bool {
	for _, feature := range args.Features {
		if feature == "network" {
			return true
		}
	}
	return false
}

func (args Metrics) hasAppFeature() bool {
	for _, feature := range args.Features {
		switch feature {
		case "application", "application_host", "application_span", "application_service_graph",
			"application_process", "application_span_otel", "application_span_sizes":
			return true
		}
	}
	return false
}

func (args Metrics) Validate() error {
	for _, instrumentation := range args.Instrumentations {
		if _, ok := validInstrumentations[instrumentation]; !ok {
			return fmt.Errorf("metrics.instrumentations: invalid value %q", instrumentation)
		}
	}

	validFeatures := map[string]struct{}{
		"application": {}, "application_span": {}, "application_span_otel": {},
		"application_span_sizes": {}, "application_host": {},
		"application_service_graph": {}, "application_process": {},
		"network": {}, "network_inter_zone": {},
	}
	for _, feature := range args.Features {
		if _, ok := validFeatures[feature]; !ok {
			return fmt.Errorf("metrics.features: invalid value %q", feature)
		}
	}
	return nil
}

func (args Services) Validate() error {
	for i, svc := range args {
		// Check if any Kubernetes fields are defined
		hasKubernetes := svc.Kubernetes.Namespace != "" ||
			svc.Kubernetes.PodName != "" ||
			svc.Kubernetes.DeploymentName != "" ||
			svc.Kubernetes.ReplicaSetName != "" ||
			svc.Kubernetes.StatefulSetName != "" ||
			svc.Kubernetes.DaemonSetName != "" ||
			svc.Kubernetes.OwnerName != "" ||
			len(svc.Kubernetes.PodLabels) > 0

		if svc.OpenPorts == "" && svc.Path == "" && !hasKubernetes {
			return fmt.Errorf("discovery.services[%d] must define at least one of: open_ports, exe_path, or kubernetes configuration", i)
		}
	}
	return nil
}

func (args *Arguments) Validate() error {
	hasAppFeature := args.Metrics.hasAppFeature()

	if args.TracePrinter == "" {
		args.TracePrinter = "disabled"
	} else {
		validPrinters := map[string]bool{
			"disabled": true, "counter": true, "text": true, "json": true, "json_indent": true,
		}
		if !validPrinters[args.TracePrinter] {
			return fmt.Errorf("trace_printer: invalid value %q. Valid values are: disabled, counter, text, json, json_indent", args.TracePrinter)
		}
	}

	if err := args.Metrics.Validate(); err != nil {
		return err
	}

	if err := args.Traces.Validate(); err != nil {
		return err
	}

	// If traces block is defined with instrumentations, output section must be defined
	if len(args.Traces.Instrumentations) > 0 || args.Traces.Sampler.Name != "" {
		if args.Output == nil {
			return fmt.Errorf("traces block is defined but output section is missing. When using traces configuration, you must define an output block")
		}
	}

	if hasAppFeature {
		// Check if any discovery method is configured (new or legacy)
		hasAnyDiscovery := len(args.Discovery.Services) > 0 ||
			len(args.Discovery.Survey) > 0 ||
			len(args.Discovery.Instrument) > 0

		if !hasAnyDiscovery {
			return fmt.Errorf("discovery.services, discovery.instrument, or discovery.survey is required when application features are enabled")
		}

		// Validate legacy services field
		if len(args.Discovery.Services) > 0 {
			if err := args.Discovery.Services.Validate(); err != nil {
				return fmt.Errorf("invalid discovery configuration: %s", err.Error())
			}
		}

		// Validate survey field
		if len(args.Discovery.Survey) > 0 {
			if err := args.Discovery.Survey.Validate(); err != nil {
				return fmt.Errorf("invalid survey configuration: %s", err.Error())
			}
		}

		// Validate new instrument field
		if len(args.Discovery.Instrument) > 0 {
			if err := args.Discovery.Instrument.Validate(); err != nil {
				return fmt.Errorf("invalid instrument configuration: %s", err.Error())
			}
		}
	}

	// Validate legacy exclude_services field
	if len(args.Discovery.ExcludeServices) > 0 {
		if err := args.Discovery.ExcludeServices.Validate(); err != nil {
			return fmt.Errorf("invalid exclude_services configuration: %s", err.Error())
		}
	}

	// Validate new exclude_instrument field
	if len(args.Discovery.ExcludeInstrument) > 0 {
		if err := args.Discovery.ExcludeInstrument.Validate(); err != nil {
			return fmt.Errorf("invalid exclude_instrument configuration: %s", err.Error())
		}
	}

	// Validate new default_exclude_instrument field
	if len(args.Discovery.DefaultExcludeInstrument) > 0 {
		if err := args.Discovery.DefaultExcludeInstrument.Validate(); err != nil {
			return fmt.Errorf("invalid default_exclude_instrument configuration: %s", err.Error())
		}
	}

	// Validate per-service samplers for legacy services
	for i, service := range args.Discovery.Services {
		if err := service.Sampler.Validate(); err != nil {
			return fmt.Errorf("invalid sampler configuration in discovery.services[%d]: %s", i, err.Error())
		}
	}

	// Validate per-service samplers for new instrument field
	for i, service := range args.Discovery.Instrument {
		if err := service.Sampler.Validate(); err != nil {
			return fmt.Errorf("invalid sampler configuration in discovery.instrument[%d]: %s", i, err.Error())
		}
	}

	// Validate per-service samplers for survey field
	for i, service := range args.Discovery.Survey {
		if err := service.Sampler.Validate(); err != nil {
			return fmt.Errorf("invalid sampler configuration in discovery.survey[%d]: %s", i, err.Error())
		}
	}

	return nil
}

func (args Traces) Validate() error {
	for _, instrumentation := range args.Instrumentations {
		if _, ok := validInstrumentations[instrumentation]; !ok {
			return fmt.Errorf("traces.instrumentations: invalid value %q", instrumentation)
		}
	}

	// Validate the global sampler config
	if err := args.Sampler.Validate(); err != nil {
		return fmt.Errorf("invalid global sampler configuration: %s", err.Error())
	}

	return nil
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

// writeConfigFile writes the Beyla config to a temporary file
// This generates YAML directly from Arguments without using Beyla's config types
func (c *Component) writeConfigFile() (string, func(), error) {
	config := make(map[string]interface{})

	// Build YAML structure directly from c.args
	c.mut.Lock()
	port := c.subprocessPort
	c.mut.Unlock()

	// Prometheus configuration
	prometheus := map[string]interface{}{
		"port": port,
	}
	if len(c.args.Metrics.Features) > 0 {
		prometheus["features"] = c.args.Metrics.Features
	}
	if len(c.args.Metrics.Instrumentations) > 0 {
		prometheus["instrumentations"] = c.args.Metrics.Instrumentations
	}
	if c.args.Metrics.AllowServiceGraphSelfReferences {
		prometheus["allow_service_graph_self_references"] = true
	}
	if len(c.args.Metrics.ExtraResourceLabels) > 0 {
		prometheus["extra_resource_labels"] = c.args.Metrics.ExtraResourceLabels
	}
	if len(c.args.Metrics.ExtraSpanResourceLabels) > 0 {
		prometheus["extra_span_resource_labels"] = c.args.Metrics.ExtraSpanResourceLabels
	}
	config["prometheus_export"] = prometheus

	// Routes configuration
	if c.args.Routes.Unmatch != "" || len(c.args.Routes.Patterns) > 0 || len(c.args.Routes.IgnorePatterns) > 0 {
		routes := make(map[string]interface{})
		if c.args.Routes.Unmatch != "" {
			routes["unmatched"] = c.args.Routes.Unmatch
		}
		if len(c.args.Routes.Patterns) > 0 {
			routes["patterns"] = c.args.Routes.Patterns
		}
		if len(c.args.Routes.IgnorePatterns) > 0 {
			routes["ignored_patterns"] = c.args.Routes.IgnorePatterns
		}
		if c.args.Routes.IgnoredEvents != "" {
			routes["ignore_mode"] = c.args.Routes.IgnoredEvents
		}
		if c.args.Routes.WildcardChar != "" {
			routes["wildcard"] = c.args.Routes.WildcardChar
		}
		config["routes"] = routes
	}

	// Attributes configuration
	if c.args.Attributes.Kubernetes.Enable != "" || c.args.Attributes.InstanceID.OverrideHostname != "" || len(c.args.Attributes.Select) > 0 {
		attributes := make(map[string]interface{})

		// Kubernetes attributes
		if c.args.Attributes.Kubernetes.Enable != "" {
			kubernetes := map[string]interface{}{
				"enable": c.args.Attributes.Kubernetes.Enable,
			}
			if c.args.Attributes.Kubernetes.ClusterName != "" {
				kubernetes["cluster_name"] = c.args.Attributes.Kubernetes.ClusterName
			}
			if c.args.Attributes.Kubernetes.InformersSyncTimeout != 0 {
				kubernetes["informers_sync_timeout"] = c.args.Attributes.Kubernetes.InformersSyncTimeout.String()
			}
			if c.args.Attributes.Kubernetes.InformersResyncPeriod != 0 {
				kubernetes["informers_resync_period"] = c.args.Attributes.Kubernetes.InformersResyncPeriod.String()
			}
			if len(c.args.Attributes.Kubernetes.DisableInformers) > 0 {
				kubernetes["disable_informers"] = c.args.Attributes.Kubernetes.DisableInformers
			}
			if c.args.Attributes.Kubernetes.MetaRestrictLocalNode {
				kubernetes["meta_restrict_local_node"] = true
			}
			if c.args.Attributes.Kubernetes.MetaCacheAddress != "" {
				kubernetes["meta_cache_address"] = c.args.Attributes.Kubernetes.MetaCacheAddress
			}
			attributes["kubernetes"] = kubernetes
		}

		// InstanceID attributes
		if c.args.Attributes.InstanceID.HostnameDNSResolution || c.args.Attributes.InstanceID.OverrideHostname != "" {
			instanceID := make(map[string]interface{})
			if c.args.Attributes.InstanceID.HostnameDNSResolution {
				instanceID["dns"] = true
			}
			if c.args.Attributes.InstanceID.OverrideHostname != "" {
				instanceID["override_hostname"] = c.args.Attributes.InstanceID.OverrideHostname
			}
			attributes["instance_id"] = instanceID
		}

		// Select attributes
		if len(c.args.Attributes.Select) > 0 {
			selectMap := make(map[string]interface{})
			for _, sel := range c.args.Attributes.Select {
				selConfig := make(map[string]interface{})
				if len(sel.Include) > 0 {
					selConfig["include"] = sel.Include
				}
				if len(sel.Exclude) > 0 {
					selConfig["exclude"] = sel.Exclude
				}
				if len(selConfig) > 0 {
					selectMap[sel.Section] = selConfig
				}
			}
			if len(selectMap) > 0 {
				attributes["select"] = selectMap
			}
		}

		config["attributes"] = attributes
	}

	// Discovery configuration
	discovery := make(map[string]interface{})

	// Legacy services (deprecated)
	if len(c.args.Discovery.Services) > 0 {
		discovery["services"] = buildServicesYAML(c.args.Discovery.Services)
	}
	if len(c.args.Discovery.ExcludeServices) > 0 {
		discovery["exclude_services"] = buildServicesYAML(c.args.Discovery.ExcludeServices)
	}
	if len(c.args.Discovery.DefaultExcludeServices) > 0 {
		discovery["default_exclude_services"] = buildServicesYAML(c.args.Discovery.DefaultExcludeServices)
	}

	// New discovery fields
	if len(c.args.Discovery.Survey) > 0 {
		discovery["survey"] = buildServicesYAML(c.args.Discovery.Survey)
	}
	if len(c.args.Discovery.Instrument) > 0 {
		discovery["instrument"] = buildServicesYAML(c.args.Discovery.Instrument)
	}
	if len(c.args.Discovery.ExcludeInstrument) > 0 {
		discovery["exclude_instrument"] = buildServicesYAML(c.args.Discovery.ExcludeInstrument)
	}
	if len(c.args.Discovery.DefaultExcludeInstrument) > 0 {
		discovery["default_exclude_instrument"] = buildServicesYAML(c.args.Discovery.DefaultExcludeInstrument)
	}

	if c.args.Discovery.SkipGoSpecificTracers {
		discovery["skip_go_specific_tracers"] = true
	}
	if c.args.Discovery.ExcludeOTelInstrumentedServices {
		discovery["exclude_otel_instrumented_services"] = true
	}

	if len(discovery) > 0 {
		config["discovery"] = discovery
	}

	// EBPF configuration
	ebpf := make(map[string]interface{})
	if c.args.EBPF.HTTPRequestTimeout != 0 {
		ebpf["http_request_timeout"] = c.args.EBPF.HTTPRequestTimeout.String()
	}
	if c.args.EBPF.ContextPropagation != "" {
		ebpf["context_propagation"] = c.args.EBPF.ContextPropagation
	}
	if c.args.EBPF.WakeupLen != 0 {
		ebpf["wakeup_len"] = c.args.EBPF.WakeupLen
	}
	if c.args.EBPF.TrackRequestHeaders {
		ebpf["track_request_headers"] = true
	}
	if c.args.EBPF.HighRequestVolume {
		ebpf["high_request_volume"] = true
	}
	if c.args.EBPF.HeuristicSQLDetect {
		ebpf["heuristic_sql_detect"] = true
	}
	if c.args.EBPF.BpfDebug {
		ebpf["bpf_debug"] = true
	}
	if c.args.EBPF.ProtocolDebug {
		ebpf["protocol_debug"] = true
	}
	if len(ebpf) > 0 {
		config["ebpf"] = ebpf
	}

	// Network flows configuration
	if c.args.Metrics.hasNetworkFeature() || c.args.Metrics.Network.Enable {
		networkFlows := map[string]interface{}{
			"enable": true,
		}
		if c.args.Metrics.Network.Source != "" {
			networkFlows["source"] = c.args.Metrics.Network.Source
		}
		if c.args.Metrics.Network.AgentIP != "" {
			networkFlows["agent_ip"] = c.args.Metrics.Network.AgentIP
		}
		if c.args.Metrics.Network.AgentIPIface != "" {
			networkFlows["agent_ip_iface"] = c.args.Metrics.Network.AgentIPIface
		}
		if c.args.Metrics.Network.AgentIPType != "" {
			networkFlows["agent_ip_type"] = c.args.Metrics.Network.AgentIPType
		}
		if len(c.args.Metrics.Network.Interfaces) > 0 {
			networkFlows["interfaces"] = c.args.Metrics.Network.Interfaces
		}
		if len(c.args.Metrics.Network.ExcludeInterfaces) > 0 {
			networkFlows["exclude_interfaces"] = c.args.Metrics.Network.ExcludeInterfaces
		}
		if len(c.args.Metrics.Network.Protocols) > 0 {
			networkFlows["protocols"] = c.args.Metrics.Network.Protocols
		}
		if len(c.args.Metrics.Network.ExcludeProtocols) > 0 {
			networkFlows["exclude_protocols"] = c.args.Metrics.Network.ExcludeProtocols
		}
		if c.args.Metrics.Network.CacheMaxFlows != 0 {
			networkFlows["cache_max_flows"] = c.args.Metrics.Network.CacheMaxFlows
		}
		if c.args.Metrics.Network.CacheActiveTimeout != 0 {
			networkFlows["cache_active_timeout"] = c.args.Metrics.Network.CacheActiveTimeout.String()
		}
		if c.args.Metrics.Network.Direction != "" {
			networkFlows["direction"] = c.args.Metrics.Network.Direction
		}
		if c.args.Metrics.Network.Sampling != 0 {
			networkFlows["sampling"] = c.args.Metrics.Network.Sampling
		}
		if len(c.args.Metrics.Network.CIDRs) > 0 {
			networkFlows["cidrs"] = c.args.Metrics.Network.CIDRs
		}
		config["network_flows"] = networkFlows
	}

	// Filters configuration
	if len(c.args.Filters.Application) > 0 || len(c.args.Filters.Network) > 0 {
		filters := make(map[string]interface{})
		if len(c.args.Filters.Application) > 0 {
			appFilters := make(map[string]interface{})
			for _, filter := range c.args.Filters.Application {
				filterDef := make(map[string]interface{})
				if filter.Match != "" {
					filterDef["match"] = filter.Match
				}
				if filter.NotMatch != "" {
					filterDef["not_match"] = filter.NotMatch
				}
				if len(filterDef) > 0 {
					appFilters[filter.Attr] = filterDef
				}
			}
			if len(appFilters) > 0 {
				filters["application"] = appFilters
			}
		}
		if len(c.args.Filters.Network) > 0 {
			netFilters := make(map[string]interface{})
			for _, filter := range c.args.Filters.Network {
				filterDef := make(map[string]interface{})
				if filter.Match != "" {
					filterDef["match"] = filter.Match
				}
				if filter.NotMatch != "" {
					filterDef["not_match"] = filter.NotMatch
				}
				if len(filterDef) > 0 {
					netFilters[filter.Attr] = filterDef
				}
			}
			if len(netFilters) > 0 {
				filters["network"] = netFilters
			}
		}
		if len(filters) > 0 {
			config["filters"] = filters
		}
	}

	// Traces configuration (only if output is defined)
	if c.args.Output != nil && (len(c.args.Traces.Instrumentations) > 0 || c.args.Traces.Sampler.Name != "") {
		traces := make(map[string]interface{})
		if len(c.args.Traces.Instrumentations) > 0 {
			traces["instrumentations"] = c.args.Traces.Instrumentations
		}
		if c.args.Traces.Sampler.Name != "" {
			sampler := map[string]interface{}{
				"name": c.args.Traces.Sampler.Name,
			}
			if c.args.Traces.Sampler.Arg != "" {
				sampler["arg"] = c.args.Traces.Sampler.Arg
			}
			traces["sampler"] = sampler
		}
		if len(traces) > 0 {
			config["traces"] = traces
		}
	}

	// OTLP traces export configuration (when Output consumer is configured)
	if c.args.Output != nil && len(c.args.Output.Traces) > 0 {
		c.mut.Lock()
		otlpPort := c.otlpReceiverPort
		c.mut.Unlock()

		if otlpPort > 0 {
			otelTracesExport := map[string]interface{}{
				"endpoint": fmt.Sprintf("http://localhost:%d", otlpPort),
				"protocol": "http/protobuf",
			}
			config["otel_traces_export"] = otelTracesExport
			level.Debug(c.opts.Logger).Log("msg", "configured OTLP traces export", "endpoint", fmt.Sprintf("http://localhost:%d", otlpPort))
		}
	}

	// TracePrinter configuration
	if c.args.TracePrinter != "" && c.args.TracePrinter != "disabled" {
		config["trace_printer"] = c.args.TracePrinter
	}

	// EnforceSysCaps configuration
	if c.args.EnforceSysCaps {
		config["enforce_sys_caps"] = true
	}

	// Serialize config to YAML
	configData, err := yaml.Marshal(config)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	// Log the generated YAML for debugging
	level.Debug(c.opts.Logger).Log("msg", "generated Beyla YAML config", "yaml", string(configData))

	// Create temporary file
	tmpFile, err := os.CreateTemp("", "beyla-config-*.yaml")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	if _, err := tmpFile.Write(configData); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", nil, fmt.Errorf("failed to write config: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpFile.Name())
		return "", nil, fmt.Errorf("failed to close temp file: %w", err)
	}

	cleanup := func() {
		os.Remove(tmpFile.Name())
	}

	return tmpFile.Name(), cleanup, nil
}

// buildServicesYAML builds YAML configuration for services discovery
func buildServicesYAML(services Services) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(services))

	for _, svc := range services {
		service := make(map[string]interface{})

		if svc.Name != "" {
			service["name"] = svc.Name
		}
		if svc.Namespace != "" {
			service["namespace"] = svc.Namespace
		}
		if svc.OpenPorts != "" {
			service["open_ports"] = svc.OpenPorts
		}
		if svc.Path != "" {
			service["exe_path"] = svc.Path
		}
		if svc.ContainersOnly {
			service["containers_only"] = true
		}
		if len(svc.ExportModes) > 0 {
			service["exports"] = svc.ExportModes
		}

		// Kubernetes metadata
		k8s := make(map[string]interface{})
		if svc.Kubernetes.Namespace != "" {
			k8s["namespace"] = svc.Kubernetes.Namespace
		}
		if svc.Kubernetes.PodName != "" {
			k8s["pod_name"] = svc.Kubernetes.PodName
		}
		if svc.Kubernetes.DeploymentName != "" {
			k8s["deployment_name"] = svc.Kubernetes.DeploymentName
		}
		if svc.Kubernetes.ReplicaSetName != "" {
			k8s["replicaset_name"] = svc.Kubernetes.ReplicaSetName
		}
		if svc.Kubernetes.StatefulSetName != "" {
			k8s["statefulset_name"] = svc.Kubernetes.StatefulSetName
		}
		if svc.Kubernetes.DaemonSetName != "" {
			k8s["daemonset_name"] = svc.Kubernetes.DaemonSetName
		}
		if svc.Kubernetes.OwnerName != "" {
			k8s["owner_name"] = svc.Kubernetes.OwnerName
		}
		if len(svc.Kubernetes.PodLabels) > 0 {
			k8s["pod_labels"] = svc.Kubernetes.PodLabels
		}
		if len(svc.Kubernetes.PodAnnotations) > 0 {
			k8s["pod_annotations"] = svc.Kubernetes.PodAnnotations
		}
		if len(k8s) > 0 {
			service["kubernetes"] = k8s
		}

		// Sampler configuration
		if svc.Sampler.Name != "" {
			sampler := map[string]interface{}{
				"name": svc.Sampler.Name,
			}
			if svc.Sampler.Arg != "" {
				sampler["arg"] = svc.Sampler.Arg
			}
			service["sampler"] = sampler
		}

		if len(service) > 0 {
			result = append(result, service)
		}
	}

	return result
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
func (c *Component) startOTLPReceiver(ctx context.Context) error {
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
