//go:build (linux && arm64) || (linux && amd64)

package beyla

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/grafana/alloy/internal/runtime/logging/level"
)

// writeConfigFile writes the Beyla config to a temporary file
// This generates YAML directly from Arguments without using Beyla's config types
func (c *Component) writeConfigFile() (string, func(), error) {
	config := c.buildConfig()

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

// buildConfig builds the complete Beyla YAML configuration
func (c *Component) buildConfig() map[string]interface{} {
	config := make(map[string]interface{})

	// Add each configuration section
	c.addPrometheusConfig(config)
	c.addRoutesConfig(config)
	c.addAttributesConfig(config)
	c.addDiscoveryConfig(config)
	c.addEBPFConfig(config)
	c.addNetworkConfig(config)
	c.addFiltersConfig(config)
	c.addTracesConfig(config)
	c.addOTLPTracesExportConfig(config)
	c.addTracePrinterConfig(config)
	c.addEnforceSysCapsConfig(config)
	c.addTopLevelConfig(config)

	return config
}

// addPrometheusConfig adds Prometheus export configuration
// Generates:
//   prometheus_export:
//     port: 8080
//     features: ["application", "network"]
//     instrumentations: ["http", "grpc"]
func (c *Component) addPrometheusConfig(config map[string]interface{}) {
	c.mut.Lock()
	port := c.subprocessPort
	c.mut.Unlock()

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
}

// addRoutesConfig adds route configuration
// Generates:
//
//	routes:
//	  unmatched: "heuristic"
//	  patterns: ["/api/*", "/users/{id}"]
//	  ignored_patterns: ["/health", "/metrics"]
func (c *Component) addRoutesConfig(config map[string]interface{}) {
	if c.args.Routes.Unmatch == "" && len(c.args.Routes.Patterns) == 0 && len(c.args.Routes.IgnorePatterns) == 0 &&
		c.args.Routes.MaxPathSegmentCardinality == 0 {
		return
	}

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
	if c.args.Routes.MaxPathSegmentCardinality != 0 {
		routes["max_path_segment_cardinality"] = c.args.Routes.MaxPathSegmentCardinality
	}

	config["routes"] = routes
}

// addAttributesConfig adds attributes configuration
// Generates:
//   attributes:
//     kubernetes:
//       enable: "true"
//       cluster_name: "my-cluster"
//     instance_id:
//       dns: true
//       override_hostname: "custom-host"
//     select:
//       http:
//         include: ["method", "status"]
func (c *Component) addAttributesConfig(config map[string]interface{}) {
	if c.args.Attributes.Kubernetes.Enable == "" && c.args.Attributes.InstanceID.OverrideHostname == "" && len(c.args.Attributes.Select) == 0 {
		return
	}

	attributes := make(map[string]interface{})

	// Kubernetes attributes
	if c.args.Attributes.Kubernetes.Enable != "" {
		kubernetes := c.buildKubernetesConfig()
		attributes["kubernetes"] = kubernetes
	}

	// InstanceID attributes
	if c.args.Attributes.InstanceID.HostnameDNSResolution || c.args.Attributes.InstanceID.OverrideHostname != "" {
		instanceID := c.buildInstanceIDConfig()
		attributes["instance_id"] = instanceID
	}

	// Select attributes
	if len(c.args.Attributes.Select) > 0 {
		selectMap := c.buildSelectConfig()
		if len(selectMap) > 0 {
			attributes["select"] = selectMap
		}
	}

	config["attributes"] = attributes
}

// buildKubernetesConfig builds Kubernetes attributes configuration
func (c *Component) buildKubernetesConfig() map[string]interface{} {
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
	if c.args.Attributes.Kubernetes.DropExternal {
		kubernetes["drop_external"] = true
	}
	if len(c.args.Attributes.Kubernetes.ResourceLabels) > 0 {
		kubernetes["resource_labels"] = c.args.Attributes.Kubernetes.ResourceLabels
	}
	if c.args.Attributes.Kubernetes.ServiceNameTemplate != "" {
		kubernetes["service_name_template"] = c.args.Attributes.Kubernetes.ServiceNameTemplate
	}

	return kubernetes
}

// buildInstanceIDConfig builds InstanceID configuration
func (c *Component) buildInstanceIDConfig() map[string]interface{} {
	instanceID := make(map[string]interface{})

	if c.args.Attributes.InstanceID.HostnameDNSResolution {
		instanceID["dns"] = true
	}
	if c.args.Attributes.InstanceID.OverrideHostname != "" {
		instanceID["override_hostname"] = c.args.Attributes.InstanceID.OverrideHostname
	}

	return instanceID
}

// buildSelectConfig builds attribute selection configuration
func (c *Component) buildSelectConfig() map[string]interface{} {
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

	return selectMap
}

// addDiscoveryConfig adds service discovery configuration
// Generates:
//   discovery:
//     services:
//       - open_ports: "8080-8089"
//         exe_path: "/usr/bin/myapp"
//     instrument:
//       - name: "my-service"
//         namespace: "default"
//     skip_go_specific_tracers: true
func (c *Component) addDiscoveryConfig(config map[string]interface{}) {
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
	if c.args.Discovery.ExcludeOTelInstrumentedServicesSpanMetrics {
		discovery["exclude_otel_instrumented_services_span_metrics"] = true
	}
	if c.args.Discovery.MinProcessAge != 0 {
		discovery["min_process_age"] = c.args.Discovery.MinProcessAge.String()
	}
	if c.args.Discovery.PollInterval != 0 {
		discovery["poll_interval"] = c.args.Discovery.PollInterval.String()
	}
	if c.args.Discovery.BpfPidFilterOff {
		discovery["bpf_pid_filter_off"] = true
	}
	if c.args.Discovery.RouteHarvesterTimeout != 0 {
		discovery["route_harvester_timeout"] = c.args.Discovery.RouteHarvesterTimeout.String()
	}
	if len(c.args.Discovery.DisabledRouteHarvesters) > 0 {
		discovery["disabled_route_harvesters"] = c.args.Discovery.DisabledRouteHarvesters
	}
	if len(c.args.Discovery.ExcludedLinuxSystemPaths) > 0 {
		discovery["excluded_linux_system_paths"] = c.args.Discovery.ExcludedLinuxSystemPaths
	}

	if len(discovery) > 0 {
		config["discovery"] = discovery
	}
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
		if svc.CmdArgs != "" {
			service["cmd_args"] = svc.CmdArgs
		}
		if len(svc.Languages) > 0 {
			service["languages"] = svc.Languages
		}
		if svc.ContainersOnly {
			service["containers_only"] = true
		}
		if len(svc.ExportModes) > 0 {
			service["exports"] = svc.ExportModes
		}

		// Kubernetes metadata: merge flat k8s_* fields directly into the entry
		// (OBI v3 GlobAttributes uses flat k8s_* keys, not a nested kubernetes block)
		for k, v := range buildKubernetesServiceConfig(svc.Kubernetes) {
			service[k] = v
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

// buildKubernetesServiceConfig builds Kubernetes service metadata configuration
func buildKubernetesServiceConfig(k8sService KubernetesService) map[string]interface{} {
	k8s := make(map[string]interface{})

	if k8sService.Namespace != "" {
		k8s["k8s_namespace"] = k8sService.Namespace
	}
	if k8sService.PodName != "" {
		k8s["k8s_pod_name"] = k8sService.PodName
	}
	if k8sService.DeploymentName != "" {
		k8s["k8s_deployment_name"] = k8sService.DeploymentName
	}
	if k8sService.ReplicaSetName != "" {
		k8s["k8s_replicaset_name"] = k8sService.ReplicaSetName
	}
	if k8sService.StatefulSetName != "" {
		k8s["k8s_statefulset_name"] = k8sService.StatefulSetName
	}
	if k8sService.DaemonSetName != "" {
		k8s["k8s_daemonset_name"] = k8sService.DaemonSetName
	}
	if k8sService.CronjobName != "" {
		k8s["k8s_cronjob_name"] = k8sService.CronjobName
	}
	if k8sService.JobName != "" {
		k8s["k8s_job_name"] = k8sService.JobName
	}
	if k8sService.ContainerName != "" {
		k8s["k8s_container_name"] = k8sService.ContainerName
	}
	if k8sService.OwnerName != "" {
		k8s["k8s_owner_name"] = k8sService.OwnerName
	}
	if len(k8sService.PodLabels) > 0 {
		k8s["k8s_pod_labels"] = k8sService.PodLabels
	}
	if len(k8sService.PodAnnotations) > 0 {
		k8s["k8s_pod_annotations"] = k8sService.PodAnnotations
	}

	return k8s
}

// addEBPFConfig adds eBPF configuration
// Generates:
//   ebpf:
//     http_request_timeout: "30s"
//     context_propagation: "enabled"
//     track_request_headers: true
//     bpf_debug: false
func (c *Component) addEBPFConfig(config map[string]interface{}) {
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
	if c.args.EBPF.InstrumentCuda != 0 {
		ebpf["instrument_cuda"] = c.args.EBPF.InstrumentCuda
	}
	if c.args.EBPF.MaxTransactionTime != 0 {
		ebpf["max_transaction_time"] = c.args.EBPF.MaxTransactionTime.String()
	}
	if c.args.EBPF.DNSRequestTimeout != 0 {
		ebpf["dns_request_timeout"] = c.args.EBPF.DNSRequestTimeout.String()
	}

	if len(ebpf) > 0 {
		config["ebpf"] = ebpf
	}
}

// addNetworkConfig adds network configuration
// Generates:
//
//	network:
//	  enable: true
//	  source: "auto"
//	  interfaces: ["eth0", "eth1"]
//	  cache_max_flows: 10000
//	  direction: "both"
func (c *Component) addNetworkConfig(config map[string]interface{}) {
	if !c.args.Metrics.hasNetworkFeature() && !c.args.Metrics.Network.Enable {
		return
	}

	network := map[string]interface{}{
		"enable": true,
	}

	if c.args.Metrics.Network.Source != "" {
		network["source"] = c.args.Metrics.Network.Source
	}
	if c.args.Metrics.Network.AgentIP != "" {
		network["agent_ip"] = c.args.Metrics.Network.AgentIP
	}
	if c.args.Metrics.Network.AgentIPIface != "" {
		network["agent_ip_iface"] = c.args.Metrics.Network.AgentIPIface
	}
	if c.args.Metrics.Network.AgentIPType != "" {
		network["agent_ip_type"] = c.args.Metrics.Network.AgentIPType
	}
	if len(c.args.Metrics.Network.Interfaces) > 0 {
		network["interfaces"] = c.args.Metrics.Network.Interfaces
	}
	if len(c.args.Metrics.Network.ExcludeInterfaces) > 0 {
		network["exclude_interfaces"] = c.args.Metrics.Network.ExcludeInterfaces
	}
	if len(c.args.Metrics.Network.Protocols) > 0 {
		network["protocols"] = c.args.Metrics.Network.Protocols
	}
	if len(c.args.Metrics.Network.ExcludeProtocols) > 0 {
		network["exclude_protocols"] = c.args.Metrics.Network.ExcludeProtocols
	}
	if c.args.Metrics.Network.CacheMaxFlows != 0 {
		network["cache_max_flows"] = c.args.Metrics.Network.CacheMaxFlows
	}
	if c.args.Metrics.Network.CacheActiveTimeout != 0 {
		network["cache_active_timeout"] = c.args.Metrics.Network.CacheActiveTimeout.String()
	}
	if c.args.Metrics.Network.Direction != "" {
		network["direction"] = c.args.Metrics.Network.Direction
	}
	if c.args.Metrics.Network.Sampling != 0 {
		network["sampling"] = c.args.Metrics.Network.Sampling
	}
	if len(c.args.Metrics.Network.CIDRs) > 0 {
		network["cidrs"] = c.args.Metrics.Network.CIDRs
	}

	config["network"] = network
}

// addFiltersConfig adds filters configuration
// Generates:
//   filters:
//     application:
//       http.method:
//         match: "GET|POST"
//       http.status_code:
//         not_match: "404"
//     network:
//       src.ip:
//         match: "192.168.*"
func (c *Component) addFiltersConfig(config map[string]interface{}) {
	if len(c.args.Filters.Application) == 0 && len(c.args.Filters.Network) == 0 {
		return
	}

	filters := make(map[string]interface{})

	if len(c.args.Filters.Application) > 0 {
		appFilters := c.buildAttributeFilters(c.args.Filters.Application)
		if len(appFilters) > 0 {
			filters["application"] = appFilters
		}
	}

	if len(c.args.Filters.Network) > 0 {
		netFilters := c.buildAttributeFilters(c.args.Filters.Network)
		if len(netFilters) > 0 {
			filters["network"] = netFilters
		}
	}

	if len(filters) > 0 {
		config["filter"] = filters
	}
}

// buildAttributeFilters builds attribute filter configuration
func (c *Component) buildAttributeFilters(filters AttributeFamilies) map[string]interface{} {
	result := make(map[string]interface{})

	for _, filter := range filters {
		filterDef := make(map[string]interface{})
		if filter.Match != "" {
			filterDef["match"] = filter.Match
		}
		if filter.NotMatch != "" {
			filterDef["not_match"] = filter.NotMatch
		}
		if len(filterDef) > 0 {
			result[filter.Attr] = filterDef
		}
	}

	return result
}

// addTracesConfig adds traces configuration
// Generates:
//   traces:
//     instrumentations: ["http", "grpc", "sql"]
//     sampler:
//       name: "traceidratio"
//       arg: "0.1"
func (c *Component) addTracesConfig(config map[string]interface{}) {
	if c.args.Output == nil || (len(c.args.Traces.Instrumentations) == 0 && c.args.Traces.Sampler.Name == "") {
		return
	}

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

// addOTLPTracesExportConfig adds OTLP traces export configuration
// Generates:
//   otel_traces_export:
//     endpoint: "http://localhost:54321"
//     protocol: "http/protobuf"
func (c *Component) addOTLPTracesExportConfig(config map[string]interface{}) {
	if c.args.Output == nil || len(c.args.Output.Traces) == 0 {
		return
	}

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

// addTracePrinterConfig adds trace printer configuration
// Generates:
//   trace_printer: "json"
func (c *Component) addTracePrinterConfig(config map[string]interface{}) {
	if c.args.TracePrinter != "" && c.args.TracePrinter != "disabled" {
		config["trace_printer"] = c.args.TracePrinter
	}
}

// addEnforceSysCapsConfig adds enforce_sys_caps configuration
// Generates:
//   enforce_sys_caps: true
func (c *Component) addEnforceSysCapsConfig(config map[string]interface{}) {
	if c.args.EnforceSysCaps {
		config["enforce_sys_caps"] = true
	}
}

// addTopLevelConfig adds miscellaneous top-level configuration fields.
func (c *Component) addTopLevelConfig(config map[string]interface{}) {
	if c.args.LogLevel != "" {
		config["log_level"] = c.args.LogLevel
	}
	if c.args.ShutdownTimeout != 0 {
		config["shutdown_timeout"] = c.args.ShutdownTimeout.String()
	}

	ja := c.args.JavaAgent
	if ja.Enabled || ja.AttachTimeout != "" || ja.Debug || ja.DebugInstrumentation {
		javaagent := map[string]interface{}{}
		if ja.Enabled {
			javaagent["enabled"] = true
		}
		if ja.AttachTimeout != "" {
			javaagent["attach_timeout"] = ja.AttachTimeout
		}
		if ja.Debug {
			javaagent["debug"] = true
		}
		if ja.DebugInstrumentation {
			javaagent["debug_instrumentation"] = true
		}
		config["javaagent"] = javaagent
	}

	if c.args.NodeJS.Enabled {
		config["nodejs"] = map[string]interface{}{
			"enabled": true,
		}
	}
}
