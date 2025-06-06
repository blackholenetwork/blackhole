// Package webserver provides HTTP/WebSocket server functionality
package webserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/websocket/v2"

	"github.com/blackholenetwork/blackhole/pkg/core/monitor"
	"github.com/blackholenetwork/blackhole/pkg/core/orchestrator"
	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

// RegistryInterface defines the registry methods needed by the webserver
type RegistryInterface interface {
	List() []plugin.Plugin
	Subscribe(eventType string, handler plugin.EventHandler) func()
}

const (
	// statusReady indicates a plugin is ready
	statusReady = "ready"
)

// Plugin provides HTTP/WebSocket server with progressive API activation
type Plugin struct {
	*plugin.BasePlugin
	server       *fiber.App
	config       Config
	registry     RegistryInterface
	orchestrator interface {
		Health() map[string]orchestrator.ComponentHealth
		HealthExcluding(caller string) map[string]orchestrator.ComponentHealth
	}
	mu            sync.RWMutex
	readyAPIs     map[string]bool
	startupStatus map[string]PluginStatus
	wsClients     map[*websocket.Conn]bool
	wsClientsMu   sync.RWMutex
	started       bool
	healthStatus  plugin.HealthStatus
	healthMessage string
	logger        *log.Logger
}

// Config holds configuration for the web server
type Config struct {
	Port            int    `json:"port"`
	Host            string `json:"host"`
	EnableDashboard bool   `json:"enable_dashboard"`
	EnableWebSocket bool   `json:"enable_websocket"`
	CORSOrigins     string `json:"cors_origins"`
}

// PluginStatus represents the status of a plugin during startup
type PluginStatus struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"` // starting, ready, failed
	Message   string    `json:"message"`
	StartedAt time.Time `json:"started_at"`
}

// New creates a new web server plugin
func New(registry RegistryInterface, orch interface {
	Health() map[string]orchestrator.ComponentHealth
	HealthExcluding(caller string) map[string]orchestrator.ComponentHealth
},
) *Plugin {
	info := plugin.Info{
		Name:         "webserver",
		Version:      "1.0.0",
		Description:  "Web server with dashboard and API endpoints",
		Author:       "Blackhole Network",
		License:      "Apache-2.0",
		Dependencies: []string{"security"},
		Capabilities: []string{string(plugin.CapabilityAPI)},
	}

	ws := &Plugin{
		BasePlugin:    plugin.NewBasePlugin(info),
		registry:      registry,
		orchestrator:  orch,
		readyAPIs:     make(map[string]bool),
		startupStatus: make(map[string]PluginStatus),
		wsClients:     make(map[*websocket.Conn]bool),
		healthStatus:  plugin.HealthStatusUnknown,
		healthMessage: "Not initialized",
		logger:        log.New(os.Stdout, "[WebServer] ", log.LstdFlags),
	}
	// Note: SetRegistry expects *plugin.Registry, but we only have the interface
	// This is a limitation of the current architecture
	return ws
}

// Info returns metadata about the plugin
func (ws *Plugin) Info() plugin.Info {
	return plugin.Info{
		Name:         "webserver",
		Version:      "1.0.0",
		Description:  "Web server with dashboard and API endpoints",
		Author:       "Blackhole Network",
		License:      "Apache-2.0",
		Dependencies: []string{"security"},
		Capabilities: []string{string(plugin.CapabilityAPI)},
	}
}

// Init initializes the plugin with configuration
func (ws *Plugin) Init(_ context.Context, config plugin.Config) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	// Parse configuration
	ws.config = Config{
		Port:            8080,
		Host:            "127.0.0.1", // Localhost only by default
		EnableDashboard: true,
		EnableWebSocket: true,
		CORSOrigins:     "http://localhost:8080", // Allow localhost:8080
	}

	if port, ok := config["port"].(int); ok {
		ws.config.Port = port
	}
	if host, ok := config["host"].(string); ok {
		ws.config.Host = host
	}
	if dashboard, ok := config["enable_dashboard"].(bool); ok {
		ws.config.EnableDashboard = dashboard
	}
	if websocket, ok := config["enable_websocket"].(bool); ok {
		ws.config.EnableWebSocket = websocket
	}


	// Update health status
	ws.healthStatus = plugin.HealthStatusHealthy
	ws.healthMessage = "WebServer initialized"
	ws.SetHealth(ws.healthStatus, ws.healthMessage)

	return nil
}

// Start starts the plugin
func (ws *Plugin) Start(_ context.Context) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	if ws.started {
		return fmt.Errorf("webserver plugin already started")
	}

	// Create Fiber app
	ws.server = fiber.New(fiber.Config{
		DisableStartupMessage: true,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{
				"error": err.Error(),
			})
		},
	})

	// Setup middleware
	ws.server.Use(cors.New(cors.Config{
		AllowOrigins: ws.config.CORSOrigins,
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders: "Origin,Content-Type,Accept,Authorization",
	}))
	ws.server.Use(logger.New())
	ws.server.Use(recover.New())

	// Setup basic endpoints
	ws.setupBasicEndpoints()

	// Setup plugin API endpoints (must be done before server starts)
	ws.setupPluginAPIs()

	// Setup WebSocket if enabled
	if ws.config.EnableWebSocket {
		ws.setupWebSocket()
	}

	// Setup dashboard if enabled
	if ws.config.EnableDashboard {
		ws.setupDashboard()
	}


	// Subscribe to plugin state transition events
	if ws.registry != nil {
		ws.registry.Subscribe("state_transition", ws.handleStateTransition)
	}

	// Start monitoring plugin status by polling
	go ws.monitorPluginStatus(context.Background())

	// Start server in goroutine
	go func() {
		addr := fmt.Sprintf("%s:%d", ws.config.Host, ws.config.Port)
		if err := ws.server.Listen(addr); err != nil {
			log.Printf("Web server error: %v", err)
		}
	}()

	ws.started = true

	// Update and publish initial health status
	ws.healthStatus = plugin.HealthStatusHealthy
	ws.healthMessage = fmt.Sprintf("WebServer operational on %s:%d", ws.config.Host, ws.config.Port)
	ws.SetHealth(ws.healthStatus, ws.healthMessage)

	return nil
}

// Stop gracefully shuts down the plugin
func (ws *Plugin) Stop(_ context.Context) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	if !ws.started {
		return nil
	}


	// Shutdown server
	if ws.server != nil {
		if err := ws.server.Shutdown(); err != nil {
			return fmt.Errorf("failed to shutdown webserver: %w", err)
		}
	}


	// Clean up resources
	ws.started = false

	// Update health status
	ws.healthStatus = plugin.HealthStatusUnknown
	ws.healthMessage = "WebServer stopped"
	ws.SetHealth(ws.healthStatus, ws.healthMessage)

	return nil
}

// Health returns the current health status
func (ws *Plugin) Health() plugin.Health {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	// Calculate current health status
	var status plugin.HealthStatus
	var message string

	readyAPICount := len(ws.readyAPIs)
	clientCount := len(ws.wsClients)

	switch {
	case !ws.started:
		status = plugin.HealthStatusUnknown
		message = "WebServer not started"
	case ws.server == nil:
		status = plugin.HealthStatusUnhealthy
		message = "WebServer not properly initialized"
	default:
		status = plugin.HealthStatusHealthy
		message = fmt.Sprintf("WebServer operational (%d APIs ready, %d WS clients)", readyAPICount, clientCount)
	}

	return plugin.Health{
		Status:    status,
		Message:   message,
		LastCheck: time.Now(),
		Details: map[string]interface{}{
			"address":    fmt.Sprintf("%s:%d", ws.config.Host, ws.config.Port),
			"apis_ready": readyAPICount,
			"ws_clients": clientCount,
			"started":    ws.started,
			"dashboard":  ws.config.EnableDashboard,
			"websocket":  ws.config.EnableWebSocket,
		},
	}
}

// setupBasicEndpoints sets up endpoints that are always available
func (ws *Plugin) setupBasicEndpoints() {
	// Health check endpoint
	ws.server.Get("/health", ws.healthHandler)

	// System status endpoint
	ws.server.Get("/status", ws.statusHandler)

	// Startup progress endpoint
	ws.server.Get("/startup", ws.startupProgressHandler)

	// Plugin list endpoint
	ws.server.Get("/api/plugins", ws.pluginsHandler)

	// Startup log endpoint
	ws.server.Get("/api/startup-log", ws.startupLogHandler)

	// Plugin states endpoint
	ws.server.Get("/api/plugin-states", ws.pluginStatesHandler)
}

// setupPluginAPIs sets up all plugin API endpoints upfront
func (ws *Plugin) setupPluginAPIs() {
	// Monitor plugin APIs
	ws.server.Get("/api/metrics", ws.metricsHandler)
	ws.server.Get("/api/diagnostics", ws.placeholderHandler("System diagnostics"))

	// Network plugin APIs
	ws.server.Get("/api/network/peers", ws.placeholderHandler("Network peers"))
	ws.server.Get("/api/network/stats", ws.placeholderHandler("Network stats"))

	// Storage plugin APIs (when implemented)
	ws.server.Post("/api/storage/upload", ws.placeholderHandler("Storage upload"))
	ws.server.Get("/api/storage/download/:cid", ws.placeholderHandler("Storage download"))
	ws.server.Get("/api/storage/list", ws.placeholderHandler("Storage list"))

	// Compute plugin APIs (when implemented)
	ws.server.Post("/api/compute/submit", ws.placeholderHandler("Submit compute job"))
	ws.server.Get("/api/compute/status/:jobId", ws.placeholderHandler("Job status"))

	// Economic plugin APIs (when implemented)
	ws.server.Get("/api/economic/balance", ws.placeholderHandler("Account balance"))
	ws.server.Get("/api/economic/usage", ws.placeholderHandler("Resource usage"))
}

// Health check handler
func (ws *Plugin) healthHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status": "healthy",
		"time":   time.Now(),
		"uptime": time.Since(time.Now()).Seconds(), // TODO: Track actual start time
	})
}

// Status handler shows system status
func (ws *Plugin) statusHandler(c *fiber.Ctx) error {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	return c.JSON(fiber.Map{
		"status":     "operational",
		"ready_apis": ws.readyAPIs,
		"plugins":    ws.startupStatus,
		"time":       time.Now(),
	})
}

// Startup progress handler
func (ws *Plugin) startupProgressHandler(c *fiber.Ctx) error {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	// Calculate overall progress
	totalPlugins := len(ws.startupStatus)
	readyPlugins := 0
	for _, status := range ws.startupStatus {
		if status.Status == statusReady {
			readyPlugins++
		}
	}

	overallProgress := 0
	if totalPlugins > 0 {
		overallProgress = (readyPlugins * 100) / totalPlugins
	}

	return c.JSON(fiber.Map{
		"overall_progress": overallProgress,
		"plugins":          ws.startupStatus,
		"ready":            readyPlugins == totalPlugins,
		"time":             time.Now(),
	})
}

// Plugins handler lists all registered plugins
func (ws *Plugin) pluginsHandler(c *fiber.Ctx) error {
	// TODO: Get from registry when proper state management is implemented
	return c.JSON(fiber.Map{
		"plugins": []string{
			"security",
			"monitor",
			"network",
			"webserver",
			"resourcemanager",
		},
		"time": time.Now(),
	})
}

// startupLogHandler returns the startup log
func (ws *Plugin) startupLogHandler(c *fiber.Ctx) error {
	// Get today's log file path
	logsDir := "./logs"
	startupLogPath := fmt.Sprintf("%s/startup_%s.log", logsDir, time.Now().Format("2006-01-02"))

	// Check if log file exists
	if _, err := os.Stat(startupLogPath); os.IsNotExist(err) {
		return c.JSON(fiber.Map{
			"error": "No startup log found for today",
			"path":  startupLogPath,
		})
	}

	// Read the log file
	content, err := os.ReadFile(startupLogPath)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to read startup log: %v", err),
		})
	}

	// Parse log lines
	lines := strings.Split(string(content), "\n")
	var events []map[string]string

	for _, line := range lines {
		if line == "" {
			continue
		}

		// Parse log line format: "2025/06/06 16:00:00.123456 [EVENT_TYPE] plugin_name: message"
		// Or separator lines: "2025/06/06 16:00:00.123456 === message ==="
		parts := strings.SplitN(line, " ", 3)
		if len(parts) >= 3 {
			dateTime := parts[0] + " " + parts[1]
			eventInfo := parts[2]

			event := map[string]string{
				"timestamp": dateTime,
				"raw":       line,
			}

			if strings.HasPrefix(eventInfo, "[") {
				// Parse structured event
				endIdx := strings.Index(eventInfo, "]")
				if endIdx > 0 {
					eventType := eventInfo[1:endIdx]
					rest := strings.TrimSpace(eventInfo[endIdx+1:])
					colonIdx := strings.Index(rest, ":")
					if colonIdx > 0 {
						plugin := strings.TrimSpace(rest[:colonIdx])
						message := strings.TrimSpace(rest[colonIdx+1:])
						event["type"] = eventType
						event["plugin"] = plugin
						event["message"] = message
					}
				}
			} else if strings.HasPrefix(eventInfo, "===") {
				// System message
				event["type"] = "SYSTEM"
				event["message"] = eventInfo
			}

			events = append(events, event)
		}
	}

	return c.JSON(fiber.Map{
		"log_file": startupLogPath,
		"events":   events,
		"count":    len(events),
		"time":     time.Now(),
	})
}

// metricsHandler returns system metrics from the monitor plugin
func (ws *Plugin) metricsHandler(c *fiber.Ctx) error {
	// Try to get the monitor plugin from registry
	if ws.registry != nil {
		plugins := ws.registry.List()
		for _, p := range plugins {
			if p.Info().Name == "monitor" {
				// Try to get metrics via type assertion
				if metricsProvider, ok := p.(interface{ GetMetrics() map[string]*monitor.Metric }); ok {
					metrics := metricsProvider.GetMetrics()
					return c.JSON(metrics)
				}
			}
		}
	}

	// Fallback to placeholder if monitor plugin not found or doesn't support GetMetrics
	return c.JSON(fiber.Map{
		"error": "Monitor plugin not available or metrics not supported",
		"time":  time.Now(),
	})
}

// setupWebSocket sets up WebSocket endpoints for real-time updates
func (ws *Plugin) setupWebSocket() {
	ws.server.Get("/ws", websocket.New(func(c *websocket.Conn) {
		ws.handleWebSocket(c)
	}))
}

// handleWebSocket handles WebSocket connections
func (ws *Plugin) handleWebSocket(conn *websocket.Conn) {
	// Register client
	ws.wsClientsMu.Lock()
	ws.wsClients[conn] = true
	ws.wsClientsMu.Unlock()

	// Send initial status
	ws.sendStartupStatus(conn)

	// Cleanup on disconnect
	defer func() {
		ws.wsClientsMu.Lock()
		delete(ws.wsClients, conn)
		ws.wsClientsMu.Unlock()
		if err := conn.Close(); err != nil {
			ws.logger.Printf("Error closing WebSocket connection: %v", err)
		}
	}()

	// Keep connection alive and handle messages
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		// Echo back for now - implement command handling later
		if err := conn.WriteMessage(messageType, message); err != nil {
			break
		}
	}
}

// sendStartupStatus sends current startup status to a WebSocket client
func (ws *Plugin) sendStartupStatus(conn *websocket.Conn) {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	// Make sure we have some status to send
	if len(ws.startupStatus) == 0 {
		// Initialize with current state if empty
		ws.mu.RUnlock()
		ws.updatePluginStatus("security", statusReady, "Plugin operational")
		ws.updatePluginStatus("analytics", statusReady, "Plugin operational")
		ws.updatePluginStatus("webserver", statusReady, "Plugin operational")
		ws.updatePluginStatus("network", "degraded", "No peers connected")
		ws.mu.RLock()
	}

	status := map[string]interface{}{
		"type":    "startup_status",
		"plugins": ws.startupStatus,
		"time":    time.Now(),
	}

	data, _ := json.Marshal(status)
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		ws.logger.Printf("Error sending connection status: %v", err)
	}
}

// broadcastStatusSnapshot broadcasts status update using provided snapshot
func (ws *Plugin) broadcastStatusSnapshot(currentStatus map[string]PluginStatus) {
	ws.wsClientsMu.RLock()
	defer ws.wsClientsMu.RUnlock()

	// Send full plugin status
	update := map[string]interface{}{
		"type":    "plugin_update",
		"plugins": currentStatus,
		"time":    time.Now(),
	}

	data, _ := json.Marshal(update)

	for conn := range ws.wsClients {
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			ws.logger.Printf("Error broadcasting to WebSocket client: %v", err)
		}
	}
}


// broadcastStartupEvent broadcasts a startup event for plugin lifecycle tracking
func (ws *Plugin) broadcastStartupEvent(pluginName, status, message string) {
	ws.wsClientsMu.RLock()
	defer ws.wsClientsMu.RUnlock()

	// Map status to event type
	eventType := "initializing"
	switch status {
	case statusReady, string(plugin.HealthStatusHealthy):
		eventType = "started"
	case "failed", string(plugin.HealthStatusUnhealthy):
		eventType = "failed"
	case "starting":
		eventType = "starting"
	case string(plugin.HealthStatusDegraded):
		eventType = "started"  // Map degraded to started with a degraded message
	case "stopped":
		eventType = "stopped"
	}

	event := map[string]interface{}{
		"type": "startup_event",
		"startup_event": map[string]interface{}{
			"timestamp": time.Now().Format(time.RFC3339Nano),
			"plugin":    pluginName,
			"event":     eventType,
			"message":   message,
		},
		"time": time.Now(),
	}

	data, _ := json.Marshal(event)

	for conn := range ws.wsClients {
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			ws.logger.Printf("Error broadcasting startup event: %v", err)
		}
	}
}

// monitorPluginStatus polls plugin health status periodically
func (ws *Plugin) monitorPluginStatus(ctx context.Context) {
	// Poll plugin health every 5 seconds
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Get initial status immediately
	ws.pollPluginHealth()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ws.pollPluginHealth()
		}
	}
}

// pollPluginHealth checks the current health of all plugins directly
func (ws *Plugin) pollPluginHealth() {
	if ws.registry == nil {
		return
	}

	plugins := ws.registry.List()

	// Process all plugins except ourselves
	for _, p := range plugins {
		pluginName := p.Info().Name

		// Skip ourselves to avoid circular dependency
		if pluginName == "webserver" {
			continue
		}

		health := p.Health()
		message := health.Message

		var status string
		switch health.Status {
		case plugin.HealthStatusHealthy:
			status = statusReady
		case plugin.HealthStatusDegraded:
			status = "degraded"
		case plugin.HealthStatusUnhealthy:
			status = "failed"
		default:
			status = "starting"
		}

		ws.updatePluginStatus(pluginName, status, message)

		// Enable API for plugins that are ready or degraded
		if status == statusReady || status == "degraded" {
			ws.enableAPIForPlugin(pluginName)
		}
	}

	// Add our own health status
	ourHealth := ws.Health()
	var ourStatus string
	switch ourHealth.Status {
	case plugin.HealthStatusHealthy:
		ourStatus = statusReady
	case plugin.HealthStatusDegraded:
		ourStatus = "degraded"
	case plugin.HealthStatusUnhealthy:
		ourStatus = "failed"
	default:
		ourStatus = "starting"
	}

	ws.updatePluginStatus("webserver", ourStatus, ourHealth.Message)
	ws.enableAPIForPlugin("webserver")
}

// updatePluginStatus updates the status of a plugin
func (ws *Plugin) updatePluginStatus(name, status, message string) {
	pluginStatus := PluginStatus{
		Name:      name,
		Status:    status,
		Message:   message,
		StartedAt: time.Now(),
	}

	// Update status under lock
	ws.mu.Lock()
	previousStatus := ""
	if prev, exists := ws.startupStatus[name]; exists {
		previousStatus = prev.Status
	}
	ws.startupStatus[name] = pluginStatus
	log.Printf("[WebServer] Updated %s status to %s (total plugins: %d)\n", name, status, len(ws.startupStatus))
	// Make a copy of the status for broadcasting (to avoid deadlock)
	currentStatus := make(map[string]PluginStatus)
	for n, s := range ws.startupStatus {
		currentStatus[n] = s
	}
	ws.mu.Unlock()

	// Broadcast update to WebSocket clients (outside the lock to avoid deadlock)
	ws.broadcastStatusSnapshot(currentStatus)

	// Also broadcast as a startup event if status changed
	if previousStatus != status {
		ws.broadcastStartupEvent(name, status, message)
	}
}

// enableAPIForPlugin marks API endpoints as ready for a plugin
func (ws *Plugin) enableAPIForPlugin(pluginName string) {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	// Skip if already enabled
	if ws.readyAPIs[pluginName] {
		return
	}

	ws.logger.Printf("Enabling API for plugin: %s", pluginName)

	// Mark the API as ready
	ws.readyAPIs[pluginName] = true
}

// pluginStatesHandler returns the current state of all plugins
func (ws *Plugin) pluginStatesHandler(c *fiber.Ctx) error {
	if ws.registry == nil {
		return c.JSON(fiber.Map{
			"error": "Plugin registry not available",
			"time":  time.Now(),
		})
	}

	plugins := ws.registry.List()
	states := make(map[string]interface{})

	for _, p := range plugins {
		// Check if plugin implements GetState method
		if stateGetter, ok := p.(interface{ GetState() plugin.PluginState }); ok {
			states[p.Info().Name] = map[string]interface{}{
				"state":  stateGetter.GetState(),
				"health": p.Health(),
			}
		} else {
			// Fallback to health-based state inference
			health := p.Health()
			var inferredState string
			switch health.Status {
			case plugin.HealthStatusHealthy:
				inferredState = "running"
			case plugin.HealthStatusUnhealthy:
				inferredState = "error"
			default:
				inferredState = "unknown"
			}

			states[p.Info().Name] = map[string]interface{}{
				"state":  inferredState,
				"health": health,
				"note":   "State inferred from health (plugin doesn't support state API)",
			}
		}
	}

	return c.JSON(fiber.Map{
		"plugin_states": states,
		"time":          time.Now(),
	})
}

// handleStateTransition handles plugin state transition events for logging
func (ws *Plugin) handleStateTransition(event plugin.Event) {
	// Extract state transition data
	data, ok := event.Data.(map[string]interface{})
	if !ok {
		return
	}

	from, _ := data["from"].(string)
	to, _ := data["to"].(string)
	message, _ := data["message"].(string)

	// Write to orchestrator startup log (we'll need to get the log file path)
	// For now, just log it normally
	ws.logger.Printf("[PLUGIN] %s: %s → %s (%s)", event.Source, from, to, message)
}

// placeholderHandler returns a placeholder handler for APIs
func (ws *Plugin) placeholderHandler(apiName string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"api":     apiName,
			"status":  "placeholder",
			"message": fmt.Sprintf("%s API endpoint - implementation pending", apiName),
			"time":    time.Now(),
		})
	}
}

// setupDashboard sets up the dashboard static files
func (ws *Plugin) setupDashboard() {
	// Check if React build exists
	if _, err := os.Stat("./web/build/index.html"); err == nil {
		// Serve React build in production
		ws.server.Static("/static", "./web/build/static")
		ws.server.Static("/assets", "./web/build/assets")

		// Serve index.html for all non-API routes (React Router)
		ws.server.Get("/*", func(c *fiber.Ctx) error {
			// Don't serve index.html for API routes
			if strings.HasPrefix(c.Path(), "/api") ||
				strings.HasPrefix(c.Path(), "/ws") ||
				strings.HasPrefix(c.Path(), "/health") ||
				strings.HasPrefix(c.Path(), "/status") ||
				strings.HasPrefix(c.Path(), "/startup") {
				return c.Next()
			}
			return c.SendFile("./web/build/index.html")
		})
	} else {
		// Development mode - serve the simple HTML
		ws.server.Get("/", func(c *fiber.Ctx) error {
			c.Set("Content-Type", "text/html")
			return c.SendString(dashboardHTML)
		})

		// Add a note about building the React app
		ws.server.Get("/react-status", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{
				"status":  "development",
				"message": "React app not built. Run 'cd web && npm install && npm run build' to build the dashboard.",
			})
		})
	}
}

// Simple dashboard HTML for development
const dashboardHTML = `<!DOCTYPE html>
<html>
<head>
    <title>Blackhole Network Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #333; }
        .status-card { background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .plugin-status { display: flex; justify-content: space-between; align-items: center; margin: 10px 0; }
        .status-badge { padding: 5px 15px; border-radius: 20px; font-size: 14px; }
        .starting { background: #ffa500; color: white; }
        .ready { background: #4caf50; color: white; }
        .failed { background: #f44336; color: white; }
        .progress-bar { width: 100%; height: 20px; background: #e0e0e0; border-radius: 10px; overflow: hidden; margin: 5px 0; }
        .progress-fill { height: 100%; background: #2196f3; transition: width 0.3s ease; }
        #ws-status { position: fixed; top: 20px; right: 20px; padding: 10px 20px; border-radius: 5px; }
        .ws-connected { background: #4caf50; color: white; }
        .ws-disconnected { background: #f44336; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Blackhole Network Node</h1>
        <div id="ws-status" class="ws-disconnected">Disconnected</div>

        <div class="status-card">
            <h2>Startup Progress</h2>
            <div class="progress-bar">
                <div id="overall-progress" class="progress-fill" style="width: 0%"></div>
            </div>
            <p id="progress-text">0% Complete</p>
        </div>

        <div class="status-card">
            <h2>Plugin Status</h2>
            <div id="plugin-list"></div>
        </div>

        <div class="status-card">
            <h2>System Information</h2>
            <div id="system-info">Loading...</div>
        </div>
    </div>

    <script>
        let ws = null;
        let reconnectInterval = null;

        function connect() {
            ws = new WebSocket('ws://localhost:8080/ws');

            ws.onopen = () => {
                document.getElementById('ws-status').textContent = 'Connected';
                document.getElementById('ws-status').className = 'ws-connected';
                if (reconnectInterval) {
                    clearInterval(reconnectInterval);
                    reconnectInterval = null;
                }
            };

            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                if (data.type === 'startup_status' || data.type === 'plugin_update') {
                    updatePluginStatus(data);
                }
            };

            ws.onclose = () => {
                document.getElementById('ws-status').textContent = 'Disconnected';
                document.getElementById('ws-status').className = 'ws-disconnected';
                if (!reconnectInterval) {
                    reconnectInterval = setInterval(connect, 5000);
                }
            };
        }

        function updatePluginStatus(data) {
            const plugins = data.plugins || {};
            const pluginList = document.getElementById('plugin-list');
            pluginList.innerHTML = '';

            let readyCount = 0;
            let totalCount = 0;

            for (const [name, status] of Object.entries(plugins)) {
                const div = document.createElement('div');
                div.className = 'plugin-status';
                div.innerHTML = '<div>' +
                    '<strong>' + name + '</strong>' +
                    '<div style="color: #666; font-size: 14px;">' + (status.message || '') + '</div>' +
                    '</div>' +
                    '<span class="status-badge ' + status.status + '">' + status.status + '</span>';
                pluginList.appendChild(div);

                totalCount++;
                if (status.status === 'ready') {
                    readyCount++;
                }
            }

            // Update overall progress based on ready plugins
            if (totalCount > 0) {
                const overallProgress = Math.round((readyCount * 100) / totalCount);
                document.getElementById('overall-progress').style.width = overallProgress + '%';
                document.getElementById('progress-text').textContent = overallProgress + '% Complete';
            }
        }

        async function loadSystemInfo() {
            try {
                const response = await fetch('/status');
                const data = await response.json();
                document.getElementById('system-info').innerHTML =
                    '<p><strong>Status:</strong> ' + data.status + '</p>' +
                    '<p><strong>Ready APIs:</strong> ' + (Object.keys(data.ready_apis || {}).join(', ') || 'None') + '</p>' +
                    '<p><strong>Time:</strong> ' + new Date(data.time).toLocaleString() + '</p>';
            } catch (err) {
                document.getElementById('system-info').textContent = 'Failed to load system info';
            }
        }

        // Initial connection
        connect();
        loadSystemInfo();
        setInterval(loadSystemInfo, 5000);
    </script>
</body>
</html>`

// Ensure Plugin implements the Plugin interface
var _ plugin.Plugin = (*Plugin)(nil)
