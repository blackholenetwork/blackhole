# U47: Monitoring and Analytics

## Overview
Comprehensive network monitoring, usage analytics, performance metrics collection, and business intelligence system for BlackHole distributed storage network.

## Implementation

### Core Types

```go
package analytics

import (
    "context"
    "sync"
    "time"
)

// MetricType defines different types of metrics
type MetricType int

const (
    MetricNetworkThroughput MetricType = iota
    MetricStorageUtilization
    MetricNodePerformance
    MetricUserActivity
    MetricTransactionVolume
    MetricRevenueTracking
    MetricErrorRate
    MetricLatency
    MetricBandwidthUsage
    MetricCostAnalysis
    MetricPredictiveMetrics
)

// Metric represents a single metric data point
type Metric struct {
    ID        string
    Type      MetricType
    Name      string
    Value     float64
    Unit      string
    Labels    map[string]string
    Timestamp time.Time
    NodeID    string
    UserID    string
    Context   map[string]interface{}
}

// TimeSeries represents a time series of metrics
type TimeSeries struct {
    MetricName  string
    Labels      map[string]string
    DataPoints  []DataPoint
    Granularity time.Duration
    StartTime   time.Time
    EndTime     time.Time
}

// DataPoint represents a single data point in a time series
type DataPoint struct {
    Timestamp time.Time
    Value     float64
    Labels    map[string]string
}

// Dashboard represents a monitoring dashboard
type Dashboard struct {
    ID          string
    Name        string
    Description string
    Panels      []Panel
    Filters     []Filter
    TimeRange   TimeRange
    RefreshRate time.Duration
    Owner       string
    Public      bool
    Created     time.Time
    Updated     time.Time
}

// Panel represents a dashboard panel
type Panel struct {
    ID          string
    Title       string
    Type        PanelType
    Query       string
    Metrics     []string
    Visualization VisualizationType
    Config      map[string]interface{}
    Position    Position
    Size        Size
}

// PanelType defines panel types
type PanelType int

const (
    PanelGraph PanelType = iota
    PanelStat
    PanelTable
    PanelHeatmap
    PanelPieChart
    PanelBarChart
    PanelGauge
    PanelAlert
)

// VisualizationType defines visualization types
type VisualizationType int

const (
    VisLine VisualizationType = iota
    VisBar
    VisArea
    VisPie
    VisScatter
    VisHeatmap
    VisGauge
    VisTable
)

// Position represents panel position
type Position struct {
    X int
    Y int
}

// Size represents panel size
type Size struct {
    Width  int
    Height int
}

// Filter represents a dashboard filter
type Filter struct {
    Name     string
    Type     FilterType
    Values   []string
    Default  string
    Required bool
}

// FilterType defines filter types
type FilterType int

const (
    FilterDropdown FilterType = iota
    FilterText
    FilterDateRange
    FilterNumericRange
)

// TimeRange represents a time range
type TimeRange struct {
    Start time.Time
    End   time.Time
}

// Alert represents a monitoring alert
type Alert struct {
    ID          string
    Name        string
    Description string
    Query       string
    Condition   AlertCondition
    Threshold   float64
    Severity    AlertSeverity
    Enabled     bool
    Frequency   time.Duration
    Recipients  []string
    Created     time.Time
    Updated     time.Time
    LastFired   time.Time
    FireCount   int
}

// AlertCondition defines alert condition types
type AlertCondition int

const (
    ConditionAbove AlertCondition = iota
    ConditionBelow
    ConditionEqual
    ConditionChange
    ConditionAnomaly
)

// AlertSeverity defines alert severity levels
type AlertSeverity int

const (
    SeverityInfo AlertSeverity = iota
    SeverityWarning
    SeverityError
    SeverityCritical
)
```

### Analytics Engine

```go
// AnalyticsEngine is the main analytics and monitoring engine
type AnalyticsEngine struct {
    config          AnalyticsConfig
    storage         AnalyticsStorage
    metricCollector *MetricCollector
    alertManager    *AlertManager
    dashboardMgr    *DashboardManager
    reportGenerator *ReportGenerator
    predictor       *PredictiveAnalytics
    eventChan       chan AnalyticsEvent
    subscribers     []chan AnalyticsUpdate
    mu              sync.RWMutex
    stopCh          chan struct{}
}

// AnalyticsConfig configures the analytics engine
type AnalyticsConfig struct {
    RetentionPolicy  map[MetricType]time.Duration
    AggregationRules map[MetricType]AggregationRule
    SamplingRate     float64
    BatchSize        int
    FlushInterval    time.Duration
    AlertEnabled     bool
    PredictionEnabled bool
    ReportSchedule   map[string]time.Duration
    ExportTargets    []ExportTarget
}

// AggregationRule defines how metrics should be aggregated
type AggregationRule struct {
    Function   AggregationFunction
    Window     time.Duration
    Buckets    int
    Percentiles []float64
}

// AggregationFunction defines aggregation functions
type AggregationFunction int

const (
    AggSum AggregationFunction = iota
    AggAvg
    AggMin
    AggMax
    AggCount
    AggPercentile
    AggStdDev
    AggRate
)

// ExportTarget represents a data export target
type ExportTarget struct {
    Type     ExportType
    Endpoint string
    Interval time.Duration
    Format   ExportFormat
    Filters  []string
}

// ExportType defines export target types
type ExportType int

const (
    ExportPrometheus ExportType = iota
    ExportInfluxDB
    ExportElasticsearch
    ExportS3
    ExportWebhook
)

// ExportFormat defines export formats
type ExportFormat int

const (
    FormatJSON ExportFormat = iota
    FormatCSV
    FormatParquet
    FormatAvro
)

// AnalyticsEvent represents an analytics event
type AnalyticsEvent struct {
    Type      EventType
    Timestamp time.Time
    Data      interface{}
    Source    string
}

// EventType defines analytics event types
type EventType int

const (
    EventMetricIngested EventType = iota
    EventAlertTriggered
    EventDashboardViewed
    EventReportGenerated
    EventAnomalyDetected
    EventPredictionUpdated
)

// AnalyticsUpdate represents an analytics update notification
type AnalyticsUpdate struct {
    Type      UpdateType
    Message   string
    Data      interface{}
    Timestamp time.Time
}

// UpdateType defines update types
type UpdateType int

const (
    UpdateMetricAlert UpdateType = iota
    UpdateSystemStatus
    UpdatePerformanceReport
    UpdateAnomalyDetection
)

// NewAnalyticsEngine creates a new analytics engine
func NewAnalyticsEngine(config AnalyticsConfig, storage AnalyticsStorage) *AnalyticsEngine {
    return &AnalyticsEngine{
        config:          config,
        storage:         storage,
        metricCollector: NewMetricCollector(config, storage),
        alertManager:    NewAlertManager(config, storage),
        dashboardMgr:    NewDashboardManager(storage),
        reportGenerator: NewReportGenerator(config, storage),
        predictor:       NewPredictiveAnalytics(config, storage),
        eventChan:       make(chan AnalyticsEvent, 10000),
        subscribers:     make([]chan AnalyticsUpdate, 0),
        stopCh:          make(chan struct{}),
    }
}

// Start begins the analytics engine
func (ae *AnalyticsEngine) Start(ctx context.Context) error {
    // Start components
    if err := ae.metricCollector.Start(ctx); err != nil {
        return err
    }
    
    if err := ae.alertManager.Start(ctx); err != nil {
        return err
    }
    
    if err := ae.reportGenerator.Start(ctx); err != nil {
        return err
    }
    
    if ae.config.PredictionEnabled {
        if err := ae.predictor.Start(ctx); err != nil {
            return err
        }
    }
    
    // Start event processor
    go ae.processEvents(ctx)
    
    return nil
}

// IngestMetric ingests a metric into the analytics system
func (ae *AnalyticsEngine) IngestMetric(metric Metric) error {
    // Validate metric
    if err := ae.validateMetric(metric); err != nil {
        return err
    }
    
    // Apply sampling if configured
    if ae.config.SamplingRate < 1.0 {
        if rand.Float64() > ae.config.SamplingRate {
            return nil // Skip this metric
        }
    }
    
    // Send to collector
    return ae.metricCollector.Collect(metric)
}

// IngestBatch ingests multiple metrics in a batch
func (ae *AnalyticsEngine) IngestBatch(metrics []Metric) error {
    validMetrics := make([]Metric, 0, len(metrics))
    
    for _, metric := range metrics {
        if err := ae.validateMetric(metric); err == nil {
            if ae.config.SamplingRate >= 1.0 || rand.Float64() <= ae.config.SamplingRate {
                validMetrics = append(validMetrics, metric)
            }
        }
    }
    
    return ae.metricCollector.CollectBatch(validMetrics)
}

// QueryMetrics queries metrics from storage
func (ae *AnalyticsEngine) QueryMetrics(query MetricQuery) (*QueryResult, error) {
    return ae.storage.Query(query)
}

// GetTimeSeries retrieves time series data
func (ae *AnalyticsEngine) GetTimeSeries(query TimeSeriesQuery) (*TimeSeries, error) {
    return ae.storage.GetTimeSeries(query)
}

// CreateDashboard creates a new dashboard
func (ae *AnalyticsEngine) CreateDashboard(dashboard Dashboard) error {
    return ae.dashboardMgr.Create(dashboard)
}

// GetDashboard retrieves a dashboard
func (ae *AnalyticsEngine) GetDashboard(id string) (*Dashboard, error) {
    return ae.dashboardMgr.Get(id)
}

// CreateAlert creates a new alert
func (ae *AnalyticsEngine) CreateAlert(alert Alert) error {
    return ae.alertManager.Create(alert)
}

// GenerateReport generates a report
func (ae *AnalyticsEngine) GenerateReport(request ReportRequest) (*Report, error) {
    return ae.reportGenerator.Generate(request)
}

// GetPrediction gets predictive analytics
func (ae *AnalyticsEngine) GetPrediction(request PredictionRequest) (*Prediction, error) {
    if !ae.config.PredictionEnabled {
        return nil, ErrPredictionDisabled
    }
    return ae.predictor.Predict(request)
}

// validateMetric validates a metric before ingestion
func (ae *AnalyticsEngine) validateMetric(metric Metric) error {
    if metric.Name == "" {
        return ErrMissingMetricName
    }
    
    if metric.Timestamp.IsZero() {
        metric.Timestamp = time.Now()
    }
    
    if math.IsNaN(metric.Value) || math.IsInf(metric.Value, 0) {
        return ErrInvalidMetricValue
    }
    
    return nil
}

// processEvents processes analytics events
func (ae *AnalyticsEngine) processEvents(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            return
        case event := <-ae.eventChan:
            ae.handleEvent(event)
        }
    }
}

// handleEvent handles a single analytics event
func (ae *AnalyticsEngine) handleEvent(event AnalyticsEvent) {
    switch event.Type {
    case EventMetricIngested:
        // Check for alerts
        metric := event.Data.(Metric)
        ae.alertManager.CheckMetric(metric)
        
    case EventAlertTriggered:
        // Notify subscribers
        alert := event.Data.(Alert)
        ae.notifySubscribers(AnalyticsUpdate{
            Type:      UpdateMetricAlert,
            Message:   fmt.Sprintf("Alert triggered: %s", alert.Name),
            Data:      alert,
            Timestamp: time.Now(),
        })
        
    case EventAnomalyDetected:
        // Handle anomaly detection
        anomaly := event.Data.(Anomaly)
        ae.handleAnomaly(anomaly)
    }
}
```

### Metric Collector

```go
// MetricCollector collects and stores metrics
type MetricCollector struct {
    config    AnalyticsConfig
    storage   AnalyticsStorage
    buffer    []Metric
    mu        sync.Mutex
    stopCh    chan struct{}
}

// NewMetricCollector creates a new metric collector
func NewMetricCollector(config AnalyticsConfig, storage AnalyticsStorage) *MetricCollector {
    return &MetricCollector{
        config:  config,
        storage: storage,
        buffer:  make([]Metric, 0, config.BatchSize),
        stopCh:  make(chan struct{}),
    }
}

// Start begins metric collection
func (mc *MetricCollector) Start(ctx context.Context) error {
    ticker := time.NewTicker(mc.config.FlushInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return mc.flush()
        case <-mc.stopCh:
            return mc.flush()
        case <-ticker.C:
            if err := mc.flush(); err != nil {
                // Log error but continue
                continue
            }
        }
    }
}

// Collect collects a single metric
func (mc *MetricCollector) Collect(metric Metric) error {
    mc.mu.Lock()
    defer mc.mu.Unlock()
    
    metric.ID = generateMetricID()
    if metric.Timestamp.IsZero() {
        metric.Timestamp = time.Now()
    }
    
    mc.buffer = append(mc.buffer, metric)
    
    if len(mc.buffer) >= mc.config.BatchSize {
        return mc.flushUnlocked()
    }
    
    return nil
}

// CollectBatch collects multiple metrics
func (mc *MetricCollector) CollectBatch(metrics []Metric) error {
    mc.mu.Lock()
    defer mc.mu.Unlock()
    
    for i := range metrics {
        metrics[i].ID = generateMetricID()
        if metrics[i].Timestamp.IsZero() {
            metrics[i].Timestamp = time.Now()
        }
    }
    
    mc.buffer = append(mc.buffer, metrics...)
    
    if len(mc.buffer) >= mc.config.BatchSize {
        return mc.flushUnlocked()
    }
    
    return nil
}

// flush flushes buffered metrics to storage
func (mc *MetricCollector) flush() error {
    mc.mu.Lock()
    defer mc.mu.Unlock()
    return mc.flushUnlocked()
}

// flushUnlocked flushes without locking (assumes already locked)
func (mc *MetricCollector) flushUnlocked() error {
    if len(mc.buffer) == 0 {
        return nil
    }
    
    if err := mc.storage.StoreMetrics(mc.buffer); err != nil {
        return err
    }
    
    // Apply aggregation rules
    mc.applyAggregation(mc.buffer)
    
    mc.buffer = mc.buffer[:0]
    return nil
}

// applyAggregation applies aggregation rules to metrics
func (mc *MetricCollector) applyAggregation(metrics []Metric) {
    for metricType, rule := range mc.config.AggregationRules {
        filtered := mc.filterMetricsByType(metrics, metricType)
        if len(filtered) == 0 {
            continue
        }
        
        aggregated := mc.aggregateMetrics(filtered, rule)
        mc.storage.StoreAggregatedMetrics(aggregated)
    }
}

// filterMetricsByType filters metrics by type
func (mc *MetricCollector) filterMetricsByType(metrics []Metric, metricType MetricType) []Metric {
    filtered := make([]Metric, 0)
    for _, metric := range metrics {
        if metric.Type == metricType {
            filtered = append(filtered, metric)
        }
    }
    return filtered
}

// aggregateMetrics aggregates metrics according to rules
func (mc *MetricCollector) aggregateMetrics(metrics []Metric, rule AggregationRule) []AggregatedMetric {
    // Group metrics by time windows
    windows := mc.groupByTimeWindows(metrics, rule.Window)
    
    aggregated := make([]AggregatedMetric, 0, len(windows))
    
    for windowStart, windowMetrics := range windows {
        agg := AggregatedMetric{
            MetricType:  windowMetrics[0].Type,
            WindowStart: windowStart,
            WindowEnd:   windowStart.Add(rule.Window),
            Count:       len(windowMetrics),
        }
        
        values := make([]float64, len(windowMetrics))
        for i, metric := range windowMetrics {
            values[i] = metric.Value
        }
        
        // Apply aggregation function
        switch rule.Function {
        case AggSum:
            agg.Value = mc.sum(values)
        case AggAvg:
            agg.Value = mc.avg(values)
        case AggMin:
            agg.Value = mc.min(values)
        case AggMax:
            agg.Value = mc.max(values)
        case AggCount:
            agg.Value = float64(len(values))
        case AggStdDev:
            agg.Value = mc.stddev(values)
        case AggPercentile:
            agg.Percentiles = mc.calculatePercentiles(values, rule.Percentiles)
        }
        
        aggregated = append(aggregated, agg)
    }
    
    return aggregated
}

// groupByTimeWindows groups metrics by time windows
func (mc *MetricCollector) groupByTimeWindows(metrics []Metric, window time.Duration) map[time.Time][]Metric {
    windows := make(map[time.Time][]Metric)
    
    for _, metric := range metrics {
        windowStart := metric.Timestamp.Truncate(window)
        windows[windowStart] = append(windows[windowStart], metric)
    }
    
    return windows
}

// Mathematical aggregation functions
func (mc *MetricCollector) sum(values []float64) float64 {
    var sum float64
    for _, v := range values {
        sum += v
    }
    return sum
}

func (mc *MetricCollector) avg(values []float64) float64 {
    if len(values) == 0 {
        return 0
    }
    return mc.sum(values) / float64(len(values))
}

func (mc *MetricCollector) min(values []float64) float64 {
    if len(values) == 0 {
        return 0
    }
    min := values[0]
    for _, v := range values[1:] {
        if v < min {
            min = v
        }
    }
    return min
}

func (mc *MetricCollector) max(values []float64) float64 {
    if len(values) == 0 {
        return 0
    }
    max := values[0]
    for _, v := range values[1:] {
        if v > max {
            max = v
        }
    }
    return max
}

func (mc *MetricCollector) stddev(values []float64) float64 {
    if len(values) <= 1 {
        return 0
    }
    
    mean := mc.avg(values)
    var variance float64
    
    for _, v := range values {
        diff := v - mean
        variance += diff * diff
    }
    
    variance /= float64(len(values) - 1)
    return math.Sqrt(variance)
}

func (mc *MetricCollector) calculatePercentiles(values []float64, percentiles []float64) map[float64]float64 {
    sort.Float64s(values)
    result := make(map[float64]float64)
    
    for _, p := range percentiles {
        index := int(p/100.0 * float64(len(values)))
        if index >= len(values) {
            index = len(values) - 1
        }
        result[p] = values[index]
    }
    
    return result
}
```

### Alert Manager

```go
// AlertManager manages monitoring alerts
type AlertManager struct {
    config  AnalyticsConfig
    storage AnalyticsStorage
    alerts  map[string]*Alert
    rules   []AlertRule
    mu      sync.RWMutex
    stopCh  chan struct{}
}

// AlertRule represents an alert rule
type AlertRule struct {
    ID        string
    MetricType MetricType
    Condition AlertCondition
    Threshold float64
    Window    time.Duration
    Frequency time.Duration
    Alert     Alert
}

// NewAlertManager creates a new alert manager
func NewAlertManager(config AnalyticsConfig, storage AnalyticsStorage) *AlertManager {
    return &AlertManager{
        config:  config,
        storage: storage,
        alerts:  make(map[string]*Alert),
        rules:   make([]AlertRule, 0),
        stopCh:  make(chan struct{}),
    }
}

// Start begins alert management
func (am *AlertManager) Start(ctx context.Context) error {
    if !am.config.AlertEnabled {
        return nil
    }
    
    // Load existing alerts
    if err := am.loadAlerts(); err != nil {
        return err
    }
    
    // Start alert evaluation loop
    go am.evaluateAlerts(ctx)
    
    return nil
}

// Create creates a new alert
func (am *AlertManager) Create(alert Alert) error {
    am.mu.Lock()
    defer am.mu.Unlock()
    
    alert.ID = generateAlertID()
    alert.Created = time.Now()
    alert.Updated = time.Now()
    
    am.alerts[alert.ID] = &alert
    
    return am.storage.StoreAlert(alert)
}

// Update updates an existing alert
func (am *AlertManager) Update(alert Alert) error {
    am.mu.Lock()
    defer am.mu.Unlock()
    
    existing, exists := am.alerts[alert.ID]
    if !exists {
        return ErrAlertNotFound
    }
    
    alert.Created = existing.Created
    alert.Updated = time.Now()
    
    am.alerts[alert.ID] = &alert
    
    return am.storage.StoreAlert(alert)
}

// Delete deletes an alert
func (am *AlertManager) Delete(id string) error {
    am.mu.Lock()
    defer am.mu.Unlock()
    
    delete(am.alerts, id)
    
    return am.storage.DeleteAlert(id)
}

// CheckMetric checks if a metric triggers any alerts
func (am *AlertManager) CheckMetric(metric Metric) {
    am.mu.RLock()
    defer am.mu.RUnlock()
    
    for _, alert := range am.alerts {
        if !alert.Enabled {
            continue
        }
        
        if am.shouldEvaluateAlert(alert, metric) {
            go am.evaluateAlert(alert, metric)
        }
    }
}

// evaluateAlerts periodically evaluates all alerts
func (am *AlertManager) evaluateAlerts(ctx context.Context) {
    ticker := time.NewTicker(time.Minute)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-am.stopCh:
            return
        case <-ticker.C:
            am.evaluateAllAlerts()
        }
    }
}

// evaluateAllAlerts evaluates all enabled alerts
func (am *AlertManager) evaluateAllAlerts() {
    am.mu.RLock()
    alerts := make([]*Alert, 0, len(am.alerts))
    for _, alert := range am.alerts {
        if alert.Enabled {
            alerts = append(alerts, alert)
        }
    }
    am.mu.RUnlock()
    
    for _, alert := range alerts {
        if time.Since(alert.LastFired) >= alert.Frequency {
            go am.evaluateAlertQuery(alert)
        }
    }
}

// evaluateAlert evaluates a specific alert against a metric
func (am *AlertManager) evaluateAlert(alert *Alert, metric Metric) {
    triggered := false
    
    switch alert.Condition {
    case ConditionAbove:
        triggered = metric.Value > alert.Threshold
    case ConditionBelow:
        triggered = metric.Value < alert.Threshold
    case ConditionEqual:
        triggered = math.Abs(metric.Value-alert.Threshold) < 0.001
    }
    
    if triggered {
        am.fireAlert(alert, metric)
    }
}

// evaluateAlertQuery evaluates an alert using its query
func (am *AlertManager) evaluateAlertQuery(alert *Alert) {
    query := MetricQuery{
        Query:     alert.Query,
        StartTime: time.Now().Add(-time.Hour),
        EndTime:   time.Now(),
    }
    
    result, err := am.storage.Query(query)
    if err != nil {
        return
    }
    
    if len(result.Metrics) == 0 {
        return
    }
    
    // Evaluate condition against query result
    value := am.calculateQueryValue(result)
    
    triggered := false
    switch alert.Condition {
    case ConditionAbove:
        triggered = value > alert.Threshold
    case ConditionBelow:
        triggered = value < alert.Threshold
    case ConditionEqual:
        triggered = math.Abs(value-alert.Threshold) < 0.001
    case ConditionAnomaly:
        triggered = am.detectAnomaly(result, alert)
    }
    
    if triggered {
        am.fireAlertFromQuery(alert, value, result)
    }
}

// fireAlert fires an alert
func (am *AlertManager) fireAlert(alert *Alert, metric Metric) {
    am.mu.Lock()
    alert.LastFired = time.Now()
    alert.FireCount++
    am.mu.Unlock()
    
    notification := AlertNotification{
        Alert:     *alert,
        Metric:    metric,
        Timestamp: time.Now(),
        Message:   am.generateAlertMessage(alert, metric.Value),
    }
    
    am.sendNotification(notification)
    am.storage.StoreAlert(*alert)
}

// fireAlertFromQuery fires an alert from query evaluation
func (am *AlertManager) fireAlertFromQuery(alert *Alert, value float64, result *QueryResult) {
    am.mu.Lock()
    alert.LastFired = time.Now()
    alert.FireCount++
    am.mu.Unlock()
    
    notification := AlertNotification{
        Alert:     *alert,
        Value:     value,
        Timestamp: time.Now(),
        Message:   am.generateAlertMessage(alert, value),
        Context:   result,
    }
    
    am.sendNotification(notification)
    am.storage.StoreAlert(*alert)
}

// sendNotification sends alert notification to recipients
func (am *AlertManager) sendNotification(notification AlertNotification) {
    for _, recipient := range notification.Alert.Recipients {
        go am.deliverNotification(recipient, notification)
    }
}

// deliverNotification delivers notification to a specific recipient
func (am *AlertManager) deliverNotification(recipient string, notification AlertNotification) {
    // Implementation would depend on notification method (email, webhook, etc.)
    // For now, just log the notification
    fmt.Printf("Alert: %s - %s (Value: %.2f, Threshold: %.2f)\n",
        notification.Alert.Name,
        notification.Message,
        notification.Value,
        notification.Alert.Threshold)
}

// calculateQueryValue calculates a single value from query result
func (am *AlertManager) calculateQueryValue(result *QueryResult) float64 {
    if len(result.Metrics) == 0 {
        return 0
    }
    
    var sum float64
    for _, metric := range result.Metrics {
        sum += metric.Value
    }
    
    return sum / float64(len(result.Metrics))
}

// detectAnomaly detects anomalies in query results
func (am *AlertManager) detectAnomaly(result *QueryResult, alert *Alert) bool {
    if len(result.Metrics) < 10 {
        return false // Need enough data points
    }
    
    values := make([]float64, len(result.Metrics))
    for i, metric := range result.Metrics {
        values[i] = metric.Value
    }
    
    // Calculate z-score for anomaly detection
    mean := am.calculateMean(values)
    stddev := am.calculateStdDev(values, mean)
    
    if stddev == 0 {
        return false
    }
    
    latestValue := values[len(values)-1]
    zScore := math.Abs((latestValue - mean) / stddev)
    
    // Threshold for anomaly (e.g., 2 standard deviations)
    return zScore > 2.0
}

// shouldEvaluateAlert checks if an alert should be evaluated for a metric
func (am *AlertManager) shouldEvaluateAlert(alert *Alert, metric Metric) bool {
    // Check if alert query matches the metric
    // This is a simplified check - in practice, you'd parse the query
    return strings.Contains(alert.Query, string(metric.Type)) ||
           strings.Contains(alert.Query, metric.Name)
}

// generateAlertMessage generates a human-readable alert message
func (am *AlertManager) generateAlertMessage(alert *Alert, value float64) string {
    condition := ""
    switch alert.Condition {
    case ConditionAbove:
        condition = "above"
    case ConditionBelow:
        condition = "below"
    case ConditionEqual:
        condition = "equal to"
    case ConditionAnomaly:
        condition = "anomalous compared to"
    }
    
    return fmt.Sprintf("%s: Value %.2f is %s threshold %.2f",
        alert.Name, value, condition, alert.Threshold)
}

// loadAlerts loads existing alerts from storage
func (am *AlertManager) loadAlerts() error {
    alerts, err := am.storage.LoadAlerts()
    if err != nil {
        return err
    }
    
    am.mu.Lock()
    defer am.mu.Unlock()
    
    for _, alert := range alerts {
        am.alerts[alert.ID] = &alert
    }
    
    return nil
}

// Mathematical helper functions
func (am *AlertManager) calculateMean(values []float64) float64 {
    var sum float64
    for _, v := range values {
        sum += v
    }
    return sum / float64(len(values))
}

func (am *AlertManager) calculateStdDev(values []float64, mean float64) float64 {
    var variance float64
    for _, v := range values {
        diff := v - mean
        variance += diff * diff
    }
    variance /= float64(len(values) - 1)
    return math.Sqrt(variance)
}
```

### Report Generator

```go
// ReportGenerator generates analytics reports
type ReportGenerator struct {
    config  AnalyticsConfig
    storage AnalyticsStorage
    templates map[string]ReportTemplate
    scheduler *ReportScheduler
    mu        sync.RWMutex
}

// ReportTemplate defines a report template
type ReportTemplate struct {
    ID          string
    Name        string
    Description string
    Sections    []ReportSection
    Format      ReportFormat
    Parameters  []ReportParameter
}

// ReportSection represents a section in a report
type ReportSection struct {
    Title       string
    Type        SectionType
    Query       string
    Metrics     []string
    Aggregation AggregationFunction
    Visualization VisualizationType
    Config      map[string]interface{}
}

// SectionType defines report section types
type SectionType int

const (
    SectionSummary SectionType = iota
    SectionChart
    SectionTable
    SectionMetrics
    SectionAnalysis
    SectionRecommendations
)

// ReportFormat defines report output formats
type ReportFormat int

const (
    ReportHTML ReportFormat = iota
    ReportPDF
    ReportCSV
    ReportJSON
    ReportExcel
)

// ReportParameter defines a report parameter
type ReportParameter struct {
    Name         string
    Type         ParameterType
    Required     bool
    DefaultValue interface{}
    Description  string
}

// ParameterType defines parameter types
type ParameterType int

const (
    ParamString ParameterType = iota
    ParamNumber
    ParamDate
    ParamBoolean
    ParamList
)

// ReportRequest represents a report generation request
type ReportRequest struct {
    TemplateID  string
    Parameters  map[string]interface{}
    TimeRange   TimeRange
    Format      ReportFormat
    Recipients  []string
    Schedule    *ReportSchedule
}

// ReportSchedule defines automated report scheduling
type ReportSchedule struct {
    Frequency time.Duration
    Enabled   bool
    NextRun   time.Time
}

// Report represents a generated report
type Report struct {
    ID         string
    TemplateID string
    Title      string
    Generated  time.Time
    TimeRange  TimeRange
    Sections   []GeneratedSection
    Format     ReportFormat
    Size       int64
    URL        string
    ExpiresAt  time.Time
}

// GeneratedSection represents a generated report section
type GeneratedSection struct {
    Title   string
    Type    SectionType
    Content interface{}
    Charts  []ChartData
    Tables  []TableData
}

// ChartData represents chart data for reports
type ChartData struct {
    Type   ChartType
    Title  string
    Data   []DataSeries
    Config map[string]interface{}
}

// ChartType defines chart types
type ChartType int

const (
    ChartLine ChartType = iota
    ChartBar
    ChartPie
    ChartArea
    ChartScatter
    ChartHeatmap
)

// DataSeries represents a data series in a chart
type DataSeries struct {
    Name   string
    Data   []DataPoint
    Color  string
    Style  string
}

// TableData represents table data for reports
type TableData struct {
    Headers []string
    Rows    [][]interface{}
    Summary map[string]interface{}
}

// NewReportGenerator creates a new report generator
func NewReportGenerator(config AnalyticsConfig, storage AnalyticsStorage) *ReportGenerator {
    return &ReportGenerator{
        config:    config,
        storage:   storage,
        templates: make(map[string]ReportTemplate),
        scheduler: NewReportScheduler(),
    }
}

// Start begins the report generator
func (rg *ReportGenerator) Start(ctx context.Context) error {
    // Load templates
    if err := rg.loadTemplates(); err != nil {
        return err
    }
    
    // Start scheduler
    return rg.scheduler.Start(ctx, rg)
}

// Generate generates a report
func (rg *ReportGenerator) Generate(request ReportRequest) (*Report, error) {
    template, exists := rg.templates[request.TemplateID]
    if !exists {
        return nil, ErrTemplateNotFound
    }
    
    report := &Report{
        ID:         generateReportID(),
        TemplateID: request.TemplateID,
        Title:      template.Name,
        Generated:  time.Now(),
        TimeRange:  request.TimeRange,
        Format:     request.Format,
        Sections:   make([]GeneratedSection, len(template.Sections)),
        ExpiresAt:  time.Now().Add(30 * 24 * time.Hour), // 30 days
    }
    
    // Generate each section
    for i, section := range template.Sections {
        generatedSection, err := rg.generateSection(section, request)
        if err != nil {
            return nil, err
        }
        report.Sections[i] = generatedSection
    }
    
    // Render report in requested format
    content, err := rg.renderReport(report, request.Format)
    if err != nil {
        return nil, err
    }
    
    // Store report
    url, err := rg.storage.StoreReport(report.ID, content, request.Format)
    if err != nil {
        return nil, err
    }
    
    report.URL = url
    report.Size = int64(len(content))
    
    // Send to recipients if specified
    if len(request.Recipients) > 0 {
        go rg.deliverReport(report, request.Recipients)
    }
    
    return report, nil
}

// generateSection generates a single report section
func (rg *ReportGenerator) generateSection(section ReportSection, request ReportRequest) (GeneratedSection, error) {
    generated := GeneratedSection{
        Title:  section.Title,
        Type:   section.Type,
        Charts: make([]ChartData, 0),
        Tables: make([]TableData, 0),
    }
    
    switch section.Type {
    case SectionSummary:
        content, err := rg.generateSummary(section, request)
        if err != nil {
            return generated, err
        }
        generated.Content = content
        
    case SectionChart:
        chart, err := rg.generateChart(section, request)
        if err != nil {
            return generated, err
        }
        generated.Charts = append(generated.Charts, chart)
        
    case SectionTable:
        table, err := rg.generateTable(section, request)
        if err != nil {
            return generated, err
        }
        generated.Tables = append(generated.Tables, table)
        
    case SectionMetrics:
        metrics, err := rg.generateMetrics(section, request)
        if err != nil {
            return generated, err
        }
        generated.Content = metrics
        
    case SectionAnalysis:
        analysis, err := rg.generateAnalysis(section, request)
        if err != nil {
            return generated, err
        }
        generated.Content = analysis
        
    case SectionRecommendations:
        recommendations, err := rg.generateRecommendations(section, request)
        if err != nil {
            return generated, err
        }
        generated.Content = recommendations
    }
    
    return generated, nil
}

// generateSummary generates a summary section
func (rg *ReportGenerator) generateSummary(section ReportSection, request ReportRequest) (map[string]interface{}, error) {
    query := MetricQuery{
        Query:     section.Query,
        StartTime: request.TimeRange.Start,
        EndTime:   request.TimeRange.End,
    }
    
    result, err := rg.storage.Query(query)
    if err != nil {
        return nil, err
    }
    
    summary := map[string]interface{}{
        "total_metrics": len(result.Metrics),
        "time_range": map[string]interface{}{
            "start": request.TimeRange.Start,
            "end":   request.TimeRange.End,
        },
    }
    
    if len(result.Metrics) > 0 {
        values := make([]float64, len(result.Metrics))
        for i, metric := range result.Metrics {
            values[i] = metric.Value
        }
        
        summary["min_value"] = rg.min(values)
        summary["max_value"] = rg.max(values)
        summary["avg_value"] = rg.avg(values)
        summary["total_value"] = rg.sum(values)
    }
    
    return summary, nil
}

// generateChart generates chart data
func (rg *ReportGenerator) generateChart(section ReportSection, request ReportRequest) (ChartData, error) {
    query := MetricQuery{
        Query:     section.Query,
        StartTime: request.TimeRange.Start,
        EndTime:   request.TimeRange.End,
    }
    
    result, err := rg.storage.Query(query)
    if err != nil {
        return ChartData{}, err
    }
    
    // Group metrics by labels to create data series
    seriesMap := make(map[string][]DataPoint)
    
    for _, metric := range result.Metrics {
        seriesKey := rg.getSeriesKey(metric.Labels)
        if seriesKey == "" {
            seriesKey = "default"
        }
        
        point := DataPoint{
            Timestamp: metric.Timestamp,
            Value:     metric.Value,
            Labels:    metric.Labels,
        }
        
        seriesMap[seriesKey] = append(seriesMap[seriesKey], point)
    }
    
    // Convert to data series
    series := make([]DataSeries, 0, len(seriesMap))
    for name, points := range seriesMap {
        series = append(series, DataSeries{
            Name: name,
            Data: points,
        })
    }
    
    return ChartData{
        Type:  rg.mapVisualizationToChart(section.Visualization),
        Title: section.Title,
        Data:  series,
    }, nil
}

// generateTable generates table data
func (rg *ReportGenerator) generateTable(section ReportSection, request ReportRequest) (TableData, error) {
    query := MetricQuery{
        Query:     section.Query,
        StartTime: request.TimeRange.Start,
        EndTime:   request.TimeRange.End,
    }
    
    result, err := rg.storage.Query(query)
    if err != nil {
        return TableData{}, err
    }
    
    // Create table headers
    headers := []string{"Timestamp", "Metric", "Value", "Unit"}
    
    // Add label columns
    labelSet := make(map[string]bool)
    for _, metric := range result.Metrics {
        for label := range metric.Labels {
            labelSet[label] = true
        }
    }
    
    for label := range labelSet {
        headers = append(headers, label)
    }
    
    // Create table rows
    rows := make([][]interface{}, len(result.Metrics))
    for i, metric := range result.Metrics {
        row := []interface{}{
            metric.Timestamp.Format("2006-01-02 15:04:05"),
            metric.Name,
            metric.Value,
            metric.Unit,
        }
        
        // Add label values
        for label := range labelSet {
            value := metric.Labels[label]
            if value == "" {
                value = "-"
            }
            row = append(row, value)
        }
        
        rows[i] = row
    }
    
    // Calculate summary
    values := make([]float64, len(result.Metrics))
    for i, metric := range result.Metrics {
        values[i] = metric.Value
    }
    
    summary := map[string]interface{}{
        "count": len(values),
    }
    
    if len(values) > 0 {
        summary["min"] = rg.min(values)
        summary["max"] = rg.max(values)
        summary["avg"] = rg.avg(values)
        summary["sum"] = rg.sum(values)
    }
    
    return TableData{
        Headers: headers,
        Rows:    rows,
        Summary: summary,
    }, nil
}

// generateMetrics generates key metrics
func (rg *ReportGenerator) generateMetrics(section ReportSection, request ReportRequest) (map[string]interface{}, error) {
    metrics := make(map[string]interface{})
    
    for _, metricName := range section.Metrics {
        query := MetricQuery{
            Query:     fmt.Sprintf("metric_name:%s", metricName),
            StartTime: request.TimeRange.Start,
            EndTime:   request.TimeRange.End,
        }
        
        result, err := rg.storage.Query(query)
        if err != nil {
            continue
        }
        
        if len(result.Metrics) > 0 {
            values := make([]float64, len(result.Metrics))
            for i, metric := range result.Metrics {
                values[i] = metric.Value
            }
            
            switch section.Aggregation {
            case AggSum:
                metrics[metricName] = rg.sum(values)
            case AggAvg:
                metrics[metricName] = rg.avg(values)
            case AggMin:
                metrics[metricName] = rg.min(values)
            case AggMax:
                metrics[metricName] = rg.max(values)
            case AggCount:
                metrics[metricName] = len(values)
            default:
                metrics[metricName] = rg.avg(values)
            }
        }
    }
    
    return metrics, nil
}

// generateAnalysis generates analysis content
func (rg *ReportGenerator) generateAnalysis(section ReportSection, request ReportRequest) (string, error) {
    // This would typically involve more sophisticated analysis
    // For now, provide a basic analysis template
    
    analysis := fmt.Sprintf("Analysis for period %s to %s:\n\n",
        request.TimeRange.Start.Format("2006-01-02"),
        request.TimeRange.End.Format("2006-01-02"))
    
    query := MetricQuery{
        Query:     section.Query,
        StartTime: request.TimeRange.Start,
        EndTime:   request.TimeRange.End,
    }
    
    result, err := rg.storage.Query(query)
    if err != nil {
        return analysis, err
    }
    
    if len(result.Metrics) > 0 {
        values := make([]float64, len(result.Metrics))
        for i, metric := range result.Metrics {
            values[i] = metric.Value
        }
        
        avg := rg.avg(values)
        stddev := rg.stddev(values)
        
        analysis += fmt.Sprintf("- Total data points: %d\n", len(values))
        analysis += fmt.Sprintf("- Average value: %.2f\n", avg)
        analysis += fmt.Sprintf("- Standard deviation: %.2f\n", stddev)
        analysis += fmt.Sprintf("- Coefficient of variation: %.2f%%\n", (stddev/avg)*100)
        
        if stddev/avg > 0.3 {
            analysis += "- High variability detected in the data\n"
        } else {
            analysis += "- Data shows consistent behavior\n"
        }
    }
    
    return analysis, nil
}

// generateRecommendations generates recommendations
func (rg *ReportGenerator) generateRecommendations(section ReportSection, request ReportRequest) ([]string, error) {
    recommendations := make([]string, 0)
    
    query := MetricQuery{
        Query:     section.Query,
        StartTime: request.TimeRange.Start,
        EndTime:   request.TimeRange.End,
    }
    
    result, err := rg.storage.Query(query)
    if err != nil {
        return recommendations, err
    }
    
    if len(result.Metrics) > 0 {
        values := make([]float64, len(result.Metrics))
        for i, metric := range result.Metrics {
            values[i] = metric.Value
        }
        
        avg := rg.avg(values)
        trend := rg.calculateTrend(values)
        
        if trend > 0.1 {
            recommendations = append(recommendations, "Upward trend detected - consider scaling resources")
        } else if trend < -0.1 {
            recommendations = append(recommendations, "Downward trend detected - investigate potential issues")
        }
        
        if avg > 0.8 {
            recommendations = append(recommendations, "High utilization detected - monitor for capacity issues")
        } else if avg < 0.2 {
            recommendations = append(recommendations, "Low utilization detected - consider resource optimization")
        }
    }
    
    return recommendations, nil
}

// Helper functions
func (rg *ReportGenerator) getSeriesKey(labels map[string]string) string {
    // Create a consistent key from labels
    keys := make([]string, 0, len(labels))
    for k, v := range labels {
        keys = append(keys, fmt.Sprintf("%s=%s", k, v))
    }
    sort.Strings(keys)
    return strings.Join(keys, ",")
}

func (rg *ReportGenerator) mapVisualizationToChart(vis VisualizationType) ChartType {
    switch vis {
    case VisLine:
        return ChartLine
    case VisBar:
        return ChartBar
    case VisPie:
        return ChartPie
    case VisArea:
        return ChartArea
    case VisScatter:
        return ChartScatter
    case VisHeatmap:
        return ChartHeatmap
    default:
        return ChartLine
    }
}

func (rg *ReportGenerator) calculateTrend(values []float64) float64 {
    if len(values) < 2 {
        return 0
    }
    
    // Simple linear trend calculation
    n := float64(len(values))
    sumX := n * (n - 1) / 2
    sumY := rg.sum(values)
    sumXY := 0.0
    sumXX := 0.0
    
    for i, y := range values {
        x := float64(i)
        sumXY += x * y
        sumXX += x * x
    }
    
    slope := (n*sumXY - sumX*sumY) / (n*sumXX - sumX*sumX)
    return slope
}

// Mathematical helper functions (reuse from previous implementations)
func (rg *ReportGenerator) sum(values []float64) float64 {
    var sum float64
    for _, v := range values {
        sum += v
    }
    return sum
}

func (rg *ReportGenerator) avg(values []float64) float64 {
    if len(values) == 0 {
        return 0
    }
    return rg.sum(values) / float64(len(values))
}

func (rg *ReportGenerator) min(values []float64) float64 {
    if len(values) == 0 {
        return 0
    }
    min := values[0]
    for _, v := range values[1:] {
        if v < min {
            min = v
        }
    }
    return min
}

func (rg *ReportGenerator) max(values []float64) float64 {
    if len(values) == 0 {
        return 0
    }
    max := values[0]
    for _, v := range values[1:] {
        if v > max {
            max = v
        }
    }
    return max
}

func (rg *ReportGenerator) stddev(values []float64) float64 {
    if len(values) <= 1 {
        return 0
    }
    
    mean := rg.avg(values)
    var variance float64
    
    for _, v := range values {
        diff := v - mean
        variance += diff * diff
    }
    
    variance /= float64(len(values) - 1)
    return math.Sqrt(variance)
}
```

### Helper Functions

```go
// generateMetricID generates a unique metric ID
func generateMetricID() string {
    return fmt.Sprintf("metric_%d_%s", time.Now().UnixNano(), randomString(8))
}

// generateAlertID generates a unique alert ID
func generateAlertID() string {
    return fmt.Sprintf("alert_%d_%s", time.Now().UnixNano(), randomString(8))
}

// generateReportID generates a unique report ID
func generateReportID() string {
    return fmt.Sprintf("report_%d_%s", time.Now().UnixNano(), randomString(8))
}

// randomString generates a random string
func randomString(length int) string {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    b := make([]byte, length)
    for i := range b {
        b[i] = charset[rand.Intn(len(charset))]
    }
    return string(b)
}

// Subscribe subscribes to analytics updates
func (ae *AnalyticsEngine) Subscribe() <-chan AnalyticsUpdate {
    ae.mu.Lock()
    defer ae.mu.Unlock()
    
    ch := make(chan AnalyticsUpdate, 10)
    ae.subscribers = append(ae.subscribers, ch)
    return ch
}

// notifySubscribers notifies all subscribers
func (ae *AnalyticsEngine) notifySubscribers(update AnalyticsUpdate) {
    for _, ch := range ae.subscribers {
        select {
        case ch <- update:
        default:
            // Channel full, skip
        }
    }
}

// GetNetworkStats returns current network statistics
func (ae *AnalyticsEngine) GetNetworkStats() (*NetworkStats, error) {
    now := time.Now()
    stats := &NetworkStats{
        Timestamp: now,
    }
    
    // Query recent metrics for network stats
    query := MetricQuery{
        StartTime: now.Add(-time.Hour),
        EndTime:   now,
    }
    
    result, err := ae.storage.Query(query)
    if err != nil {
        return nil, err
    }
    
    // Aggregate stats by metric type
    typeStats := make(map[MetricType][]float64)
    for _, metric := range result.Metrics {
        typeStats[metric.Type] = append(typeStats[metric.Type], metric.Value)
    }
    
    // Calculate network statistics
    if values, exists := typeStats[MetricNetworkThroughput]; exists && len(values) > 0 {
        stats.TotalThroughput = ae.sum(values)
        stats.AvgThroughput = ae.avg(values)
    }
    
    if values, exists := typeStats[MetricStorageUtilization]; exists && len(values) > 0 {
        stats.TotalStorageUsed = ae.sum(values)
        stats.AvgStorageUtilization = ae.avg(values)
    }
    
    if values, exists := typeStats[MetricUserActivity]; exists && len(values) > 0 {
        stats.ActiveUsers = int(ae.sum(values))
    }
    
    if values, exists := typeStats[MetricErrorRate]; exists && len(values) > 0 {
        stats.ErrorRate = ae.avg(values)
    }
    
    return stats, nil
}

// NetworkStats represents network statistics
type NetworkStats struct {
    Timestamp              time.Time
    TotalThroughput       float64
    AvgThroughput         float64
    TotalStorageUsed      float64
    AvgStorageUtilization float64
    ActiveUsers           int
    ErrorRate             float64
    ActiveNodes           int
    TotalTransactions     int64
}

// GetDashboardData returns data for a dashboard
func (ae *AnalyticsEngine) GetDashboardData(dashboardID string, timeRange TimeRange) (*DashboardData, error) {
    dashboard, err := ae.dashboardMgr.Get(dashboardID)
    if err != nil {
        return nil, err
    }
    
    data := &DashboardData{
        DashboardID: dashboardID,
        TimeRange:   timeRange,
        Panels:      make([]PanelData, len(dashboard.Panels)),
        Generated:   time.Now(),
    }
    
    for i, panel := range dashboard.Panels {
        panelData, err := ae.getPanelData(panel, timeRange)
        if err != nil {
            continue // Skip failed panels
        }
        data.Panels[i] = panelData
    }
    
    return data, nil
}

// DashboardData represents dashboard data
type DashboardData struct {
    DashboardID string
    TimeRange   TimeRange
    Panels      []PanelData
    Generated   time.Time
}

// PanelData represents data for a dashboard panel
type PanelData struct {
    PanelID string
    Title   string
    Type    PanelType
    Data    interface{}
    Error   string
}

// getPanelData gets data for a specific panel
func (ae *AnalyticsEngine) getPanelData(panel Panel, timeRange TimeRange) (PanelData, error) {
    data := PanelData{
        PanelID: panel.ID,
        Title:   panel.Title,
        Type:    panel.Type,
    }
    
    query := MetricQuery{
        Query:     panel.Query,
        StartTime: timeRange.Start,
        EndTime:   timeRange.End,
    }
    
    result, err := ae.storage.Query(query)
    if err != nil {
        data.Error = err.Error()
        return data, err
    }
    
    switch panel.Type {
    case PanelGraph:
        data.Data = ae.formatGraphData(result, panel)
    case PanelStat:
        data.Data = ae.formatStatData(result, panel)
    case PanelTable:
        data.Data = ae.formatTableData(result, panel)
    default:
        data.Data = result
    }
    
    return data, nil
}

// formatGraphData formats data for graph panels
func (ae *AnalyticsEngine) formatGraphData(result *QueryResult, panel Panel) interface{} {
    series := make(map[string][]DataPoint)
    
    for _, metric := range result.Metrics {
        seriesKey := metric.Name
        if len(metric.Labels) > 0 {
            keys := make([]string, 0, len(metric.Labels))
            for k, v := range metric.Labels {
                keys = append(keys, fmt.Sprintf("%s=%s", k, v))
            }
            seriesKey = fmt.Sprintf("%s{%s}", metric.Name, strings.Join(keys, ","))
        }
        
        series[seriesKey] = append(series[seriesKey], DataPoint{
            Timestamp: metric.Timestamp,
            Value:     metric.Value,
        })
    }
    
    return series
}

// formatStatData formats data for stat panels
func (ae *AnalyticsEngine) formatStatData(result *QueryResult, panel Panel) interface{} {
    if len(result.Metrics) == 0 {
        return 0
    }
    
    values := make([]float64, len(result.Metrics))
    for i, metric := range result.Metrics {
        values[i] = metric.Value
    }
    
    // Return the latest value or average based on panel config
    if len(values) == 1 {
        return values[0]
    }
    
    return ae.avg(values)
}

// formatTableData formats data for table panels
func (ae *AnalyticsEngine) formatTableData(result *QueryResult, panel Panel) interface{} {
    rows := make([]map[string]interface{}, len(result.Metrics))
    
    for i, metric := range result.Metrics {
        row := map[string]interface{}{
            "timestamp": metric.Timestamp,
            "name":      metric.Name,
            "value":     metric.Value,
            "unit":      metric.Unit,
        }
        
        // Add labels as columns
        for k, v := range metric.Labels {
            row[k] = v
        }
        
        rows[i] = row
    }
    
    return rows
}

// Mathematical helper functions
func (ae *AnalyticsEngine) sum(values []float64) float64 {
    var sum float64
    for _, v := range values {
        sum += v
    }
    return sum
}

func (ae *AnalyticsEngine) avg(values []float64) float64 {
    if len(values) == 0 {
        return 0
    }
    return ae.sum(values) / float64(len(values))
}
```

## Testing

```go
package analytics

import (
    "context"
    "testing"
    "time"
)

func TestAnalyticsEngine(t *testing.T) {
    config := AnalyticsConfig{
        RetentionPolicy: map[MetricType]time.Duration{
            MetricNetworkThroughput: 30 * 24 * time.Hour,
        },
        SamplingRate:     1.0,
        BatchSize:        100,
        FlushInterval:    time.Second,
        AlertEnabled:     true,
        PredictionEnabled: false,
    }
    
    storage := NewMockAnalyticsStorage()
    engine := NewAnalyticsEngine(config, storage)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    go engine.Start(ctx)
    
    // Test metric ingestion
    metric := Metric{
        Type:      MetricNetworkThroughput,
        Name:      "network_throughput",
        Value:     1024.5,
        Unit:      "bytes/sec",
        Timestamp: time.Now(),
        NodeID:    "node1",
        Labels: map[string]string{
            "region": "us-west",
        },
    }
    
    err := engine.IngestMetric(metric)
    if err != nil {
        t.Fatalf("Failed to ingest metric: %v", err)
    }
    
    // Test batch ingestion
    metrics := make([]Metric, 10)
    for i := range metrics {
        metrics[i] = Metric{
            Type:      MetricStorageUtilization,
            Name:      "storage_utilization",
            Value:     float64(i) * 10.0,
            Unit:      "percent",
            Timestamp: time.Now().Add(-time.Duration(i) * time.Minute),
            NodeID:    fmt.Sprintf("node%d", i),
        }
    }
    
    err = engine.IngestBatch(metrics)
    if err != nil {
        t.Fatalf("Failed to ingest batch: %v", err)
    }
    
    // Wait for processing
    time.Sleep(2 * time.Second)
    
    // Test query
    query := MetricQuery{
        StartTime: time.Now().Add(-time.Hour),
        EndTime:   time.Now(),
    }
    
    result, err := engine.QueryMetrics(query)
    if err != nil {
        t.Fatalf("Failed to query metrics: %v", err)
    }
    
    if len(result.Metrics) == 0 {
        t.Error("Expected metrics in query result")
    }
}

func TestAlertManager(t *testing.T) {
    config := AnalyticsConfig{
        AlertEnabled: true,
    }
    
    storage := NewMockAnalyticsStorage()
    am := NewAlertManager(config, storage)
    
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    go am.Start(ctx)
    
    // Create alert
    alert := Alert{
        Name:        "High CPU Usage",
        Description: "CPU usage above 80%",
        Query:       "cpu_usage",
        Condition:   ConditionAbove,
        Threshold:   80.0,
        Severity:    SeverityWarning,
        Enabled:     true,
        Frequency:   time.Minute,
        Recipients:  []string{"admin@example.com"},
    }
    
    err := am.Create(alert)
    if err != nil {
        t.Fatalf("Failed to create alert: %v", err)
    }
    
    // Test metric that should trigger alert
    metric := Metric{
        Name:  "cpu_usage",
        Value: 85.0, // Above threshold
        Timestamp: time.Now(),
    }
    
    am.CheckMetric(metric)
    
    // Should have fired the alert
    updatedAlert, _ := am.storage.LoadAlert(alert.ID)
    if updatedAlert.FireCount == 0 {
        t.Error("Expected alert to fire")
    }
}

func TestReportGenerator(t *testing.T) {
    config := AnalyticsConfig{}
    storage := NewMockAnalyticsStorage()
    rg := NewReportGenerator(config, storage)
    
    // Add some test data
    metrics := []Metric{
        {Name: "cpu_usage", Value: 75.0, Timestamp: time.Now()},
        {Name: "memory_usage", Value: 60.0, Timestamp: time.Now()},
        {Name: "disk_usage", Value: 45.0, Timestamp: time.Now()},
    }
    
    for _, metric := range metrics {
        storage.StoreMetrics([]Metric{metric})
    }
    
    // Create report template
    template := ReportTemplate{
        ID:   "system_report",
        Name: "System Performance Report",
        Sections: []ReportSection{
            {
                Title: "Summary",
                Type:  SectionSummary,
                Query: "cpu_usage OR memory_usage OR disk_usage",
            },
            {
                Title: "CPU Metrics",
                Type:  SectionChart,
                Query: "cpu_usage",
                Visualization: VisLine,
            },
        },
        Format: ReportHTML,
    }
    
    rg.templates[template.ID] = template
    
    // Generate report
    request := ReportRequest{
        TemplateID: "system_report",
        TimeRange: TimeRange{
            Start: time.Now().Add(-time.Hour),
            End:   time.Now(),
        },
        Format: ReportHTML,
    }
    
    report, err := rg.Generate(request)
    if err != nil {
        t.Fatalf("Failed to generate report: %v", err)
    }
    
    if len(report.Sections) != 2 {
        t.Errorf("Expected 2 sections, got %d", len(report.Sections))
    }
    
    if report.URL == "" {
        t.Error("Expected report URL to be set")
    }
}
```

## Integration

1. **Storage Integration**: Connect to distributed storage nodes for metrics collection
2. **Network Integration**: Monitor network performance and topology
3. **Payment Integration**: Track transaction and revenue metrics
4. **Reputation Integration**: Monitor provider performance metrics
5. **Alert Integration**: Send notifications through multiple channels

## Configuration

```yaml
analytics:
  retention_policy:
    network_throughput: 720h  # 30 days
    storage_utilization: 168h # 7 days
    user_activity: 2160h      # 90 days
    error_rate: 720h          # 30 days
    
  aggregation_rules:
    network_throughput:
      function: avg
      window: 5m
      buckets: 12
      percentiles: [50, 90, 95, 99]
      
  sampling_rate: 1.0
  batch_size: 1000
  flush_interval: 10s
  
  alerts:
    enabled: true
    evaluation_interval: 30s
    
  predictions:
    enabled: true
    models:
      - linear_regression
      - time_series
      - anomaly_detection
      
  exports:
    - type: prometheus
      endpoint: "http://prometheus:9090"
      interval: 30s
      format: json
    - type: influxdb
      endpoint: "http://influxdb:8086"
      interval: 60s
      format: json

reporting:
  default_retention: 30d
  max_report_size: 100mb
  export_formats:
    - html
    - pdf
    - csv
    - json
```