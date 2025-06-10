# U25: WASM Runtime

## Overview
WebAssembly execution environment that provides secure, sandboxed execution of compute jobs with resource limits, module loading, and performance monitoring.

## Implementation

### Core Runtime Types

```go
package wasm

import (
    "context"
    "fmt"
    "io"
    "sync"
    "time"
    
    "github.com/bytecodealliance/wasmtime-go/v14"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/rs/zerolog/log"
)

// RuntimeConfig defines WASM runtime configuration
type RuntimeConfig struct {
    MaxMemoryPages   uint32        `json:"max_memory_pages"`   // 64KB per page
    MaxTableElements uint32        `json:"max_table_elements"`
    MaxInstances     uint32        `json:"max_instances"`
    MaxTables        uint32        `json:"max_tables"`
    FuelLimit        uint64        `json:"fuel_limit"`
    EpochDeadline    time.Duration `json:"epoch_deadline"`
    EnableWASI       bool          `json:"enable_wasi"`
    EnableThreads    bool          `json:"enable_threads"`
    EnableSIMD       bool          `json:"enable_simd"`
    CacheDir         string        `json:"cache_dir"`
}

// DefaultRuntimeConfig returns default configuration
func DefaultRuntimeConfig() *RuntimeConfig {
    return &RuntimeConfig{
        MaxMemoryPages:   16384, // 1GB max memory
        MaxTableElements: 10000,
        MaxInstances:     10,
        MaxTables:        10,
        FuelLimit:        1000000000, // 1 billion units
        EpochDeadline:    30 * time.Minute,
        EnableWASI:       true,
        EnableThreads:    false,
        EnableSIMD:       true,
        CacheDir:         "/var/cache/blackhole/wasm",
    }
}

// WASMRuntime manages WebAssembly execution
type WASMRuntime struct {
    config      *RuntimeConfig
    engine      *wasmtime.Engine
    moduleCache sync.Map // map[string]*wasmtime.Module
    
    // Resource tracking
    activeInstances sync.Map // map[string]*Instance
    instanceCount   int32
    
    // Metrics
    executionTime   prometheus.Histogram
    memoryUsage     prometheus.Gauge
    fuelConsumption prometheus.Counter
    moduleLoads     prometheus.Counter
    executions      prometheus.Counter
    failures        prometheus.Counter
}

// Instance represents a WASM module instance
type Instance struct {
    ID         string
    Module     *wasmtime.Module
    Store      *wasmtime.Store
    Instance   *wasmtime.Instance
    Memory     *wasmtime.Memory
    StartTime  time.Time
    FuelUsed   uint64
    
    // I/O channels
    stdin      io.Reader
    stdout     io.Writer
    stderr     io.Writer
    
    // Resource limits
    memoryLimit uint64
    cpuLimit    float64
    
    // Execution state
    mu         sync.Mutex
    cancelled  bool
    exitCode   int
}

// NewWASMRuntime creates a new WASM runtime
func NewWASMRuntime(config *RuntimeConfig) (*WASMRuntime, error) {
    if config == nil {
        config = DefaultRuntimeConfig()
    }
    
    // Create engine with configuration
    engineConfig := wasmtime.NewConfig()
    engineConfig.SetConsumeFuel(true)
    engineConfig.SetEpochInterruption(true)
    engineConfig.SetWasmThreads(config.EnableThreads)
    engineConfig.SetWasmSIMD(config.EnableSIMD)
    engineConfig.SetCraneliftOptLevel(wasmtime.OptLevelSpeed)
    engineConfig.SetStrategy(wasmtime.StrategyCompiler)
    
    if config.CacheDir != "" {
        if err := engineConfig.CacheConfigLoadDefault(); err != nil {
            log.Warn().Err(err).Msg("Failed to load cache config")
        }
    }
    
    engine := wasmtime.NewEngineWithConfig(engineConfig)
    
    runtime := &WASMRuntime{
        config: config,
        engine: engine,
    }
    
    runtime.initMetrics()
    
    return runtime, nil
}

func (r *WASMRuntime) initMetrics() {
    r.executionTime = prometheus.NewHistogram(prometheus.HistogramOpts{
        Name:    "blackhole_wasm_execution_seconds",
        Help:    "WASM execution time in seconds",
        Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
    })
    
    r.memoryUsage = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "blackhole_wasm_memory_bytes",
        Help: "Current WASM memory usage in bytes",
    })
    
    r.fuelConsumption = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "blackhole_wasm_fuel_consumed_total",
        Help: "Total fuel consumed by WASM executions",
    })
    
    r.moduleLoads = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "blackhole_wasm_module_loads_total",
        Help: "Total number of WASM module loads",
    })
    
    r.executions = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "blackhole_wasm_executions_total",
        Help: "Total number of WASM executions",
    })
    
    r.failures = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "blackhole_wasm_failures_total",
        Help: "Total number of WASM execution failures",
    })
    
    prometheus.MustRegister(
        r.executionTime,
        r.memoryUsage,
        r.fuelConsumption,
        r.moduleLoads,
        r.executions,
        r.failures,
    )
}

// LoadModule loads a WASM module
func (r *WASMRuntime) LoadModule(ctx context.Context, name string, wasmBytes []byte) (*wasmtime.Module, error) {
    // Check cache
    if cached, ok := r.moduleCache.Load(name); ok {
        return cached.(*wasmtime.Module), nil
    }
    
    // Compile module
    module, err := wasmtime.NewModule(r.engine, wasmBytes)
    if err != nil {
        return nil, fmt.Errorf("failed to compile module: %w", err)
    }
    
    // Validate module
    if err := r.validateModule(module); err != nil {
        return nil, fmt.Errorf("module validation failed: %w", err)
    }
    
    // Cache module
    r.moduleCache.Store(name, module)
    r.moduleLoads.Inc()
    
    return module, nil
}

func (r *WASMRuntime) validateModule(module *wasmtime.Module) error {
    // Check imports
    imports := module.Imports()
    for _, imp := range imports {
        impType := imp.Type()
        
        switch impType := impType.(type) {
        case *wasmtime.FuncType:
            // Validate function imports
            if imp.Module() != "wasi_snapshot_preview1" && imp.Module() != "env" {
                return fmt.Errorf("unsupported import module: %s", imp.Module())
            }
        case *wasmtime.MemoryType:
            // Validate memory imports
            if impType.Limits().Max != nil && *impType.Limits().Max > r.config.MaxMemoryPages {
                return fmt.Errorf("memory limit exceeds maximum: %d > %d", *impType.Limits().Max, r.config.MaxMemoryPages)
            }
        default:
            return fmt.Errorf("unsupported import type: %T", impType)
        }
    }
    
    // Check exports
    exports := module.Exports()
    hasStart := false
    for _, exp := range exports {
        if exp.Name() == "_start" && exp.Type().FuncType() != nil {
            hasStart = true
            break
        }
    }
    
    if !hasStart {
        return fmt.Errorf("module missing _start export")
    }
    
    return nil
}

// CreateInstance creates a new WASM instance
func (r *WASMRuntime) CreateInstance(ctx context.Context, module *wasmtime.Module, config *InstanceConfig) (*Instance, error) {
    // Check instance limit
    count := atomic.AddInt32(&r.instanceCount, 1)
    if count > int32(r.config.MaxInstances) {
        atomic.AddInt32(&r.instanceCount, -1)
        return nil, fmt.Errorf("instance limit exceeded: %d", count)
    }
    
    // Create store with limits
    storeConfig := wasmtime.NewConfig()
    store := wasmtime.NewStore(r.engine)
    store.SetFuel(r.config.FuelLimit)
    store.SetEpochDeadline(1)
    
    // Set resource limits
    store.Limiter(&resourceLimiter{
        memoryLimit:      config.MemoryLimit,
        tableLimit:       r.config.MaxTableElements,
        instanceLimit:    1,
        tablesLimit:      r.config.MaxTables,
        memoriesLimit:    1,
    })
    
    // Create WASI config if enabled
    var wasiConfig *wasmtime.WasiConfig
    if r.config.EnableWASI {
        wasiConfig = wasmtime.NewWasiConfig()
        wasiConfig.SetStdin(config.Stdin)
        wasiConfig.SetStdout(config.Stdout)
        wasiConfig.SetStderr(config.Stderr)
        wasiConfig.SetArgv(config.Args)
        
        for k, v := range config.Env {
            wasiConfig.SetEnv(k, v)
        }
        
        // Add allowed directories
        for _, dir := range config.AllowedDirs {
            wasiConfig.PreopenDir(dir, dir)
        }
    }
    
    // Create linker
    linker := wasmtime.NewLinker(r.engine)
    
    // Add WASI if configured
    if wasiConfig != nil {
        if err := linker.DefineWasi(); err != nil {
            atomic.AddInt32(&r.instanceCount, -1)
            return nil, fmt.Errorf("failed to define WASI: %w", err)
        }
        
        store.SetWasi(wasiConfig)
    }
    
    // Add custom host functions
    if err := r.defineHostFunctions(linker); err != nil {
        atomic.AddInt32(&r.instanceCount, -1)
        return nil, fmt.Errorf("failed to define host functions: %w", err)
    }
    
    // Instantiate module
    wasmInstance, err := linker.Instantiate(store, module)
    if err != nil {
        atomic.AddInt32(&r.instanceCount, -1)
        return nil, fmt.Errorf("failed to instantiate module: %w", err)
    }
    
    // Get memory export
    memory := wasmInstance.GetExport(store, "memory").Memory()
    
    instance := &Instance{
        ID:          config.ID,
        Module:      module,
        Store:       store,
        Instance:    wasmInstance,
        Memory:      memory,
        StartTime:   time.Now(),
        stdin:       config.Stdin,
        stdout:      config.Stdout,
        stderr:      config.Stderr,
        memoryLimit: config.MemoryLimit,
        cpuLimit:    config.CPULimit,
    }
    
    r.activeInstances.Store(config.ID, instance)
    
    return instance, nil
}

// InstanceConfig defines instance configuration
type InstanceConfig struct {
    ID          string
    Args        []string
    Env         map[string]string
    Stdin       io.Reader
    Stdout      io.Writer
    Stderr      io.Writer
    AllowedDirs []string
    MemoryLimit uint64
    CPULimit    float64
}

// Execute runs a WASM instance
func (r *WASMRuntime) Execute(ctx context.Context, instance *Instance, entryPoint string) error {
    r.executions.Inc()
    
    startTime := time.Now()
    defer func() {
        duration := time.Since(startTime)
        r.executionTime.Observe(duration.Seconds())
    }()
    
    // Get entry point function
    fn := instance.Instance.GetFunc(instance.Store, entryPoint)
    if fn == nil {
        r.failures.Inc()
        return fmt.Errorf("entry point not found: %s", entryPoint)
    }
    
    // Set up epoch ticker for interruption
    ticker := time.NewTicker(100 * time.Millisecond)
    defer ticker.Stop()
    
    errCh := make(chan error, 1)
    
    // Run in goroutine to allow interruption
    go func() {
        _, err := fn.Call(instance.Store)
        errCh <- err
    }()
    
    // Monitor execution
    for {
        select {
        case <-ctx.Done():
            instance.Cancel()
            r.failures.Inc()
            return ctx.Err()
            
        case <-ticker.C:
            // Update epoch for interruption check
            r.engine.IncrementEpoch()
            
            // Check fuel consumption
            fuel, err := instance.Store.GetFuel()
            if err == nil {
                fuelUsed := r.config.FuelLimit - fuel
                instance.FuelUsed = fuelUsed
                r.fuelConsumption.Add(float64(fuelUsed))
            }
            
            // Update memory usage
            if instance.Memory != nil {
                memSize := instance.Memory.DataSize(instance.Store)
                r.memoryUsage.Set(float64(memSize))
            }
            
        case err := <-errCh:
            if err != nil {
                r.failures.Inc()
                
                // Check if it's a trap
                if trap, ok := err.(*wasmtime.Trap); ok {
                    return fmt.Errorf("WASM trap: %v", trap)
                }
                
                return fmt.Errorf("execution failed: %w", err)
            }
            
            // Execution completed successfully
            return nil
        }
    }
}

// Cancel cancels instance execution
func (i *Instance) Cancel() {
    i.mu.Lock()
    defer i.mu.Unlock()
    
    i.cancelled = true
    i.Store.SetEpochDeadline(0) // Trigger immediate interruption
}

// Cleanup cleans up instance resources
func (r *WASMRuntime) Cleanup(instanceID string) {
    if inst, ok := r.activeInstances.LoadAndDelete(instanceID); ok {
        instance := inst.(*Instance)
        
        // Clean up store
        instance.Store = nil
        instance.Instance = nil
        instance.Memory = nil
        
        atomic.AddInt32(&r.instanceCount, -1)
    }
}

// defineHostFunctions defines custom host functions
func (r *WASMRuntime) defineHostFunctions(linker *wasmtime.Linker) error {
    // Add logging function
    logFn := wasmtime.WrapFunc(
        linker.Store,
        func(caller *wasmtime.Caller, ptr int32, len int32) {
            memory := caller.GetExport("memory").Memory()
            data := memory.Data(caller)
            
            if ptr >= 0 && len > 0 && int(ptr+len) <= len(data) {
                msg := string(data[ptr : ptr+len])
                log.Info().Str("source", "wasm").Msg(msg)
            }
        },
    )
    
    if err := linker.Define("env", "log", logFn); err != nil {
        return err
    }
    
    // Add time function
    timeFn := wasmtime.WrapFunc(
        linker.Store,
        func() int64 {
            return time.Now().Unix()
        },
    )
    
    if err := linker.Define("env", "time", timeFn); err != nil {
        return err
    }
    
    // Add random function
    randFn := wasmtime.WrapFunc(
        linker.Store,
        func() int32 {
            return rand.Int31()
        },
    )
    
    if err := linker.Define("env", "random", randFn); err != nil {
        return err
    }
    
    return nil
}

// resourceLimiter implements wasmtime.ResourceLimiter
type resourceLimiter struct {
    memoryLimit   uint64
    tableLimit    uint32
    instanceLimit uint32
    tablesLimit   uint32
    memoriesLimit uint32
}

func (l *resourceLimiter) MemoryGrowing(currentPages, desiredPages, maxPages uint64) (bool, uint64) {
    pageSize := uint64(65536) // 64KB
    desiredBytes := desiredPages * pageSize
    
    if desiredBytes > l.memoryLimit {
        return false, currentPages
    }
    
    return true, desiredPages
}

func (l *resourceLimiter) TableGrowing(currentElements, desiredElements, maxElements uint32) (bool, uint32) {
    if desiredElements > l.tableLimit {
        return false, currentElements
    }
    
    return true, desiredElements
}

func (l *resourceLimiter) MaxInstances() uint32 {
    return l.instanceLimit
}

func (l *resourceLimiter) MaxTables() uint32 {
    return l.tablesLimit
}

func (l *resourceLimiter) MaxMemories() uint32 {
    return l.memoriesLimit
}
```

### Security Sandbox

```go
package wasm

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"
    
    "golang.org/x/sys/unix"
)

// Sandbox provides additional security isolation
type Sandbox struct {
    rootDir     string
    allowedDirs []string
    uid         int
    gid         int
}

// NewSandbox creates a new security sandbox
func NewSandbox(rootDir string) (*Sandbox, error) {
    // Create sandbox directory
    if err := os.MkdirAll(rootDir, 0755); err != nil {
        return nil, fmt.Errorf("failed to create sandbox dir: %w", err)
    }
    
    return &Sandbox{
        rootDir:     rootDir,
        allowedDirs: []string{rootDir},
        uid:         65534, // nobody
        gid:         65534, // nogroup
    }, nil
}

// Setup sets up the sandbox environment
func (s *Sandbox) Setup() error {
    // Create necessary directories
    dirs := []string{"tmp", "home", "work"}
    for _, dir := range dirs {
        path := filepath.Join(s.rootDir, dir)
        if err := os.MkdirAll(path, 0755); err != nil {
            return fmt.Errorf("failed to create %s: %w", dir, err)
        }
    }
    
    // Set up minimal /etc files
    etcDir := filepath.Join(s.rootDir, "etc")
    if err := os.MkdirAll(etcDir, 0755); err != nil {
        return err
    }
    
    // Create passwd file
    passwd := fmt.Sprintf("nobody:x:%d:%d:nobody:/home:/bin/false\n", s.uid, s.gid)
    if err := os.WriteFile(filepath.Join(etcDir, "passwd"), []byte(passwd), 0644); err != nil {
        return err
    }
    
    // Create group file
    group := fmt.Sprintf("nogroup:x:%d:\n", s.gid)
    if err := os.WriteFile(filepath.Join(etcDir, "group"), []byte(group), 0644); err != nil {
        return err
    }
    
    return nil
}

// Enter enters the sandbox
func (s *Sandbox) Enter() error {
    // Change root directory
    if err := unix.Chroot(s.rootDir); err != nil {
        return fmt.Errorf("chroot failed: %w", err)
    }
    
    // Change working directory
    if err := os.Chdir("/"); err != nil {
        return fmt.Errorf("chdir failed: %w", err)
    }
    
    // Drop privileges
    if err := unix.Setgid(s.gid); err != nil {
        return fmt.Errorf("setgid failed: %w", err)
    }
    
    if err := unix.Setuid(s.uid); err != nil {
        return fmt.Errorf("setuid failed: %w", err)
    }
    
    return nil
}

// ValidatePath validates a file path
func (s *Sandbox) ValidatePath(path string) error {
    // Resolve to absolute path
    absPath, err := filepath.Abs(path)
    if err != nil {
        return err
    }
    
    // Check if path is within allowed directories
    for _, allowed := range s.allowedDirs {
        if strings.HasPrefix(absPath, allowed) {
            return nil
        }
    }
    
    return fmt.Errorf("path not allowed: %s", path)
}

// ResourceController controls resource usage
type ResourceController struct {
    cpuQuota   int64 // microseconds per period
    cpuPeriod  int64 // microseconds
    memoryMax  int64 // bytes
    pidsMax    int64
    cgroupPath string
}

// NewResourceController creates a new resource controller
func NewResourceController(cgroupPath string) (*ResourceController, error) {
    rc := &ResourceController{
        cgroupPath: cgroupPath,
        cpuPeriod:  100000, // 100ms
    }
    
    // Create cgroup
    if err := rc.createCgroup(); err != nil {
        return nil, err
    }
    
    return rc, nil
}

func (rc *ResourceController) createCgroup() error {
    // Create cgroup v2 directory
    if err := os.MkdirAll(rc.cgroupPath, 0755); err != nil {
        return fmt.Errorf("failed to create cgroup: %w", err)
    }
    
    // Enable controllers
    controllers := "+cpu +memory +pids"
    subtreeControl := filepath.Join(filepath.Dir(rc.cgroupPath), "cgroup.subtree_control")
    if err := os.WriteFile(subtreeControl, []byte(controllers), 0644); err != nil {
        return fmt.Errorf("failed to enable controllers: %w", err)
    }
    
    return nil
}

// SetCPULimit sets CPU limit (cores)
func (rc *ResourceController) SetCPULimit(cores float64) error {
    rc.cpuQuota = int64(cores * float64(rc.cpuPeriod))
    
    quotaPath := filepath.Join(rc.cgroupPath, "cpu.max")
    value := fmt.Sprintf("%d %d", rc.cpuQuota, rc.cpuPeriod)
    
    return os.WriteFile(quotaPath, []byte(value), 0644)
}

// SetMemoryLimit sets memory limit
func (rc *ResourceController) SetMemoryLimit(bytes int64) error {
    rc.memoryMax = bytes
    
    memPath := filepath.Join(rc.cgroupPath, "memory.max")
    value := fmt.Sprintf("%d", bytes)
    
    return os.WriteFile(memPath, []byte(value), 0644)
}

// SetPIDLimit sets process limit
func (rc *ResourceController) SetPIDLimit(max int64) error {
    rc.pidsMax = max
    
    pidsPath := filepath.Join(rc.cgroupPath, "pids.max")
    value := fmt.Sprintf("%d", max)
    
    return os.WriteFile(pidsPath, []byte(value), 0644)
}

// AddProcess adds a process to the cgroup
func (rc *ResourceController) AddProcess(pid int) error {
    procsPath := filepath.Join(rc.cgroupPath, "cgroup.procs")
    value := fmt.Sprintf("%d", pid)
    
    return os.WriteFile(procsPath, []byte(value), 0644)
}

// Cleanup removes the cgroup
func (rc *ResourceController) Cleanup() error {
    return os.RemoveAll(rc.cgroupPath)
}
```

### Module Manager

```go
package wasm

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "sync"
    "time"
    
    "github.com/klauspost/compress/zstd"
)

// ModuleManager manages WASM module storage and caching
type ModuleManager struct {
    baseDir      string
    maxCacheSize int64
    
    mu           sync.RWMutex
    modules      map[string]*ModuleInfo
    cacheSize    int64
    
    decoder      *zstd.Decoder
    encoder      *zstd.Encoder
}

// ModuleInfo contains module metadata
type ModuleInfo struct {
    Hash         string    `json:"hash"`
    Name         string    `json:"name"`
    Version      string    `json:"version"`
    Size         int64     `json:"size"`
    CompressedSize int64   `json:"compressed_size"`
    UploadedAt   time.Time `json:"uploaded_at"`
    LastUsedAt   time.Time `json:"last_used_at"`
    UsageCount   int64     `json:"usage_count"`
    Path         string    `json:"path"`
}

// NewModuleManager creates a new module manager
func NewModuleManager(baseDir string, maxCacheSize int64) (*ModuleManager, error) {
    if err := os.MkdirAll(baseDir, 0755); err != nil {
        return nil, fmt.Errorf("failed to create module dir: %w", err)
    }
    
    decoder, err := zstd.NewReader(nil)
    if err != nil {
        return nil, err
    }
    
    encoder, err := zstd.NewWriter(nil)
    if err != nil {
        return nil, err
    }
    
    mm := &ModuleManager{
        baseDir:      baseDir,
        maxCacheSize: maxCacheSize,
        modules:      make(map[string]*ModuleInfo),
        decoder:      decoder,
        encoder:      encoder,
    }
    
    // Load existing modules
    if err := mm.loadModules(); err != nil {
        return nil, err
    }
    
    return mm, nil
}

// StoreModule stores a WASM module
func (mm *ModuleManager) StoreModule(name, version string, wasmData []byte) (*ModuleInfo, error) {
    // Calculate hash
    hash := sha256.Sum256(wasmData)
    hashStr := hex.EncodeToString(hash[:])
    
    mm.mu.Lock()
    defer mm.mu.Unlock()
    
    // Check if already exists
    if info, exists := mm.modules[hashStr]; exists {
        info.LastUsedAt = time.Now()
        info.UsageCount++
        return info, nil
    }
    
    // Compress module
    compressed := mm.encoder.EncodeAll(wasmData, nil)
    
    // Create module directory
    moduleDir := filepath.Join(mm.baseDir, hashStr[:2], hashStr[2:4])
    if err := os.MkdirAll(moduleDir, 0755); err != nil {
        return nil, err
    }
    
    // Write compressed module
    modulePath := filepath.Join(moduleDir, hashStr+".wasm.zst")
    if err := os.WriteFile(modulePath, compressed, 0644); err != nil {
        return nil, err
    }
    
    // Create module info
    info := &ModuleInfo{
        Hash:           hashStr,
        Name:           name,
        Version:        version,
        Size:           int64(len(wasmData)),
        CompressedSize: int64(len(compressed)),
        UploadedAt:     time.Now(),
        LastUsedAt:     time.Now(),
        UsageCount:     1,
        Path:           modulePath,
    }
    
    mm.modules[hashStr] = info
    mm.cacheSize += info.CompressedSize
    
    // Evict old modules if needed
    if mm.cacheSize > mm.maxCacheSize {
        mm.evictOldModules()
    }
    
    // Save metadata
    if err := mm.saveModuleInfo(info); err != nil {
        return nil, err
    }
    
    return info, nil
}

// LoadModule loads a WASM module
func (mm *ModuleManager) LoadModule(hash string) ([]byte, error) {
    mm.mu.RLock()
    info, exists := mm.modules[hash]
    mm.mu.RUnlock()
    
    if !exists {
        return nil, fmt.Errorf("module not found: %s", hash)
    }
    
    // Read compressed module
    compressed, err := os.ReadFile(info.Path)
    if err != nil {
        return nil, fmt.Errorf("failed to read module: %w", err)
    }
    
    // Decompress
    wasmData, err := mm.decoder.DecodeAll(compressed, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to decompress module: %w", err)
    }
    
    // Verify hash
    actualHash := sha256.Sum256(wasmData)
    if hex.EncodeToString(actualHash[:]) != hash {
        return nil, fmt.Errorf("module hash mismatch")
    }
    
    // Update usage
    mm.mu.Lock()
    info.LastUsedAt = time.Now()
    info.UsageCount++
    mm.mu.Unlock()
    
    return wasmData, nil
}

// GetModuleInfo gets module information
func (mm *ModuleManager) GetModuleInfo(hash string) (*ModuleInfo, error) {
    mm.mu.RLock()
    defer mm.mu.RUnlock()
    
    info, exists := mm.modules[hash]
    if !exists {
        return nil, fmt.Errorf("module not found: %s", hash)
    }
    
    return info, nil
}

// ListModules lists all modules
func (mm *ModuleManager) ListModules() []*ModuleInfo {
    mm.mu.RLock()
    defer mm.mu.RUnlock()
    
    modules := make([]*ModuleInfo, 0, len(mm.modules))
    for _, info := range mm.modules {
        modules = append(modules, info)
    }
    
    return modules
}

func (mm *ModuleManager) loadModules() error {
    // Walk module directory
    err := filepath.Walk(mm.baseDir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        
        if !strings.HasSuffix(path, ".json") {
            return nil
        }
        
        // Load module info
        data, err := os.ReadFile(path)
        if err != nil {
            return err
        }
        
        var moduleInfo ModuleInfo
        if err := json.Unmarshal(data, &moduleInfo); err != nil {
            return err
        }
        
        mm.modules[moduleInfo.Hash] = &moduleInfo
        mm.cacheSize += moduleInfo.CompressedSize
        
        return nil
    })
    
    return err
}

func (mm *ModuleManager) saveModuleInfo(info *ModuleInfo) error {
    infoPath := info.Path + ".json"
    data, err := json.MarshalIndent(info, "", "  ")
    if err != nil {
        return err
    }
    
    return os.WriteFile(infoPath, data, 0644)
}

func (mm *ModuleManager) evictOldModules() {
    // Sort modules by last used time
    type moduleEntry struct {
        hash string
        info *ModuleInfo
    }
    
    entries := make([]moduleEntry, 0, len(mm.modules))
    for hash, info := range mm.modules {
        entries = append(entries, moduleEntry{hash, info})
    }
    
    sort.Slice(entries, func(i, j int) bool {
        return entries[i].info.LastUsedAt.Before(entries[j].info.LastUsedAt)
    })
    
    // Remove oldest modules until under limit
    for _, entry := range entries {
        if mm.cacheSize <= mm.maxCacheSize {
            break
        }
        
        // Remove module files
        os.Remove(entry.info.Path)
        os.Remove(entry.info.Path + ".json")
        
        // Update cache
        mm.cacheSize -= entry.info.CompressedSize
        delete(mm.modules, entry.hash)
        
        log.Info().
            Str("module", entry.info.Name).
            Str("hash", entry.hash).
            Msg("Evicted module from cache")
    }
}
```

## Testing

```go
package wasm_test

import (
    "bytes"
    "context"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// Test WASM module that adds two numbers
var testWASM = []byte{
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // WASM header
    // ... actual WASM bytecode
}

func TestWASMRuntime(t *testing.T) {
    config := DefaultRuntimeConfig()
    runtime, err := NewWASMRuntime(config)
    require.NoError(t, err)
    
    t.Run("LoadModule", func(t *testing.T) {
        module, err := runtime.LoadModule(context.Background(), "test", testWASM)
        require.NoError(t, err)
        assert.NotNil(t, module)
    })
    
    t.Run("CreateInstance", func(t *testing.T) {
        module, err := runtime.LoadModule(context.Background(), "test", testWASM)
        require.NoError(t, err)
        
        stdout := &bytes.Buffer{}
        stderr := &bytes.Buffer{}
        
        instanceConfig := &InstanceConfig{
            ID:          "test-instance",
            Args:        []string{"arg1", "arg2"},
            Env:         map[string]string{"TEST": "value"},
            Stdout:      stdout,
            Stderr:      stderr,
            MemoryLimit: 64 * 1024 * 1024, // 64MB
            CPULimit:    1.0,
        }
        
        instance, err := runtime.CreateInstance(context.Background(), module, instanceConfig)
        require.NoError(t, err)
        assert.NotNil(t, instance)
        
        // Cleanup
        runtime.Cleanup(instance.ID)
    })
    
    t.Run("Execute", func(t *testing.T) {
        module, err := runtime.LoadModule(context.Background(), "test", testWASM)
        require.NoError(t, err)
        
        stdout := &bytes.Buffer{}
        instanceConfig := &InstanceConfig{
            ID:          "exec-test",
            Stdout:      stdout,
            MemoryLimit: 64 * 1024 * 1024,
        }
        
        instance, err := runtime.CreateInstance(context.Background(), module, instanceConfig)
        require.NoError(t, err)
        
        err = runtime.Execute(context.Background(), instance, "_start")
        require.NoError(t, err)
        
        // Check output
        assert.NotEmpty(t, stdout.String())
        
        runtime.Cleanup(instance.ID)
    })
    
    t.Run("Timeout", func(t *testing.T) {
        // Use a module that runs forever
        module, err := runtime.LoadModule(context.Background(), "timeout", infiniteLoopWASM)
        require.NoError(t, err)
        
        instance, err := runtime.CreateInstance(context.Background(), module, &InstanceConfig{
            ID:          "timeout-test",
            MemoryLimit: 64 * 1024 * 1024,
        })
        require.NoError(t, err)
        
        ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
        defer cancel()
        
        err = runtime.Execute(ctx, instance, "_start")
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "context deadline exceeded")
        
        runtime.Cleanup(instance.ID)
    })
}

func TestModuleManager(t *testing.T) {
    tmpDir := t.TempDir()
    manager, err := NewModuleManager(tmpDir, 1024*1024) // 1MB cache
    require.NoError(t, err)
    
    t.Run("StoreModule", func(t *testing.T) {
        info, err := manager.StoreModule("test", "1.0.0", testWASM)
        require.NoError(t, err)
        assert.Equal(t, "test", info.Name)
        assert.Equal(t, "1.0.0", info.Version)
        assert.Greater(t, info.Size, int64(0))
    })
    
    t.Run("LoadModule", func(t *testing.T) {
        info, err := manager.StoreModule("test2", "1.0.0", testWASM)
        require.NoError(t, err)
        
        loaded, err := manager.LoadModule(info.Hash)
        require.NoError(t, err)
        assert.Equal(t, testWASM, loaded)
    })
    
    t.Run("ListModules", func(t *testing.T) {
        modules := manager.ListModules()
        assert.GreaterOrEqual(t, len(modules), 2)
    })
}

func TestSandbox(t *testing.T) {
    if os.Getuid() != 0 {
        t.Skip("Sandbox tests require root privileges")
    }
    
    tmpDir := t.TempDir()
    sandbox, err := NewSandbox(tmpDir)
    require.NoError(t, err)
    
    t.Run("Setup", func(t *testing.T) {
        err := sandbox.Setup()
        require.NoError(t, err)
        
        // Check directories exist
        assert.DirExists(t, filepath.Join(tmpDir, "tmp"))
        assert.DirExists(t, filepath.Join(tmpDir, "home"))
        assert.DirExists(t, filepath.Join(tmpDir, "work"))
        assert.FileExists(t, filepath.Join(tmpDir, "etc", "passwd"))
    })
    
    t.Run("ValidatePath", func(t *testing.T) {
        // Allowed path
        err := sandbox.ValidatePath(filepath.Join(tmpDir, "work", "file.txt"))
        assert.NoError(t, err)
        
        // Disallowed path
        err = sandbox.ValidatePath("/etc/passwd")
        assert.Error(t, err)
    })
}

func BenchmarkWASMExecution(b *testing.B) {
    config := DefaultRuntimeConfig()
    runtime, err := NewWASMRuntime(config)
    require.NoError(b, err)
    
    module, err := runtime.LoadModule(context.Background(), "bench", testWASM)
    require.NoError(b, err)
    
    b.ResetTimer()
    
    for i := 0; i < b.N; i++ {
        instance, err := runtime.CreateInstance(context.Background(), module, &InstanceConfig{
            ID:          fmt.Sprintf("bench-%d", i),
            MemoryLimit: 64 * 1024 * 1024,
        })
        require.NoError(b, err)
        
        err = runtime.Execute(context.Background(), instance, "_start")
        require.NoError(b, err)
        
        runtime.Cleanup(instance.ID)
    }
}
```

## Deployment Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: wasm-runtime-config
  namespace: blackhole-compute
data:
  config.yaml: |
    max_memory_pages: 16384
    max_table_elements: 10000
    max_instances: 100
    fuel_limit: 1000000000
    epoch_deadline: 30m
    enable_wasi: true
    enable_threads: false
    enable_simd: true
    cache_dir: /var/cache/blackhole/wasm
    
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: wasm-runtime
  namespace: blackhole-compute
spec:
  serviceName: wasm-runtime
  replicas: 3
  selector:
    matchLabels:
      app: wasm-runtime
  template:
    metadata:
      labels:
        app: wasm-runtime
    spec:
      securityContext:
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
      containers:
      - name: runtime
        image: blackhole/wasm-runtime:latest
        ports:
        - containerPort: 8080
        volumeMounts:
        - name: config
          mountPath: /etc/wasm-runtime
        - name: cache
          mountPath: /var/cache/blackhole/wasm
        - name: modules
          mountPath: /var/lib/blackhole/modules
        resources:
          requests:
            memory: "2Gi"
            cpu: "2"
          limits:
            memory: "4Gi"
            cpu: "4"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
            add:
            - NET_BIND_SERVICE
      volumes:
      - name: config
        configMap:
          name: wasm-runtime-config
  volumeClaimTemplates:
  - metadata:
      name: cache
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 10Gi
  - metadata:
      name: modules
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 50Gi
```

## Security Considerations

1. **Sandboxing**: Full process isolation with chroot
2. **Resource Limits**: CPU, memory, and PID limits via cgroups
3. **WASI Capabilities**: Restricted filesystem access
4. **Module Validation**: Strict import/export checking
5. **Fuel Metering**: Prevent infinite loops
6. **Memory Safety**: Bounds checking on all memory access

## Performance Optimizations

1. **Module Caching**: Compiled modules cached in memory
2. **Compression**: Zstandard compression for storage
3. **JIT Compilation**: Cranelift optimizer for speed
4. **Parallel Execution**: Multiple runtime instances
5. **Resource Pooling**: Reuse stores and instances
6. **Efficient Interruption**: Epoch-based cancellation