package network

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	basicconnmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	ma "github.com/multiformats/go-multiaddr"
	"go.uber.org/zap"
)

// ConnectionManager manages peer connections with configurable limits
type ConnectionManager struct {
	connmgr.ConnManager
	
	mu                sync.RWMutex
	connections       map[peer.ID]*ConnectionInfo
	streamTracker     map[network.Stream]*StreamInfo
	metrics           *Metrics
	logger            *zap.Logger
	lowWater          int
	highWater         int
	gracePeriod       time.Duration
	
	// Connection health tracking
	healthChecker     *ConnectionHealthChecker
	reconnectManager  *ReconnectManager
	
	// Performance counters
	totalConnections  atomic.Int64
	activeConnections atomic.Int32
	failedConnections atomic.Int64
	
	// Pruning settings
	pruneInterval     time.Duration
	pruneTicker       *time.Ticker
	stopPruning       chan struct{}
}

// ConnectionInfo holds detailed information about a connection
type ConnectionInfo struct {
	PeerID           peer.ID
	RemoteAddr       string
	LocalAddr        string
	Direction        network.Direction
	OpenedAt         time.Time
	LastActivity     time.Time
	Streams          int
	BytesSent        atomic.Uint64
	BytesRecv        atomic.Uint64
	Latency          time.Duration
	State            ConnectionState
	Tags             map[string]int
	ProtocolsUsed    map[string]int
	ConnectionErrors int
}

// StreamInfo holds information about a stream
type StreamInfo struct {
	ID         string
	Protocol   string
	Direction  network.Direction
	OpenedAt   time.Time
	BytesSent  uint64
	BytesRecv  uint64
}

// ConnectionState represents the state of a connection
type ConnectionState int

const (
	ConnectionStateActive ConnectionState = iota
	ConnectionStateIdle
	ConnectionStateUnhealthy
	ConnectionStateClosing
)

// ConnectionHealthChecker monitors connection health
type ConnectionHealthChecker struct {
	manager         *ConnectionManager
	checkInterval   time.Duration
	unhealthyAfter  time.Duration
	pingTimeout     time.Duration
}

// ReconnectManager handles reconnection logic
type ReconnectManager struct {
	manager         *ConnectionManager
	attempts        map[peer.ID]*ReconnectInfo
	maxAttempts     int
	backoffBase     time.Duration
	backoffMax      time.Duration
	mu              sync.Mutex
}

// ReconnectInfo tracks reconnection attempts
type ReconnectInfo struct {
	PeerID       peer.ID
	Attempts     int
	LastAttempt  time.Time
	NextAttempt  time.Time
	BackoffTime  time.Duration
}

// NewConnectionManager creates a new connection manager with enhanced features
func NewConnectionManager(low, high int, gracePeriod time.Duration) *ConnectionManager {
	cm := &ConnectionManager{
		connections:     make(map[peer.ID]*ConnectionInfo),
		streamTracker:   make(map[network.Stream]*StreamInfo),
		lowWater:        low,
		highWater:       high,
		gracePeriod:     gracePeriod,
		pruneInterval:   30 * time.Second,
		stopPruning:     make(chan struct{}),
	}
	
	// Create the underlying libp2p connection manager
	basicCM, err := basicconnmgr.NewConnManager(low, high, basicconnmgr.WithGracePeriod(gracePeriod))
	if err != nil {
		// This should not happen with valid parameters
		panic(err)
	}
	
	cm.ConnManager = basicCM
	
	// Initialize health checker
	cm.healthChecker = &ConnectionHealthChecker{
		manager:        cm,
		checkInterval:  10 * time.Second,
		unhealthyAfter: 2 * time.Minute,
		pingTimeout:    5 * time.Second,
	}
	
	// Initialize reconnect manager
	cm.reconnectManager = &ReconnectManager{
		manager:     cm,
		attempts:    make(map[peer.ID]*ReconnectInfo),
		maxAttempts: 5,
		backoffBase: 5 * time.Second,
		backoffMax:  5 * time.Minute,
	}
	
	// Start pruning routine
	cm.startPruning()
	
	return cm
}

// SetLogger sets the logger for the connection manager
func (cm *ConnectionManager) SetLogger(logger *zap.Logger) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.logger = logger
}

// Notifee returns a network notifiee for connection events
func (cm *ConnectionManager) Notifee() network.Notifiee {
	return &connectionNotifiee{cm: cm}
}

// connectionNotifiee handles connection lifecycle events
type connectionNotifiee struct {
	cm *ConnectionManager
}

// Listen is called when network starts listening on an address
func (cn *connectionNotifiee) Listen(n network.Network, addr ma.Multiaddr) {}

// ListenClose is called when network stops listening on an address
func (cn *connectionNotifiee) ListenClose(n network.Network, addr ma.Multiaddr) {}

// Connected is called when a connection is opened
func (cn *connectionNotifiee) Connected(n network.Network, c network.Conn) {
	cn.cm.mu.Lock()
	defer cn.cm.mu.Unlock()

	// Record connection start time for latency measurement
	startTime := time.Now()
	
	info := &ConnectionInfo{
		PeerID:        c.RemotePeer(),
		RemoteAddr:    c.RemoteMultiaddr().String(),
		LocalAddr:     c.LocalMultiaddr().String(),
		Direction:     c.Stat().Direction,
		OpenedAt:      startTime,
		LastActivity:  startTime,
		Streams:       0,
		State:         ConnectionStateActive,
		Tags:          make(map[string]int),
		ProtocolsUsed: make(map[string]int),
	}

	// Calculate connection latency
	if stat := c.Stat(); !stat.Opened.IsZero() {
		info.Latency = time.Since(stat.Opened)
	}

	cn.cm.connections[c.RemotePeer()] = info
	cn.cm.activeConnections.Add(1)
	cn.cm.totalConnections.Add(1)

	if cn.cm.metrics != nil {
		cn.cm.metrics.RecordConnectionOpened()
		cn.cm.metrics.ConnectedPeers.Set(float64(cn.cm.activeConnections.Load()))
		
		// Record latency metric
		if info.Latency > 0 {
			cn.cm.metrics.ConnectionDuration.Observe(info.Latency.Seconds())
		}
	}

	if cn.cm.logger != nil {
		cn.cm.logger.Debug("Connection established",
			zap.String("peer_id", c.RemotePeer().String()),
			zap.String("direction", c.Stat().Direction.String()),
			zap.Duration("latency", info.Latency),
		)
	}

	// Remove from reconnect manager if this was a reconnection
	cn.cm.reconnectManager.removeAttempt(c.RemotePeer())
}

// Disconnected is called when a connection is closed
func (cn *connectionNotifiee) Disconnected(n network.Network, c network.Conn) {
	cn.cm.mu.Lock()
	defer cn.cm.mu.Unlock()

	if info, ok := cn.cm.connections[c.RemotePeer()]; ok {
		duration := time.Since(info.OpenedAt).Seconds()
		delete(cn.cm.connections, c.RemotePeer())
		cn.cm.activeConnections.Add(-1)

		if cn.cm.metrics != nil {
			cn.cm.metrics.RecordConnectionClosed(duration)
			cn.cm.metrics.ConnectedPeers.Set(float64(cn.cm.activeConnections.Load()))
		}

		if cn.cm.logger != nil {
			cn.cm.logger.Debug("Connection closed",
				zap.String("peer_id", c.RemotePeer().String()),
				zap.Duration("duration", time.Duration(duration)*time.Second),
				zap.Uint64("bytes_sent", info.BytesSent.Load()),
				zap.Uint64("bytes_recv", info.BytesRecv.Load()),
			)
		}

		// Schedule reconnection if this was an important peer
		if info.Direction == network.DirOutbound && info.ConnectionErrors < 3 {
			cn.cm.reconnectManager.scheduleReconnect(c.RemotePeer())
		}
	}
}

// OpenedStream is called when a stream is opened
func (cn *connectionNotifiee) OpenedStream(n network.Network, s network.Stream) {
	cn.cm.mu.Lock()
	defer cn.cm.mu.Unlock()

	if info, ok := cn.cm.connections[s.Conn().RemotePeer()]; ok {
		info.Streams++
		info.LastActivity = time.Now()
		
		// Track protocol usage
		protocol := string(s.Protocol())
		info.ProtocolsUsed[protocol]++
		
		// Track stream info
		streamInfo := &StreamInfo{
			ID:        s.ID(),
			Protocol:  protocol,
			Direction: s.Stat().Direction,
			OpenedAt:  time.Now(),
		}
		cn.cm.streamTracker[s] = streamInfo
	}

	if cn.cm.metrics != nil {
		cn.cm.metrics.RecordStreamOpened()
		cn.cm.metrics.RecordProtocolMessage(string(s.Protocol()), "stream_opened")
	}
}

// ClosedStream is called when a stream is closed
func (cn *connectionNotifiee) ClosedStream(n network.Network, s network.Stream) {
	cn.cm.mu.Lock()
	defer cn.cm.mu.Unlock()

	var streamDuration float64
	if streamInfo, ok := cn.cm.streamTracker[s]; ok {
		streamDuration = time.Since(streamInfo.OpenedAt).Seconds()
		delete(cn.cm.streamTracker, s)
	}

	if info, ok := cn.cm.connections[s.Conn().RemotePeer()]; ok {
		info.Streams--
		info.LastActivity = time.Now()
	}

	if cn.cm.metrics != nil {
		cn.cm.metrics.RecordStreamClosed(streamDuration)
	}
}

// GetConnectionInfo returns information about a specific connection
func (cm *ConnectionManager) GetConnectionInfo(peerID peer.ID) (*ConnectionInfo, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	info, ok := cm.connections[peerID]
	if !ok {
		return nil, false
	}

	// Return a copy to avoid race conditions
	copy := *info
	copy.BytesSent = atomic.Uint64{}
	copy.BytesRecv = atomic.Uint64{}
	copy.BytesSent.Store(info.BytesSent.Load())
	copy.BytesRecv.Store(info.BytesRecv.Load())
	
	return &copy, true
}

// GetAllConnections returns information about all connections
func (cm *ConnectionManager) GetAllConnections() []*ConnectionInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	connections := make([]*ConnectionInfo, 0, len(cm.connections))
	for _, info := range cm.connections {
		copy := *info
		copy.BytesSent = atomic.Uint64{}
		copy.BytesRecv = atomic.Uint64{}
		copy.BytesSent.Store(info.BytesSent.Load())
		copy.BytesRecv.Store(info.BytesRecv.Load())
		connections = append(connections, &copy)
	}

	return connections
}

// UpdateConnectionStats updates connection statistics
func (cm *ConnectionManager) UpdateConnectionStats(peerID peer.ID, bytesSent, bytesRecv uint64) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if info, ok := cm.connections[peerID]; ok {
		info.BytesSent.Add(bytesSent)
		info.BytesRecv.Add(bytesRecv)
		info.LastActivity = time.Now()
		
		if cm.metrics != nil {
			cm.metrics.RecordBytesTransferred(bytesSent, bytesRecv)
		}
	}
}

// startPruning starts the connection pruning routine
func (cm *ConnectionManager) startPruning() {
	cm.pruneTicker = time.NewTicker(cm.pruneInterval)
	
	go func() {
		for {
			select {
			case <-cm.pruneTicker.C:
				cm.pruneConnections()
			case <-cm.stopPruning:
				cm.pruneTicker.Stop()
				return
			}
		}
	}()
}

// pruneConnections removes idle and unhealthy connections
func (cm *ConnectionManager) pruneConnections() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	now := time.Now()
	activeCount := len(cm.connections)
	
	// Only prune if we're above the low water mark
	if activeCount <= cm.lowWater {
		return
	}

	// Identify connections to prune
	var toPrune []peer.ID
	for peerID, info := range cm.connections {
		// Skip recently active connections
		if now.Sub(info.LastActivity) < cm.gracePeriod {
			continue
		}

		// Prune idle connections
		if info.State == ConnectionStateIdle && info.Streams == 0 {
			toPrune = append(toPrune, peerID)
		}

		// Prune unhealthy connections
		if info.State == ConnectionStateUnhealthy {
			toPrune = append(toPrune, peerID)
		}
	}

	// Prune connections
	for _, peerID := range toPrune {
		if cm.logger != nil {
			cm.logger.Debug("Pruning connection",
				zap.String("peer_id", peerID.String()),
				zap.String("reason", "idle or unhealthy"),
			)
		}
		
		// This will trigger the Disconnected callback
		cm.ConnManager.TagPeer(peerID, "marked-for-close", -1000)
		cm.ConnManager.TrimOpenConns(context.Background())
	}
}

// CheckConnectionHealth performs health checks on all connections
func (cm *ConnectionManager) CheckConnectionHealth(host network.Network) {
	cm.mu.RLock()
	connections := make(map[peer.ID]*ConnectionInfo)
	for k, v := range cm.connections {
		connections[k] = v
	}
	cm.mu.RUnlock()

	for peerID, info := range connections {
		// Check if connection is still healthy
		if time.Since(info.LastActivity) > cm.healthChecker.unhealthyAfter {
			cm.markConnectionUnhealthy(peerID)
		}
	}
}

// markConnectionUnhealthy marks a connection as unhealthy
func (cm *ConnectionManager) markConnectionUnhealthy(peerID peer.ID) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if info, ok := cm.connections[peerID]; ok {
		info.State = ConnectionStateUnhealthy
		info.ConnectionErrors++
		
		if cm.logger != nil {
			cm.logger.Warn("Connection marked as unhealthy",
				zap.String("peer_id", peerID.String()),
				zap.Int("errors", info.ConnectionErrors),
			)
		}
	}
}

// TrimConnections manually triggers connection trimming
func (cm *ConnectionManager) TrimConnections(ctx context.Context) {
	cm.TrimOpenConns(ctx)
}

// SetMetrics sets the metrics instance for the connection manager
func (cm *ConnectionManager) SetMetrics(metrics *Metrics) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.metrics = metrics
}

// Stop stops the connection manager
func (cm *ConnectionManager) Stop() {
	close(cm.stopPruning)
}

// ReconnectManager implementation

// scheduleReconnect schedules a reconnection attempt for a peer
func (rm *ReconnectManager) scheduleReconnect(peerID peer.ID) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	info, exists := rm.attempts[peerID]
	if !exists {
		info = &ReconnectInfo{
			PeerID:      peerID,
			Attempts:    0,
			BackoffTime: rm.backoffBase,
		}
		rm.attempts[peerID] = info
	}

	if info.Attempts >= rm.maxAttempts {
		delete(rm.attempts, peerID)
		return
	}

	info.Attempts++
	info.LastAttempt = time.Now()
	info.NextAttempt = time.Now().Add(info.BackoffTime)

	// Exponential backoff
	info.BackoffTime *= 2
	if info.BackoffTime > rm.backoffMax {
		info.BackoffTime = rm.backoffMax
	}

	// Schedule the reconnection
	go func() {
		time.Sleep(time.Until(info.NextAttempt))
		rm.attemptReconnect(peerID)
	}()
}

// attemptReconnect attempts to reconnect to a peer
func (rm *ReconnectManager) attemptReconnect(peerID peer.ID) {
	// This would be implemented to actually attempt the reconnection
	// using the host's Connect method
}

// removeAttempt removes a peer from reconnection attempts
func (rm *ReconnectManager) removeAttempt(peerID peer.ID) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	delete(rm.attempts, peerID)
}