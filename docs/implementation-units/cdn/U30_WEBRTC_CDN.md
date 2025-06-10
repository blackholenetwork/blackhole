# U30: WebRTC CDN

## Overview
WebRTC-based content delivery network using data channels for P2P content distribution with browser integration and signaling server.

## Implementation

```go
package webrtccdn

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "sync"
    "time"

    "github.com/pion/datachannel"
    "github.com/pion/webrtc/v3"
    "github.com/gorilla/websocket"
)

// WebRTCCDN manages P2P content delivery via WebRTC
type WebRTCCDN struct {
    config       *Config
    peers        map[string]*Peer
    peersMutex   sync.RWMutex
    content      *ContentStore
    signaling    *SignalingServer
    stats        *CDNStats
    iceServers   []webrtc.ICEServer
}

// Config holds WebRTC CDN configuration
type Config struct {
    SignalingAddr   string
    StunServers     []string
    TurnServers     []TurnConfig
    MaxPeers        int
    ChunkSize       int
    BufferSize      int
}

// TurnConfig represents TURN server configuration
type TurnConfig struct {
    URLs       []string
    Username   string
    Credential string
}

// Peer represents a WebRTC peer connection
type Peer struct {
    ID             string
    Connection     *webrtc.PeerConnection
    DataChannel    *webrtc.DataChannel
    SignalingConn  *websocket.Conn
    Content        map[string]*ContentInfo
    LastActivity   time.Time
    BytesSent      uint64
    BytesReceived  uint64
    mutex          sync.Mutex
}

// ContentInfo tracks content availability at a peer
type ContentInfo struct {
    Hash      string
    Size      int64
    Chunks    []bool
    Available bool
}

// SignalingServer handles WebRTC signaling
type SignalingServer struct {
    upgrader websocket.Upgrader
    peers    map[string]*SignalingPeer
    mutex    sync.RWMutex
}

// SignalingPeer represents a peer in signaling
type SignalingPeer struct {
    ID       string
    Conn     *websocket.Conn
    Content  []string
    Location GeoLocation
}

// NewWebRTCCDN creates a new WebRTC CDN instance
func NewWebRTCCDN(config *Config) (*WebRTCCDN, error) {
    // Configure ICE servers
    iceServers := []webrtc.ICEServer{}
    
    // Add STUN servers
    for _, stun := range config.StunServers {
        iceServers = append(iceServers, webrtc.ICEServer{
            URLs: []string{stun},
        })
    }
    
    // Add TURN servers
    for _, turn := range config.TurnServers {
        iceServers = append(iceServers, webrtc.ICEServer{
            URLs:           turn.URLs,
            Username:       turn.Username,
            Credential:     turn.Credential,
            CredentialType: webrtc.ICECredentialTypePassword,
        })
    }

    cdn := &WebRTCCDN{
        config:     config,
        peers:      make(map[string]*Peer),
        content:    NewContentStore(),
        iceServers: iceServers,
        stats:      NewCDNStats(),
    }

    // Initialize signaling server
    cdn.signaling = &SignalingServer{
        upgrader: websocket.Upgrader{
            CheckOrigin: func(r *http.Request) bool { return true },
        },
        peers: make(map[string]*SignalingPeer),
    }

    return cdn, nil
}

// Start starts the WebRTC CDN
func (cdn *WebRTCCDN) Start(ctx context.Context) error {
    // Start signaling server
    go cdn.signaling.Start(cdn.config.SignalingAddr)

    // Start peer manager
    go cdn.managePeers(ctx)

    // Start stats collector
    go cdn.collectStats(ctx)

    return nil
}

// CreatePeerConnection creates a new peer connection
func (cdn *WebRTCCDN) CreatePeerConnection(peerID string) (*Peer, error) {
    // Create peer connection configuration
    config := webrtc.Configuration{
        ICEServers: cdn.iceServers,
    }

    // Create peer connection
    pc, err := webrtc.NewPeerConnection(config)
    if err != nil {
        return nil, fmt.Errorf("failed to create peer connection: %w", err)
    }

    peer := &Peer{
        ID:           peerID,
        Connection:   pc,
        Content:      make(map[string]*ContentInfo),
        LastActivity: time.Now(),
    }

    // Set up ICE connection state handler
    pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
        cdn.handleICEStateChange(peer, state)
    })

    // Set up data channel handler
    pc.OnDataChannel(func(dc *webrtc.DataChannel) {
        cdn.handleDataChannel(peer, dc)
    })

    return peer, nil
}

// handleDataChannel handles incoming data channels
func (cdn *WebRTCCDN) handleDataChannel(peer *Peer, dc *webrtc.DataChannel) {
    peer.mutex.Lock()
    peer.DataChannel = dc
    peer.mutex.Unlock()

    // Set up data channel handlers
    dc.OnOpen(func() {
        cdn.onDataChannelOpen(peer)
    })

    dc.OnMessage(func(msg webrtc.DataChannelMessage) {
        cdn.handleMessage(peer, msg)
    })

    dc.OnClose(func() {
        cdn.onDataChannelClose(peer)
    })
}

// Message types
const (
    MessageTypeRequest     = "request"
    MessageTypeResponse    = "response"
    MessageTypeChunk       = "chunk"
    MessageTypeInventory   = "inventory"
    MessageTypePing        = "ping"
    MessageTypePong        = "pong"
)

// Message represents a P2P message
type Message struct {
    Type      string          `json:"type"`
    ID        string          `json:"id"`
    ContentID string          `json:"content_id,omitempty"`
    ChunkID   int             `json:"chunk_id,omitempty"`
    Data      json.RawMessage `json:"data,omitempty"`
}

// handleMessage processes incoming messages
func (cdn *WebRTCCDN) handleMessage(peer *Peer, msg webrtc.DataChannelMessage) {
    var message Message
    if err := json.Unmarshal(msg.Data, &message); err != nil {
        return
    }

    peer.LastActivity = time.Now()

    switch message.Type {
    case MessageTypeRequest:
        cdn.handleContentRequest(peer, message)
    case MessageTypeInventory:
        cdn.handleInventoryUpdate(peer, message)
    case MessageTypePing:
        cdn.handlePing(peer, message)
    }
}

// handleContentRequest handles content requests from peers
func (cdn *WebRTCCDN) handleContentRequest(peer *Peer, msg Message) {
    var request ContentRequest
    if err := json.Unmarshal(msg.Data, &request); err != nil {
        return
    }

    // Check if we have the content
    chunk, err := cdn.content.GetChunk(request.ContentID, request.ChunkID)
    if err != nil {
        cdn.sendError(peer, msg.ID, "chunk not found")
        return
    }

    // Send chunk
    response := ChunkResponse{
        ContentID: request.ContentID,
        ChunkID:   request.ChunkID,
        Data:      chunk,
    }

    cdn.sendChunk(peer, msg.ID, response)
    
    // Update stats
    atomic.AddUint64(&peer.BytesSent, uint64(len(chunk)))
}

// ContentStore manages content storage
type ContentStore struct {
    chunks map[string]map[int][]byte
    mutex  sync.RWMutex
}

// NewContentStore creates a new content store
func NewContentStore() *ContentStore {
    return &ContentStore{
        chunks: make(map[string]map[int][]byte),
    }
}

// StoreChunk stores a content chunk
func (cs *ContentStore) StoreChunk(contentID string, chunkID int, data []byte) error {
    cs.mutex.Lock()
    defer cs.mutex.Unlock()

    if _, exists := cs.chunks[contentID]; !exists {
        cs.chunks[contentID] = make(map[int][]byte)
    }

    cs.chunks[contentID][chunkID] = data
    return nil
}

// GetChunk retrieves a content chunk
func (cs *ContentStore) GetChunk(contentID string, chunkID int) ([]byte, error) {
    cs.mutex.RLock()
    defer cs.mutex.RUnlock()

    chunks, exists := cs.chunks[contentID]
    if !exists {
        return nil, fmt.Errorf("content not found")
    }

    chunk, exists := chunks[chunkID]
    if !exists {
        return nil, fmt.Errorf("chunk not found")
    }

    return chunk, nil
}

// P2PContentDelivery handles content delivery between peers
type P2PContentDelivery struct {
    cdn         *WebRTCCDN
    downloader  *ChunkDownloader
    uploader    *ChunkUploader
    scheduler   *DeliveryScheduler
}

// ChunkDownloader downloads chunks from peers
type ChunkDownloader struct {
    cdn           *WebRTCCDN
    activeJobs    map[string]*DownloadJob
    jobsMutex     sync.Mutex
    maxConcurrent int
}

// DownloadJob represents an active download
type DownloadJob struct {
    ContentID    string
    TotalChunks  int
    Downloaded   []bool
    Peers        []*Peer
    StartTime    time.Time
    BytesLoaded  uint64
}

// DownloadContent downloads content from peers
func (cd *ChunkDownloader) DownloadContent(ctx context.Context, contentID string) error {
    // Find peers with content
    peers := cd.cdn.findPeersWithContent(contentID)
    if len(peers) == 0 {
        return fmt.Errorf("no peers have content")
    }

    job := &DownloadJob{
        ContentID:   contentID,
        TotalChunks: cd.cdn.content.GetChunkCount(contentID),
        Downloaded:  make([]bool, cd.cdn.content.GetChunkCount(contentID)),
        Peers:       peers,
        StartTime:   time.Now(),
    }

    cd.jobsMutex.Lock()
    cd.activeJobs[contentID] = job
    cd.jobsMutex.Unlock()

    // Download chunks in parallel
    var wg sync.WaitGroup
    semaphore := make(chan struct{}, cd.maxConcurrent)

    for i := 0; i < job.TotalChunks; i++ {
        if job.Downloaded[i] {
            continue
        }

        wg.Add(1)
        go func(chunkID int) {
            defer wg.Done()
            semaphore <- struct{}{}
            defer func() { <-semaphore }()

            cd.downloadChunk(ctx, job, chunkID)
        }(i)
    }

    wg.Wait()
    return nil
}

// BrowserIntegration provides browser-side WebRTC integration
type BrowserIntegration struct {
    script string
}

// GetBrowserScript returns the JavaScript for browser integration
func (bi *BrowserIntegration) GetBrowserScript() string {
    return `
class WebRTCCDN {
    constructor(signalingURL) {
        this.signalingURL = signalingURL;
        this.peers = new Map();
        this.content = new Map();
        this.ws = null;
        this.localPeerID = this.generatePeerID();
        this.init();
    }

    async init() {
        // Connect to signaling server
        this.ws = new WebSocket(this.signalingURL);
        
        this.ws.onopen = () => {
            console.log('Connected to signaling server');
            this.register();
        };

        this.ws.onmessage = async (event) => {
            const message = JSON.parse(event.data);
            await this.handleSignalingMessage(message);
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }

    generatePeerID() {
        return 'peer-' + Math.random().toString(36).substr(2, 9);
    }

    register() {
        this.sendSignaling({
            type: 'register',
            peerID: this.localPeerID,
            content: Array.from(this.content.keys())
        });
    }

    async createPeerConnection(remotePeerID) {
        const config = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' }
            ]
        };

        const pc = new RTCPeerConnection(config);
        const peer = {
            id: remotePeerID,
            connection: pc,
            dataChannel: null
        };

        // Create data channel
        const dataChannel = pc.createDataChannel('cdn', {
            ordered: true,
            maxRetransmits: 3
        });

        dataChannel.onopen = () => {
            console.log('Data channel opened with', remotePeerID);
            peer.dataChannel = dataChannel;
        };

        dataChannel.onmessage = (event) => {
            this.handleDataChannelMessage(peer, event);
        };

        pc.onicecandidate = (event) => {
            if (event.candidate) {
                this.sendSignaling({
                    type: 'ice-candidate',
                    to: remotePeerID,
                    candidate: event.candidate
                });
            }
        };

        this.peers.set(remotePeerID, peer);
        return pc;
    }

    async downloadContent(contentID) {
        // Find peers with content
        const peers = await this.findPeersWithContent(contentID);
        if (peers.length === 0) {
            throw new Error('No peers have this content');
        }

        // Download from multiple peers in parallel
        const chunks = await Promise.all(
            peers.map(peer => this.downloadFromPeer(peer, contentID))
        );

        // Combine chunks
        return this.combineChunks(chunks);
    }

    async downloadFromPeer(peer, contentID) {
        return new Promise((resolve, reject) => {
            const requestID = this.generateRequestID();
            
            // Send request
            this.sendToPeer(peer, {
                type: 'request',
                id: requestID,
                contentID: contentID
            });

            // Set timeout
            const timeout = setTimeout(() => {
                reject(new Error('Download timeout'));
            }, 30000);

            // Wait for response
            this.pendingRequests.set(requestID, {
                resolve: (data) => {
                    clearTimeout(timeout);
                    resolve(data);
                },
                reject: reject
            });
        });
    }

    sendToPeer(peer, message) {
        if (peer.dataChannel && peer.dataChannel.readyState === 'open') {
            peer.dataChannel.send(JSON.stringify(message));
        }
    }
}

// Initialize CDN
const cdn = new WebRTCCDN('wss://cdn.example.com/signaling');

// Export for use
window.WebRTCCDN = cdn;
`
}

// SignalingProtocol handles WebRTC signaling
type SignalingProtocol struct {
    Type      string          `json:"type"`
    From      string          `json:"from"`
    To        string          `json:"to,omitempty"`
    Data      json.RawMessage `json:"data,omitempty"`
}

// Start starts the signaling server
func (ss *SignalingServer) Start(addr string) error {
    http.HandleFunc("/signaling", ss.handleWebSocket)
    return http.ListenAndServe(addr, nil)
}

// handleWebSocket handles WebSocket connections
func (ss *SignalingServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
    conn, err := ss.upgrader.Upgrade(w, r, nil)
    if err != nil {
        return
    }
    defer conn.Close()

    peerID := r.URL.Query().Get("peer_id")
    if peerID == "" {
        peerID = generatePeerID()
    }

    peer := &SignalingPeer{
        ID:   peerID,
        Conn: conn,
    }

    ss.mutex.Lock()
    ss.peers[peerID] = peer
    ss.mutex.Unlock()

    defer func() {
        ss.mutex.Lock()
        delete(ss.peers, peerID)
        ss.mutex.Unlock()
    }()

    // Handle messages
    for {
        var msg SignalingProtocol
        if err := conn.ReadJSON(&msg); err != nil {
            break
        }

        msg.From = peerID
        ss.handleSignalingMessage(msg)
    }
}

// CDNStats tracks CDN statistics
type CDNStats struct {
    TotalPeers      int
    ActiveTransfers int
    BytesDelivered  uint64
    ChunksServed    uint64
    mutex           sync.RWMutex
}

// NewCDNStats creates new CDN statistics tracker
func NewCDNStats() *CDNStats {
    return &CDNStats{}
}

// GetStats returns current statistics
func (cs *CDNStats) GetStats() map[string]interface{} {
    cs.mutex.RLock()
    defer cs.mutex.RUnlock()

    return map[string]interface{}{
        "total_peers":      cs.TotalPeers,
        "active_transfers": cs.ActiveTransfers,
        "bytes_delivered":  cs.BytesDelivered,
        "chunks_served":    cs.ChunksServed,
    }
}
```

## Testing

```go
package webrtccdn

import (
    "context"
    "testing"
    "time"
)

func TestWebRTCCDN(t *testing.T) {
    config := &Config{
        SignalingAddr: "localhost:8080",
        StunServers:   []string{"stun:stun.l.google.com:19302"},
        MaxPeers:      100,
        ChunkSize:     1024 * 1024, // 1MB chunks
        BufferSize:    10,
    }

    cdn, err := NewWebRTCCDN(config)
    if err != nil {
        t.Fatalf("Failed to create CDN: %v", err)
    }

    ctx := context.Background()
    if err := cdn.Start(ctx); err != nil {
        t.Fatalf("Failed to start CDN: %v", err)
    }

    // Test peer connection
    peer, err := cdn.CreatePeerConnection("test-peer")
    if err != nil {
        t.Fatalf("Failed to create peer connection: %v", err)
    }

    if peer.ID != "test-peer" {
        t.Errorf("Expected peer ID 'test-peer', got %s", peer.ID)
    }
}

func TestContentStore(t *testing.T) {
    store := NewContentStore()

    // Test storing and retrieving chunks
    contentID := "test-content"
    chunkData := []byte("test chunk data")

    err := store.StoreChunk(contentID, 0, chunkData)
    if err != nil {
        t.Fatalf("Failed to store chunk: %v", err)
    }

    retrieved, err := store.GetChunk(contentID, 0)
    if err != nil {
        t.Fatalf("Failed to get chunk: %v", err)
    }

    if string(retrieved) != string(chunkData) {
        t.Errorf("Retrieved chunk doesn't match stored chunk")
    }
}

func TestChunkDownloader(t *testing.T) {
    cdn, _ := NewWebRTCCDN(&Config{
        ChunkSize: 1024,
    })

    downloader := &ChunkDownloader{
        cdn:           cdn,
        activeJobs:    make(map[string]*DownloadJob),
        maxConcurrent: 5,
    }

    // Simulate download
    job := &DownloadJob{
        ContentID:   "test-content",
        TotalChunks: 10,
        Downloaded:  make([]bool, 10),
        StartTime:   time.Now(),
    }

    downloader.activeJobs["test-content"] = job

    if len(downloader.activeJobs) != 1 {
        t.Errorf("Expected 1 active job, got %d", len(downloader.activeJobs))
    }
}

func BenchmarkDataChannel(b *testing.B) {
    config := &Config{
        ChunkSize: 1024 * 1024, // 1MB
    }

    cdn, _ := NewWebRTCCDN(config)
    store := cdn.content

    // Pre-populate content
    contentID := "bench-content"
    chunkData := make([]byte, config.ChunkSize)
    
    for i := 0; i < 10; i++ {
        store.StoreChunk(contentID, i, chunkData)
    }

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        store.GetChunk(contentID, i%10)
    }
}
```

## Configuration

```yaml
webrtc_cdn:
  signaling:
    address: ":8080"
    ssl:
      enabled: true
      cert: "/etc/ssl/cdn.crt"
      key: "/etc/ssl/cdn.key"
      
  ice_servers:
    stun:
      - "stun:stun.l.google.com:19302"
      - "stun:stun1.l.google.com:19302"
    turn:
      - urls: ["turn:turn.example.com:3478"]
        username: "user"
        credential: "pass"
        
  p2p:
    max_peers: 50
    chunk_size: 1048576  # 1MB
    buffer_size: 10
    timeout: 30s
    
  content:
    max_cache_size: "10GB"
    chunk_ttl: "24h"
    
  performance:
    max_concurrent_transfers: 10
    bandwidth_limit: "100MB/s"
```

## Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webrtc-cdn
spec:
  replicas: 3
  selector:
    matchLabels:
      app: webrtc-cdn
  template:
    metadata:
      labels:
        app: webrtc-cdn
    spec:
      containers:
      - name: cdn
        image: blackhole/webrtc-cdn:latest
        ports:
        - containerPort: 8080
        - containerPort: 3478/udp
        env:
        - name: SIGNALING_ADDR
          value: ":8080"
        - name: MAX_PEERS
          value: "100"
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
---
apiVersion: v1
kind: Service
metadata:
  name: webrtc-cdn
spec:
  type: LoadBalancer
  selector:
    app: webrtc-cdn
  ports:
  - name: signaling
    port: 8080
    targetPort: 8080
  - name: turn
    port: 3478
    targetPort: 3478
    protocol: UDP
```