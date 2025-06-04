# Deployment Standards

This document defines standards for building, packaging, deploying, and operating the Blackhole Network in production.

## 1. Build Standards

### Build Pipeline
```yaml
# .github/workflows/build.yml
name: Build and Test

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  build:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        go: ['1.22']
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: ${{ matrix.go }}
      
      - name: Cache Go modules
        uses: actions/cache@v3
        with:
          path: ~/go/pkg/mod
          key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}
      
      - name: Install dependencies
        run: go mod download
      
      - name: Run tests
        run: go test -v -race -coverprofile=coverage.out ./...
      
      - name: Check coverage
        run: |
          go tool cover -func=coverage.out
          coverage=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
          if (( $(echo "$coverage < 80" | bc -l) )); then
            echo "Coverage is below 80%"
            exit 1
          fi
      
      - name: Run linters
        uses: golangci/golangci-lint-action@v3
        with:
          version: latest
      
      - name: Build binary
        run: |
          go build -ldflags="-s -w -X main.Version=${{ github.sha }}" \
            -o blackhole-${{ matrix.os }} ./cmd/blackhole
```

### Build Configuration
```go
// build/config.go
package build

var (
    // Set at build time
    Version   = "dev"
    Commit    = "unknown"
    BuildTime = "unknown"
    GoVersion = runtime.Version()
)

// Makefile
VERSION := $(shell git describe --tags --always --dirty)
COMMIT := $(shell git rev-parse --short HEAD)
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')

LDFLAGS := -ldflags "\
    -s -w \
    -X github.com/blackhole/build.Version=$(VERSION) \
    -X github.com/blackhole/build.Commit=$(COMMIT) \
    -X github.com/blackhole/build.BuildTime=$(BUILD_TIME)"

build:
	go build $(LDFLAGS) -o blackhole ./cmd/blackhole

build-all:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/blackhole-linux-amd64
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/blackhole-linux-arm64
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/blackhole-darwin-amd64
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/blackhole-darwin-arm64
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/blackhole-windows-amd64.exe
```

### Reproducible Builds
```dockerfile
# Dockerfile.build
FROM golang:1.22-alpine AS builder

# Install certificates and build tools
RUN apk add --no-cache ca-certificates git make

# Create non-root user
RUN adduser -D -g '' appuser

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build with specific versions
ARG VERSION
ARG COMMIT
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT}" \
    -o blackhole ./cmd/blackhole

# Final stage
FROM scratch

# Copy certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy user
COPY --from=builder /etc/passwd /etc/passwd

# Copy binary
COPY --from=builder /build/blackhole /blackhole

USER appuser

ENTRYPOINT ["/blackhole"]
```

## 2. Container Standards

### Docker Image Structure
```dockerfile
# Dockerfile
FROM gcr.io/distroless/static:nonroot

# Labels
LABEL org.opencontainers.image.source="https://github.com/blackhole/blackhole"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.vendor="Blackhole Network"
LABEL org.opencontainers.image.title="Blackhole Node"
LABEL org.opencontainers.image.description="Decentralized storage and compute node"

# Copy binary
COPY --chown=nonroot:nonroot blackhole /usr/local/bin/blackhole

# Create data directory
WORKDIR /data
VOLUME ["/data"]

# Expose ports
EXPOSE 8080 4001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD ["/usr/local/bin/blackhole", "health"]

# Run as non-root
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/blackhole"]
CMD ["node", "start"]
```

### Container Security
```yaml
# docker-compose.yml
version: '3.8'

services:
  blackhole:
    image: blackhole/node:latest
    container_name: blackhole-node
    
    # Security options
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    read_only: true
    
    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
    
    # Volumes
    volumes:
      - type: volume
        source: blackhole-data
        target: /data
      - type: tmpfs
        target: /tmp
    
    # Network
    ports:
      - "8080:8080"
      - "4001:4001"
    networks:
      - blackhole-net
    
    # Environment
    environment:
      - NODE_ENV=production
      - LOG_LEVEL=info
    env_file:
      - .env.production
    
    # Health and restart
    healthcheck:
      test: ["CMD", "blackhole", "health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    restart: unless-stopped

volumes:
  blackhole-data:
    driver: local

networks:
  blackhole-net:
    driver: bridge
```

## 3. Kubernetes Deployment

### Deployment Manifest
```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blackhole-node
  labels:
    app: blackhole
    component: node
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: blackhole
      component: node
  template:
    metadata:
      labels:
        app: blackhole
        component: node
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
    spec:
      # Security context
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        fsGroup: 65534
        seccompProfile:
          type: RuntimeDefault
      
      # Service account
      serviceAccountName: blackhole-node
      
      # Init container for setup
      initContainers:
      - name: init-config
        image: busybox:1.36
        command: ['sh', '-c', 'cp /config/* /data/']
        volumeMounts:
        - name: config
          mountPath: /config
        - name: data
          mountPath: /data
      
      # Main container
      containers:
      - name: blackhole
        image: blackhole/node:v1.0.0
        imagePullPolicy: IfNotPresent
        
        # Security
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        
        # Ports
        ports:
        - name: http
          containerPort: 8080
          protocol: TCP
        - name: p2p
          containerPort: 4001
          protocol: TCP
        - name: metrics
          containerPort: 9090
          protocol: TCP
        
        # Environment
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: NODE_IP
          valueFrom:
            fieldRef:
              fieldPath: status.podIP
        - name: NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        envFrom:
        - configMapRef:
            name: blackhole-config
        - secretRef:
            name: blackhole-secrets
        
        # Resources
        resources:
          requests:
            cpu: 1
            memory: 2Gi
            ephemeral-storage: 10Gi
          limits:
            cpu: 2
            memory: 4Gi
            ephemeral-storage: 20Gi
        
        # Probes
        startupProbe:
          httpGet:
            path: /health/startup
            port: http
          initialDelaySeconds: 10
          periodSeconds: 10
          failureThreshold: 30
        
        livenessProbe:
          httpGet:
            path: /health/live
            port: http
          initialDelaySeconds: 0
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        
        readinessProbe:
          httpGet:
            path: /health/ready
            port: http
          initialDelaySeconds: 0
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        
        # Volumes
        volumeMounts:
        - name: data
          mountPath: /data
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /cache
      
      # Volumes
      volumes:
      - name: config
        configMap:
          name: blackhole-config
      - name: data
        persistentVolumeClaim:
          claimName: blackhole-data
      - name: tmp
        emptyDir:
          medium: Memory
          sizeLimit: 1Gi
      - name: cache
        emptyDir:
          sizeLimit: 5Gi
```

### Service Configuration
```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: blackhole-api
  labels:
    app: blackhole
    component: api
spec:
  type: ClusterIP
  ports:
  - name: http
    port: 80
    targetPort: http
    protocol: TCP
  selector:
    app: blackhole
    component: node
---
apiVersion: v1
kind: Service
metadata:
  name: blackhole-p2p
  labels:
    app: blackhole
    component: p2p
spec:
  type: LoadBalancer
  ports:
  - name: p2p
    port: 4001
    targetPort: p2p
    protocol: TCP
  selector:
    app: blackhole
    component: node
```

## 4. Configuration Management

### Configuration Structure
```yaml
# config/production.yaml
node:
  id: "${NODE_ID}"  # From environment
  region: "us-east-1"
  
api:
  host: "0.0.0.0"
  port: 8080
  read_timeout: 30s
  write_timeout: 30s
  
storage:
  path: "/data/storage"
  max_size: "500GB"
  cache_size: "10GB"
  
network:
  listen_addresses:
    - "/ip4/0.0.0.0/tcp/4001"
    - "/ip6/::/tcp/4001"
  bootstrap_peers:
    - "/dnsaddr/bootstrap1.blackhole.network/p2p/QmNodeID1"
    - "/dnsaddr/bootstrap2.blackhole.network/p2p/QmNodeID2"
  
monitoring:
  metrics_port: 9090
  log_level: "${LOG_LEVEL:-info}"
  log_format: "json"
  
security:
  tls_enabled: true
  tls_cert: "/certs/tls.crt"
  tls_key: "/certs/tls.key"
  
resources:
  cpu_limit: "80%"
  memory_limit: "4GB"
  bandwidth_limit: "100Mbps"
```

### Secret Management
```yaml
# k8s/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: blackhole-secrets
type: Opaque
stringData:
  NODE_PRIVATE_KEY: "${NODE_PRIVATE_KEY}"
  API_KEY: "${API_KEY}"
  DATABASE_URL: "${DATABASE_URL}"
---
# Using external secrets operator
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: blackhole-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: blackhole-secrets
  data:
  - secretKey: NODE_PRIVATE_KEY
    remoteRef:
      key: blackhole/node
      property: private_key
```

## 5. Deployment Process

### GitOps Workflow
```yaml
# argocd/application.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: blackhole
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/blackhole/k8s-config
    targetRevision: main
    path: overlays/production
  destination:
    server: https://kubernetes.default.svc
    namespace: blackhole
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
      allowEmpty: false
    syncOptions:
    - Validate=true
    - CreateNamespace=true
    - PrunePropagationPolicy=foreground
    retry:
      limit: 5
      backoff:
        duration: 5s
        factor: 2
        maxDuration: 3m
```

### Progressive Rollout
```yaml
# Using Flagger for canary deployments
apiVersion: flagger.app/v1beta1
kind: Canary
metadata:
  name: blackhole
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: blackhole-node
  progressDeadlineSeconds: 3600
  service:
    port: 80
    targetPort: http
    gateways:
    - public-gateway.istio-system.svc.cluster.local
    hosts:
    - api.blackhole.network
  analysis:
    interval: 1m
    threshold: 10
    maxWeight: 50
    stepWeight: 5
    metrics:
    - name: request-success-rate
      thresholdRange:
        min: 99
      interval: 1m
    - name: request-duration
      thresholdRange:
        max: 500
      interval: 1m
    webhooks:
    - name: load-test
      url: http://flagger-loadtester.test/
      timeout: 5s
      metadata:
        cmd: "hey -z 2m -q 10 -c 2 http://api.blackhole.network/"
```

## 6. Monitoring and Observability

### Prometheus Metrics
```go
// metrics/metrics.go
package metrics

var (
    // Node metrics
    NodeInfo = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "blackhole_node_info",
            Help: "Node information",
        },
        []string{"version", "commit", "region"},
    )
    
    // Resource metrics
    ResourceUsage = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "blackhole_resource_usage",
            Help: "Resource usage by type",
        },
        []string{"resource", "unit"},
    )
    
    // P2P metrics
    PeerCount = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "blackhole_peer_count",
            Help: "Number of connected peers",
        },
    )
)

func init() {
    prometheus.MustRegister(NodeInfo)
    prometheus.MustRegister(ResourceUsage)
    prometheus.MustRegister(PeerCount)
}
```

### Grafana Dashboard
```json
{
  "dashboard": {
    "title": "Blackhole Network",
    "panels": [
      {
        "title": "Node Status",
        "targets": [
          {
            "expr": "up{job=\"blackhole\"}"
          }
        ]
      },
      {
        "title": "Request Rate",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])"
          }
        ]
      },
      {
        "title": "Error Rate",
        "targets": [
          {
            "expr": "rate(http_requests_total{status=~\"5..\"}[5m])"
          }
        ]
      },
      {
        "title": "P99 Latency",
        "targets": [
          {
            "expr": "histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))"
          }
        ]
      }
    ]
  }
}
```

## 7. Backup and Recovery

### Backup Strategy
```yaml
# k8s/backup.yaml
apiVersion: velero.io/v1
kind: Schedule
metadata:
  name: blackhole-backup
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  template:
    includedNamespaces:
    - blackhole
    includedResources:
    - persistentvolumeclaims
    - persistentvolumes
    - secrets
    - configmaps
    ttl: 720h  # 30 days
    storageLocation: s3-backup
    volumeSnapshotLocations:
    - aws-snapshots
```

### Disaster Recovery
```bash
#!/bin/bash
# scripts/disaster-recovery.sh

# 1. Restore from backup
velero restore create --from-backup blackhole-backup-20240604

# 2. Verify data integrity
kubectl exec -n blackhole blackhole-0 -- blackhole verify --full

# 3. Rebuild indexes if needed
kubectl exec -n blackhole blackhole-0 -- blackhole index rebuild

# 4. Verify network connectivity
kubectl exec -n blackhole blackhole-0 -- blackhole network test

# 5. Resume normal operations
kubectl scale deployment blackhole-node --replicas=3
```

## 8. Production Checklist

### Pre-Deployment
- [ ] All tests passing
- [ ] Security scan completed
- [ ] Dependencies up to date
- [ ] Configuration validated
- [ ] Backup tested
- [ ] Rollback plan ready
- [ ] Monitoring configured
- [ ] Alerts configured
- [ ] Documentation updated
- [ ] Change approved

### Post-Deployment
- [ ] Health checks passing
- [ ] Metrics visible
- [ ] No error spike
- [ ] Performance normal
- [ ] Canary metrics good
- [ ] Full rollout completed
- [ ] Old version cleaned up
- [ ] Stakeholders notified

### Emergency Response
```go
// Emergency shutdown procedure
func EmergencyShutdown() {
    // 1. Stop accepting traffic
    server.GracefulStop()
    
    // 2. Drain in-flight requests
    waitForDrain(30 * time.Second)
    
    // 3. Flush data to disk
    storage.Flush()
    
    // 4. Notify peers
    network.BroadcastShutdown()
    
    // 5. Final cleanup
    cleanup()
    
    os.Exit(0)
}
```

These deployment standards ensure reliable, secure, and observable production deployments of the Blackhole Network.