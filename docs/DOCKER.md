# Docker Documentation for Blackhole Network

This guide provides comprehensive instructions for building, running, and deploying Blackhole Network using Docker.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Building Images](#building-images)
3. [Running with Docker Compose](#running-with-docker-compose)
4. [Available Profiles](#available-profiles)
5. [Environment Variables](#environment-variables)
6. [Volume Management](#volume-management)
7. [Network Configuration](#network-configuration)
8. [Health Checks](#health-checks)
9. [Security Considerations](#security-considerations)
10. [Production Deployment](#production-deployment)
11. [Monitoring Setup](#monitoring-setup)
12. [Troubleshooting](#troubleshooting)

## Quick Start

Get Blackhole Network running in under 5 minutes:

```bash
# Clone the repository
git clone https://github.com/yourusername/blackholenetwork.git
cd blackholenetwork

# Build and run with Docker Compose
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f blackhole

# Access the web dashboard
open http://localhost:8080
```

## Building Images

### Development Image

The development image includes debugging tools and hot reload capabilities:

```dockerfile
# Dockerfile.dev
FROM golang:1.21-alpine AS builder

# Install development dependencies
RUN apk add --no-cache git make gcc musl-dev

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build with debug symbols
RUN go build -gcflags="all=-N -l" -o blackhole ./cmd/blackhole

# Development stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /app/blackhole .

# Expose ports
EXPOSE 8080 4001 5001

# Run the application
CMD ["./blackhole"]
```

Build the development image:

```bash
docker build -f Dockerfile.dev -t blackhole:dev .
```

### Production Image

The production image is optimized for size and security:

```dockerfile
# Dockerfile
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git make gcc musl-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build optimized binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X main.version=$(git describe --tags --always)" \
    -o blackhole ./cmd/blackhole

# Final stage
FROM scratch

# Copy SSL certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary
COPY --from=builder /app/blackhole /blackhole

# Create non-root user
USER 1000:1000

EXPOSE 8080 4001 5001

ENTRYPOINT ["/blackhole"]
```

Build the production image:

```bash
docker build -t blackhole:latest .
```

## Running with Docker Compose

### Basic docker-compose.yml

```yaml
version: '3.8'

services:
  blackhole:
    image: blackhole:latest
    container_name: blackhole
    restart: unless-stopped
    ports:
      - "8080:8080"  # Web dashboard
      - "4001:4001"  # P2P swarm
      - "5001:5001"  # IPFS API
    volumes:
      - blackhole-data:/data
      - blackhole-config:/config
    environment:
      - NODE_ENV=production
      - LOG_LEVEL=info
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - blackhole-network

volumes:
  blackhole-data:
  blackhole-config:

networks:
  blackhole-network:
    driver: bridge
```

### Advanced docker-compose.yml with all services

```yaml
version: '3.8'

services:
  blackhole:
    image: blackhole:latest
    container_name: blackhole
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "4001:4001"
      - "5001:5001"
    volumes:
      - blackhole-data:/data
      - blackhole-config:/config
      - ./config/blackhole.yaml:/config/blackhole.yaml:ro
    environment:
      - NODE_ENV=production
      - LOG_LEVEL=info
      - METRICS_ENABLED=true
      - METRICS_PORT=9090
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - blackhole-network
    depends_on:
      - redis
    labels:
      - "prometheus.io/scrape=true"
      - "prometheus.io/port=9090"

  redis:
    image: redis:7-alpine
    container_name: blackhole-redis
    restart: unless-stopped
    volumes:
      - redis-data:/data
    networks:
      - blackhole-network
    command: redis-server --appendonly yes

  prometheus:
    image: prom/prometheus:latest
    container_name: blackhole-prometheus
    restart: unless-stopped
    volumes:
      - ./deployments/monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/usr/share/prometheus/console_libraries'
      - '--web.console.templates=/usr/share/prometheus/consoles'
    ports:
      - "9091:9090"
    networks:
      - blackhole-network

  grafana:
    image: grafana/grafana:latest
    container_name: blackhole-grafana
    restart: unless-stopped
    volumes:
      - grafana-data:/var/lib/grafana
      - ./deployments/monitoring/grafana/datasources:/etc/grafana/provisioning/datasources:ro
      - ./deployments/monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false
    ports:
      - "3000:3000"
    networks:
      - blackhole-network
    depends_on:
      - prometheus

volumes:
  blackhole-data:
  blackhole-config:
  redis-data:
  prometheus-data:
  grafana-data:

networks:
  blackhole-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

## Available Profiles

Docker Compose profiles allow you to run different configurations:

### Default Profile
Basic Blackhole Network node:
```bash
docker-compose up -d
```

### Development Profile
Includes development tools and debugging:
```bash
docker-compose --profile dev up -d
```

### Monitoring Profile
Includes Prometheus and Grafana:
```bash
docker-compose --profile monitoring up -d
```

Define profiles in docker-compose.yml:
```yaml
services:
  blackhole:
    # ... base configuration ...

  blackhole-dev:
    profiles: ["dev"]
    image: blackhole:dev
    volumes:
      - .:/app
      - /app/node_modules
    environment:
      - NODE_ENV=development
      - DEBUG=true

  prometheus:
    profiles: ["monitoring"]
    # ... prometheus configuration ...

  grafana:
    profiles: ["monitoring"]
    # ... grafana configuration ...
```

## Environment Variables

### Core Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment (development/production) | `production` |
| `LOG_LEVEL` | Logging level (debug/info/warn/error) | `info` |
| `HTTP_PORT` | Web dashboard port | `8080` |
| `P2P_PORT` | P2P swarm port | `4001` |
| `IPFS_PORT` | IPFS API port | `5001` |

### Resource Management

| Variable | Description | Default |
|----------|-------------|---------|
| `MAX_STORAGE_GB` | Maximum storage allocation | `100` |
| `MAX_BANDWIDTH_MBPS` | Maximum bandwidth allocation | `100` |
| `MAX_CPU_PERCENT` | Maximum CPU allocation | `80` |
| `MAX_MEMORY_GB` | Maximum memory allocation | `4` |

### Security

| Variable | Description | Default |
|----------|-------------|---------|
| `ENABLE_TLS` | Enable TLS for web interface | `false` |
| `TLS_CERT_PATH` | Path to TLS certificate | `/config/cert.pem` |
| `TLS_KEY_PATH` | Path to TLS key | `/config/key.pem` |
| `AUTH_ENABLED` | Enable authentication | `false` |
| `AUTH_TOKEN` | Authentication token | Generated |

### Monitoring

| Variable | Description | Default |
|----------|-------------|---------|
| `METRICS_ENABLED` | Enable Prometheus metrics | `false` |
| `METRICS_PORT` | Prometheus metrics port | `9090` |
| `TRACE_ENABLED` | Enable distributed tracing | `false` |
| `TRACE_ENDPOINT` | Jaeger endpoint | `http://jaeger:14268/api/traces` |

## Volume Management

### Data Volumes

```yaml
volumes:
  # Main data storage
  blackhole-data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /mnt/blackhole/data

  # Configuration files
  blackhole-config:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /etc/blackhole

  # Logs
  blackhole-logs:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /var/log/blackhole
```

### Backup Strategy

```bash
# Backup data volume
docker run --rm -v blackhole-data:/data -v $(pwd):/backup alpine \
  tar czf /backup/blackhole-backup-$(date +%Y%m%d).tar.gz -C /data .

# Restore data volume
docker run --rm -v blackhole-data:/data -v $(pwd):/backup alpine \
  tar xzf /backup/blackhole-backup-20240105.tar.gz -C /data
```

### Volume Permissions

Ensure proper permissions for volumes:

```bash
# Create directories with correct permissions
mkdir -p /mnt/blackhole/{data,config,logs}
chown -R 1000:1000 /mnt/blackhole
chmod -R 755 /mnt/blackhole
```

## Network Configuration

### Bridge Network

Default configuration for isolated communication:

```yaml
networks:
  blackhole-network:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 172.20.0.0/16
          gateway: 172.20.0.1
```

### Host Network

For maximum performance (Linux only):

```yaml
services:
  blackhole:
    network_mode: host
    # Note: port mapping is not needed with host network
```

### Custom Network with IPv6

```yaml
networks:
  blackhole-network:
    driver: bridge
    enable_ipv6: true
    ipam:
      driver: default
      config:
        - subnet: 172.20.0.0/16
        - subnet: 2001:db8::/64
```

### Port Forwarding

Ensure these ports are accessible:

```bash
# Check if ports are open
netstat -tuln | grep -E '(8080|4001|5001)'

# UFW firewall rules
sudo ufw allow 8080/tcp comment 'Blackhole Web Dashboard'
sudo ufw allow 4001/tcp comment 'Blackhole P2P'
sudo ufw allow 5001/tcp comment 'Blackhole IPFS API'
```

## Health Checks

### Application Health Check

```yaml
healthcheck:
  test: ["CMD", "wget", "-q", "--spider", "http://localhost:8080/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s
```

### Custom Health Check Script

```bash
#!/bin/sh
# healthcheck.sh

# Check web server
if ! wget -q --spider http://localhost:8080/health; then
  exit 1
fi

# Check P2P connectivity
if ! nc -z localhost 4001; then
  exit 1
fi

# Check IPFS API
if ! wget -q --spider http://localhost:5001/api/v0/id; then
  exit 1
fi

exit 0
```

### Monitoring Health Status

```bash
# Check container health
docker inspect blackhole --format='{{.State.Health.Status}}'

# View health check logs
docker inspect blackhole --format='{{range .State.Health.Log}}{{.Output}}{{end}}'
```

## Security Considerations

### 1. Run as Non-Root User

```dockerfile
# In Dockerfile
RUN addgroup -g 1000 blackhole && \
    adduser -D -u 1000 -G blackhole blackhole

USER blackhole
```

### 2. Read-Only Root Filesystem

```yaml
services:
  blackhole:
    read_only: true
    tmpfs:
      - /tmp
      - /var/run
```

### 3. Security Options

```yaml
services:
  blackhole:
    security_opt:
      - no-new-privileges:true
      - seccomp:unconfined
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
      - NET_RAW
```

### 4. Network Isolation

```yaml
services:
  blackhole:
    networks:
      - frontend
      - backend

  redis:
    networks:
      - backend
    # Not exposed to frontend

networks:
  frontend:
    external: true
  backend:
    internal: true
```

### 5. Secrets Management

```yaml
services:
  blackhole:
    secrets:
      - db_password
      - api_key
    environment:
      - DB_PASSWORD_FILE=/run/secrets/db_password
      - API_KEY_FILE=/run/secrets/api_key

secrets:
  db_password:
    external: true
  api_key:
    external: true
```

Create secrets:
```bash
echo "mysecretpassword" | docker secret create db_password -
echo "myapikey" | docker secret create api_key -
```

### 6. TLS Configuration

```yaml
services:
  blackhole:
    volumes:
      - ./certs:/certs:ro
    environment:
      - ENABLE_TLS=true
      - TLS_CERT_PATH=/certs/cert.pem
      - TLS_KEY_PATH=/certs/key.pem
```

Generate self-signed certificates:
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/key.pem -out certs/cert.pem \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

## Production Deployment

### 1. Use Docker Swarm

Initialize swarm:
```bash
docker swarm init
```

Deploy stack:
```yaml
# docker-stack.yml
version: '3.8'

services:
  blackhole:
    image: blackhole:latest
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      placement:
        constraints:
          - node.role == worker
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
```

Deploy:
```bash
docker stack deploy -c docker-stack.yml blackhole
```

### 2. Use Kubernetes

```yaml
# kubernetes/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blackhole
spec:
  replicas: 3
  selector:
    matchLabels:
      app: blackhole
  template:
    metadata:
      labels:
        app: blackhole
    spec:
      containers:
      - name: blackhole
        image: blackhole:latest
        ports:
        - containerPort: 8080
        - containerPort: 4001
        - containerPort: 5001
        resources:
          limits:
            memory: "4Gi"
            cpu: "2"
          requests:
            memory: "2Gi"
            cpu: "1"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

### 3. Load Balancing

Using Traefik:
```yaml
services:
  traefik:
    image: traefik:v2.10
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro

  blackhole:
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.blackhole.rule=Host(`blackhole.example.com`)"
      - "traefik.http.routers.blackhole.entrypoints=websecure"
      - "traefik.http.routers.blackhole.tls=true"
      - "traefik.http.services.blackhole.loadbalancer.server.port=8080"
```

### 4. Auto-scaling

```yaml
services:
  blackhole:
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
      # Auto-scaling based on CPU
      resources:
        limits:
          cpus: '2'
        reservations:
          cpus: '0.5'
```

### 5. Logging

Centralized logging with ELK:
```yaml
services:
  blackhole:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
        labels: "service=blackhole"

  filebeat:
    image: elastic/filebeat:8.11.0
    volumes:
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
    command: filebeat -e -strict.perms=false
```

## Monitoring Setup

### Prometheus Configuration

See `/deployments/monitoring/prometheus.yml` for full configuration.

### Grafana Dashboards

Import the dashboard from `/deployments/monitoring/grafana/dashboards/dashboard.yml`.

Key metrics to monitor:
- Node availability and uptime
- Resource utilization (CPU, memory, storage, bandwidth)
- P2P network statistics
- Request latency and throughput
- Error rates and types

### Alerting Rules

```yaml
# prometheus/alerts.yml
groups:
  - name: blackhole
    rules:
      - alert: HighCPUUsage
        expr: rate(process_cpu_seconds_total[5m]) > 0.8
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage detected"

      - alert: LowDiskSpace
        expr: node_filesystem_avail_bytes / node_filesystem_size_bytes < 0.1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Low disk space available"
```

## Troubleshooting

### Common Issues

#### 1. Container Won't Start

Check logs:
```bash
docker logs blackhole
docker-compose logs -f blackhole
```

Common causes:
- Port conflicts
- Missing environment variables
- Insufficient permissions
- Corrupted data volume

#### 2. P2P Connection Issues

```bash
# Check if P2P port is accessible
docker exec blackhole nc -zv localhost 4001

# Check peer connections
docker exec blackhole curl http://localhost:5001/api/v0/swarm/peers

# Check firewall rules
sudo iptables -L -n | grep 4001
```

#### 3. High Memory Usage

```bash
# Check memory usage
docker stats blackhole

# Limit memory
docker update --memory="2g" --memory-swap="2g" blackhole
```

#### 4. Data Corruption

```bash
# Stop container
docker-compose stop blackhole

# Backup current data
mv /mnt/blackhole/data /mnt/blackhole/data.backup

# Start fresh
docker-compose up -d blackhole
```

### Debug Mode

Enable debug logging:
```yaml
services:
  blackhole:
    environment:
      - LOG_LEVEL=debug
      - DEBUG=true
    command: ["./blackhole", "--debug"]
```

### Performance Tuning

```yaml
services:
  blackhole:
    sysctls:
      - net.core.somaxconn=1024
      - net.ipv4.tcp_syncookies=0
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
```

### Container Shell Access

```bash
# Access running container
docker exec -it blackhole sh

# Debug with all capabilities
docker run -it --rm --cap-add=ALL --security-opt seccomp=unconfined \
  -v blackhole-data:/data blackhole:latest sh
```

### Network Debugging

```bash
# Inspect network
docker network inspect blackhole_blackhole-network

# Test connectivity between containers
docker exec blackhole ping redis

# Trace network traffic
docker exec blackhole tcpdump -i eth0 -w /tmp/capture.pcap
```

## Best Practices

1. **Always use specific image tags** in production
2. **Implement proper health checks** for all services
3. **Use volume mounts** for persistent data
4. **Set resource limits** to prevent resource exhaustion
5. **Enable logging** with proper rotation
6. **Regular backups** of data volumes
7. **Monitor system metrics** continuously
8. **Keep images updated** with security patches
9. **Use secrets** for sensitive configuration
10. **Document your deployment** configuration

## Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Reference](https://docs.docker.com/compose/compose-file/)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
