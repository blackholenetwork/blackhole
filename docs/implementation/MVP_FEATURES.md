# MVP Feature Definition

## Core Features for MVP Release

### 1. P2P Networking Layer
**Status**: Required for MVP

#### Features Included
- [x] Node discovery using Kademlia DHT
- [x] NAT traversal with STUN/TURN
- [x] Encrypted node-to-node communication
- [x] Automatic peer connection management
- [x] Network health monitoring

#### Implementation Details
```
- Use libp2p for networking stack
- mDNS for local peer discovery
- DHT for global peer discovery
- TLS 1.3 for transport encryption
- Max 50 peer connections per node
```

#### NOT Included in MVP
- [ ] Advanced routing algorithms
- [ ] Multi-path connections
- [ ] Custom protocols beyond libp2p
- [ ] Mesh networking capabilities

---

### 2. Storage Service
**Status**: Required for MVP

#### Features Included
- [x] File upload with CID generation
- [x] File retrieval by CID
- [x] Reed-Solomon erasure coding (10+4)
- [x] Automatic chunk distribution
- [x] Basic garbage collection

#### Implementation Details
```
- 4MB chunk size
- Store chunks on 14 nodes (10 data + 4 parity)
- Retrieve with any 10 chunks
- SHA-256 for content addressing
- BadgerDB for local metadata
```

#### NOT Included in MVP
- [ ] Dynamic erasure coding parameters
- [ ] Compression options
- [ ] Streaming large files
- [ ] Directory/folder support
- [ ] Version control

---

### 3. Credit System
**Status**: Required for MVP

#### Features Included
- [x] Credit balance tracking
- [x] Earn credits by providing storage
- [x] Spend credits to store files
- [x] Basic transaction ledger
- [x] Hourly settlement cycle

#### Implementation Details
```
- 1 credit = 1 GB-hour of storage
- Providers earn 0.1 credit per GB-hour
- Consumers pay 0.15 credit per GB-hour
- 0.05 credit network fee for sustainability
- Local ledger with periodic sync
```

#### NOT Included in MVP
- [ ] Dynamic pricing
- [ ] Credit trading/exchange
- [ ] Multi-currency support
- [ ] Advanced economic models
- [ ] Micro-payments

---

### 4. Node Management
**Status**: Required for MVP

#### Features Included
- [x] Simple CLI for node operation
- [x] Start/stop node commands
- [x] Status and health checks
- [x] Basic configuration file
- [x] Resource limit settings

#### CLI Commands (MVP)
```bash
blackhole start              # Start node
blackhole stop               # Stop node
blackhole status             # Show node status
blackhole store <file>       # Store a file
blackhole get <cid>          # Retrieve a file
blackhole balance            # Show credit balance
blackhole config             # Edit configuration
```

#### NOT Included in MVP
- [ ] GUI interface
- [ ] Web dashboard
- [ ] Mobile apps
- [ ] Advanced monitoring
- [ ] Remote management

---

### 5. API Layer
**Status**: Required for MVP

#### Features Included
- [x] REST API for basic operations
- [x] File upload/download endpoints
- [x] Node status endpoints
- [x] Credit balance endpoints
- [x] Basic authentication

#### API Endpoints (MVP)
```
POST   /api/v1/files          # Upload file
GET    /api/v1/files/{cid}    # Download file
GET    /api/v1/node/status    # Node status
GET    /api/v1/credits        # Credit balance
GET    /api/v1/network/peers  # Peer list
```

#### NOT Included in MVP
- [ ] GraphQL API
- [ ] WebSocket streaming
- [ ] Batch operations
- [ ] Advanced querying
- [ ] Rate limiting

---

### 6. Security Features
**Status**: Required for MVP

#### Features Included
- [x] File encryption at rest
- [x] Transport encryption (TLS)
- [x] Node identity (Ed25519 keys)
- [x] Basic access control
- [x] Secure key storage

#### Implementation Details
```
- AES-256-GCM for file encryption
- User controls encryption keys
- Per-file encryption option
- Node keypair for identity
- Keyring for secure storage
```

#### NOT Included in MVP
- [ ] Advanced access control lists
- [ ] Multi-signature support
- [ ] Hardware security modules
- [ ] Quantum-resistant crypto
- [ ] Privacy mixing

---

## Feature Comparison Table

| Feature | MVP | Post-MVP | Enterprise | Never |
|---------|-----|----------|------------|-------|
| P2P Networking | ✓ | | | |
| Basic Storage | ✓ | | | |
| Credit System | ✓ | | | |
| CLI Interface | ✓ | | | |
| REST API | ✓ | | | |
| File Encryption | ✓ | | | |
| Compute Sharing | | ✓ | | |
| GPU Support | | ✓ | | |
| Smart Contracts | | | | ✓ |
| Native Mobile | | ✓ | | |
| Web Dashboard | | ✓ | | |
| IPFS Gateway | | ✓ | | |
| S3 Compatibility | | | ✓ | |
| Blockchain | | | | ✓ |
| Mining/PoW | | | | ✓ |

---

## MVP User Journey

### Storage Provider Journey
```
1. Download blackhole binary
2. Run: blackhole init
3. Run: blackhole start --provider
4. Node automatically:
   - Joins network
   - Advertises storage capacity
   - Accepts storage requests
   - Earns credits hourly
```

### Storage Consumer Journey
```
1. Download blackhole binary
2. Run: blackhole init
3. Get free starter credits (10 credits)
4. Run: blackhole store myfile.pdf
5. Receive CID: QmX...
6. Later: blackhole get QmX... -o myfile.pdf
```

### Developer Journey
```
1. Read API documentation
2. Get API key: blackhole api-key generate
3. Use REST API:
   curl -X POST http://localhost:8080/api/v1/files \
     -H "X-API-Key: xxx" \
     -F "file=@myfile.pdf"
4. Build application using API
```

---

## MVP Limitations (Acceptable)

### Performance
- Max 100MB/s transfer speed (network limited)
- 5-10 second file discovery time
- 1000 files per node limit
- 100GB total storage per node

### Functionality  
- No partial file retrieval
- No file search/indexing
- No metadata beyond CID
- No file sharing/permissions

### Scale
- Network tested up to 100 nodes
- Single region operation
- No geo-replication settings
- Basic load balancing only

---

## Definition of Done for MVP

### Code Complete
- [ ] All MVP features implemented
- [ ] Unit test coverage >80%
- [ ] Integration tests passing
- [ ] No critical bugs
- [ ] Code documented

### Operational
- [ ] Binary builds for Linux/macOS/Windows
- [ ] Installation guide written
- [ ] API documentation complete
- [ ] Example applications working
- [ ] 1-week stability test passed

### Community
- [ ] Beta tested with 10+ users
- [ ] Feedback incorporated
- [ ] Known issues documented
- [ ] Roadmap published
- [ ] Support channels active

---

## Post-MVP Roadmap

### Phase 1 (Months 1-2 post-MVP)
- Compute service (CPU tasks)
- Web dashboard
- Advanced monitoring
- IPFS compatibility layer

### Phase 2 (Months 3-4 post-MVP)
- GPU compute support
- S3-compatible API
- Mobile applications
- Enterprise features

### Phase 3 (Months 5-6 post-MVP)
- Advanced economic models
- Multi-region support
- Governance system
- Plugin marketplace