# User Stories and Scenarios

## Epic 1: Node Operator Stories

### Story 1.1: First-Time Node Setup
**As a** computer owner with spare resources
**I want to** set up a Blackhole node quickly
**So that I** can start earning credits for my unused storage

**Acceptance Criteria:**
- [ ] Download single binary (<50MB)
- [ ] Run one command to initialize
- [ ] Node starts without configuration
- [ ] See confirmation of network join
- [ ] View initial stats in <30 seconds

**Example Flow:**
```bash
$ wget https://blackhole.network/download/blackhole-linux-amd64
$ chmod +x blackhole-linux-amd64
$ ./blackhole-linux-amd64 init
✓ Generated node identity: 12D3KooWLRPJAA5o...
✓ Created config at: ~/.blackhole/config.yaml
✓ Allocated 50GB storage at: ~/.blackhole/storage
✓ Ready to start earning credits!

$ ./blackhole-linux-amd64 start
✓ Starting Blackhole node...
✓ Connected to 5 peers
✓ Storage: 0/50GB used
✓ Credits: 0.00 (earning ~1.2/day)
✓ Node running at: http://localhost:8080
```

---

### Story 1.2: Storage Provider Monitoring
**As a** node operator providing storage
**I want to** monitor my node's performance and earnings
**So that I** can optimize my resource allocation

**Acceptance Criteria:**
- [ ] View real-time storage usage
- [ ] See credit earnings per hour/day
- [ ] Monitor network connections
- [ ] Check data transfer stats
- [ ] Get alerts for issues

**Example Output:**
```bash
$ blackhole status --detailed
Node ID:     12D3KooWLRPJAA5o...
Uptime:      7d 14h 23m
Network:     23 peers connected

Storage:
  Capacity:  50.0 GB
  Used:      34.7 GB (69.4%)
  Files:     1,847

Credits:
  Balance:   47.82
  Earned:    +8.4 (last 24h)
  Rate:      0.35/hour

Network:
  Upload:    127.3 GB (last 24h)
  Download:  43.2 GB (last 24h)
  Requests:  18,734 (last 24h)
```

---

## Epic 2: Storage User Stories

### Story 2.1: Store Personal Files
**As a** individual user
**I want to** store my important files securely
**So that I** have backup with privacy and redundancy

**Acceptance Criteria:**
- [ ] Upload file with one command
- [ ] Receive unique CID immediately
- [ ] File encrypted by default
- [ ] Can retrieve from any device
- [ ] Pay only for storage used

**Example Flow:**
```bash
$ blackhole store ~/Documents/tax-return-2024.pdf --encrypt
✓ Encrypting file...
✓ Splitting into 4MB chunks...
✓ Uploading to network...
✓ Stored successfully!

CID: QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG
Size: 2.3 MB
Cost: 0.15 credits/month
Redundancy: 14 nodes (10+4 erasure coding)
Encryption: AES-256-GCM (key saved to keyring)

$ blackhole get QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG
✓ Retrieving from network...
✓ Verifying integrity...
✓ Decrypting file...
✓ Saved to: ./tax-return-2024.pdf
```

---

### Story 2.2: Developer API Usage
**As a** application developer
**I want to** integrate Blackhole storage into my app
**So that I** can offer decentralized storage to users

**Acceptance Criteria:**
- [ ] Simple REST API
- [ ] Clear documentation
- [ ] SDK for major languages
- [ ] Handle errors gracefully
- [ ] Monitor usage via API

**Example Code (Go):**
```go
package main

import (
    "github.com/blackholenetwork/blackhole-go"
)

func main() {
    // Initialize client
    client := blackhole.NewClient("http://localhost:8080", "api-key")

    // Upload file
    file, _ := os.Open("user-avatar.jpg")
    result, err := client.Store(file, blackhole.Options{
        Encrypt: true,
        Metadata: map[string]string{
            "user": "alice@example.com",
            "type": "avatar",
        },
    })

    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Stored file: %s\n", result.CID)

    // Retrieve file
    data, err := client.Get(result.CID)
    if err != nil {
        log.Fatal(err)
    }

    os.WriteFile("downloaded-avatar.jpg", data, 0644)
}
```

---

## Epic 3: Network Participant Stories

### Story 3.1: Join as Bandwidth Provider
**As a** user with good internet connection
**I want to** share my bandwidth for credits
**So that I** can monetize my unused capacity

**Acceptance Criteria:**
- [ ] Opt-in to bandwidth sharing
- [ ] Set upload/download limits
- [ ] Earn credits for data relayed
- [ ] Monitor bandwidth usage
- [ ] Stop sharing anytime

**Configuration:**
```yaml
# ~/.blackhole/config.yaml
node:
  role: provider

bandwidth:
  enabled: true
  upload_limit: 50  # Mbps
  download_limit: 100  # Mbps
  monthly_cap: 1000  # GB

# Earnings: ~0.01 credits per GB transferred
```

---

### Story 3.2: Emergency File Recovery
**As a** user who lost local files
**I want to** recover my files from the network
**So that I** don't lose important data

**Acceptance Criteria:**
- [ ] List all my stored files
- [ ] Search by date/name/size
- [ ] Bulk download option
- [ ] Verify file integrity
- [ ] Work from new device

**Recovery Flow:**
```bash
$ blackhole recover --list
Your files in the network:
1. QmYwAP... tax-return-2024.pdf     2.3 MB   2024-01-15
2. QmXkCD... family-photos.zip       145 MB   2024-01-20
3. QmPqRs... backup-2024-02.tar      4.7 GB   2024-02-01

$ blackhole recover --all --output ~/recovered/
✓ Recovering 3 files (4.85 GB total)...
[████████████████████████] 100% Complete
✓ All files recovered successfully
✓ Integrity verified with CID matching
```

---

## Epic 4: Economic Participation

### Story 4.1: Credit Management
**As a** active network participant
**I want to** manage my credit balance
**So that I** can optimize earnings and spending

**Acceptance Criteria:**
- [ ] View detailed transaction history
- [ ] Set spending limits
- [ ] Get low balance alerts
- [ ] Export reports
- [ ] Predict future costs

**Credit Report Example:**
```
$ blackhole credits report --last-month

Credit Report (January 2024)
============================
Opening Balance:     125.43
Closing Balance:     187.29

Earnings:
  Storage Provided:  +72.14 (854 GB-hours)
  Bandwidth Relay:   +15.23 (1,523 GB)
  Uptime Bonus:      +5.00 (99.9% uptime)
  Total Earned:      +92.37

Spending:
  File Storage:      -28.74 (287 GB-hours)
  Retrieval Fees:    -1.77 (59 operations)
  Total Spent:       -30.51

Net Change:          +61.86 (+49.4%)
```

---

## Epic 5: Community Stories

### Story 5.1: Contribute to Network Health
**As a** network supporter
**I want to** run a reliable node
**So that I** help maintain network stability

**Acceptance Criteria:**
- [ ] See network health metrics
- [ ] Get reliability score
- [ ] Earn bonus for uptime
- [ ] Participate in consensus
- [ ] Help new nodes bootstrap

**Reputation Display:**
```bash
$ blackhole reputation
Node Reputation Score: 94/100

Factors:
  Uptime:           99.7% (past 30 days)     +25/25
  Response Time:    <50ms average            +20/20
  Data Integrity:   100% successful          +25/25
  Peer Reviews:     4.8/5.0 (47 reviews)    +19/20
  Network Age:      187 days                 +5/10

Tier: Trusted Provider
Benefits:
  - 10% bonus on earnings
  - Priority in storage placement
  - Eligible for governance participation
```

---

## Edge Cases and Error Scenarios

### Scenario: Network Partition
**When** the network splits due to connectivity issues
**Then** nodes should:
- Continue serving cached content
- Queue new uploads locally
- Sync when reconnected
- Not lose credits/data

### Scenario: Malicious Node
**When** a node serves corrupted data
**Then** the system should:
- Detect via hash mismatch
- Retrieve from other nodes
- Penalize bad actor
- Alert affected users

### Scenario: Credit Shortage
**When** user runs out of credits during operation
**Then** the system should:
- Complete current operation
- Prevent new storage
- Offer grace period
- Suggest earning options

---

## Success Metrics

### User Satisfaction
- Setup time: <5 minutes
- First successful storage: <1 minute
- File retrieval time: <5 seconds
- Zero data loss incidents
- 95% positive feedback

### Network Health
- 100+ active nodes
- 99.9% uptime
- <100ms average latency
- Even geographic distribution
- No single point of failure

### Economic Balance
- Credits maintain stable value
- Providers earn living wages
- Storage costs 50% of cloud
- No inflation/deflation spiral
- Fair resource allocation
