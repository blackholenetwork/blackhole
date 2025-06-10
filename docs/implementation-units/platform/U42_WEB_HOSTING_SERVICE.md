# U42: Web Hosting Service

## Overview
The Web Hosting Service provides static website hosting capabilities for the Blackhole network, enabling users to deploy and manage websites without traditional hosting infrastructure.

## Technical Specifications

### Core Components

#### 1. Static Site Engine
```go
package hosting

import (
    "crypto/tls"
    "fmt"
    "io"
    "net/http"
    "path/filepath"
    "strings"
    "time"
)

type StaticSiteEngine struct {
    storage      StorageBackend
    cache        *CacheManager
    compression  *CompressionEngine
    metrics      *MetricsCollector
}

type Site struct {
    ID           string
    Domain       string
    Path         string
    SSL          *SSLConfig
    Headers      map[string]string
    Redirects    []RedirectRule
    ErrorPages   map[int]string
    Created      time.Time
    Updated      time.Time
}

type StorageBackend interface {
    Store(siteID, path string, content []byte) error
    Retrieve(siteID, path string) ([]byte, error)
    Delete(siteID, path string) error
    List(siteID string) ([]string, error)
}

func (sse *StaticSiteEngine) ServeSite(w http.ResponseWriter, r *http.Request) {
    // Extract domain from request
    domain := extractDomain(r.Host)
    
    // Find site configuration
    site, err := sse.storage.GetSiteByDomain(domain)
    if err != nil {
        http.Error(w, "Site not found", http.StatusNotFound)
        return
    }
    
    // Process request path
    path := cleanPath(r.URL.Path)
    if path == "/" {
        path = "/index.html"
    }
    
    // Check cache
    if cached, ok := sse.cache.Get(site.ID, path); ok {
        sse.serveContent(w, r, cached, site)
        return
    }
    
    // Retrieve content from storage
    content, err := sse.storage.Retrieve(site.ID, path)
    if err != nil {
        sse.serveErrorPage(w, r, site, http.StatusNotFound)
        return
    }
    
    // Cache content
    sse.cache.Set(site.ID, path, content)
    
    // Serve content
    sse.serveContent(w, r, content, site)
}

func (sse *StaticSiteEngine) serveContent(w http.ResponseWriter, r *http.Request, 
    content []byte, site *Site) {
    // Apply custom headers
    for key, value := range site.Headers {
        w.Header().Set(key, value)
    }
    
    // Set content type
    contentType := detectContentType(r.URL.Path, content)
    w.Header().Set("Content-Type", contentType)
    
    // Apply compression if supported
    if sse.compression.ShouldCompress(contentType, len(content)) {
        content = sse.compression.Compress(content, r.Header.Get("Accept-Encoding"))
    }
    
    // Set cache headers
    w.Header().Set("Cache-Control", "public, max-age=3600")
    w.Header().Set("ETag", generateETag(content))
    
    // Write response
    w.WriteHeader(http.StatusOK)
    w.Write(content)
    
    // Record metrics
    sse.metrics.RecordRequest(site.ID, r.URL.Path, len(content))
}
```

#### 2. Domain Manager
```go
package hosting

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    "math/big"
    "net"
    "sync"
    "time"
)

type DomainManager struct {
    dnsProvider  DNSProvider
    certManager  *CertificateManager
    validator    *DomainValidator
    storage      DomainStorage
    mu           sync.RWMutex
}

type Domain struct {
    Name         string
    SiteID       string
    Status       DomainStatus
    DNSRecords   []DNSRecord
    Certificate  *Certificate
    Verified     bool
    Created      time.Time
}

type DomainStatus string

const (
    DomainPending    DomainStatus = "pending"
    DomainActive     DomainStatus = "active"
    DomainInactive   DomainStatus = "inactive"
    DomainExpired    DomainStatus = "expired"
)

func (dm *DomainManager) AddDomain(siteID, domainName string) (*Domain, error) {
    dm.mu.Lock()
    defer dm.mu.Unlock()
    
    // Validate domain
    if err := dm.validator.ValidateDomain(domainName); err != nil {
        return nil, fmt.Errorf("invalid domain: %w", err)
    }
    
    // Check if domain already exists
    if existing, _ := dm.storage.GetDomain(domainName); existing != nil {
        return nil, fmt.Errorf("domain already registered")
    }
    
    // Create domain record
    domain := &Domain{
        Name:    domainName,
        SiteID:  siteID,
        Status:  DomainPending,
        Created: time.Now(),
    }
    
    // Configure DNS records
    dnsRecords := dm.generateDNSRecords(domainName)
    domain.DNSRecords = dnsRecords
    
    // Save domain
    if err := dm.storage.SaveDomain(domain); err != nil {
        return nil, fmt.Errorf("failed to save domain: %w", err)
    }
    
    // Initiate domain verification
    go dm.verifyDomain(domain)
    
    return domain, nil
}

func (dm *DomainManager) generateDNSRecords(domain string) []DNSRecord {
    return []DNSRecord{
        {
            Type:  "A",
            Name:  domain,
            Value: dm.getLoadBalancerIP(),
            TTL:   300,
        },
        {
            Type:  "AAAA",
            Name:  domain,
            Value: dm.getLoadBalancerIPv6(),
            TTL:   300,
        },
        {
            Type:  "CNAME",
            Name:  fmt.Sprintf("www.%s", domain),
            Value: domain,
            TTL:   300,
        },
    }
}

func (dm *DomainManager) verifyDomain(domain *Domain) {
    // Generate verification token
    token := dm.generateVerificationToken()
    
    // Create verification record
    verificationRecord := DNSRecord{
        Type:  "TXT",
        Name:  fmt.Sprintf("_blackhole-verify.%s", domain.Name),
        Value: token,
        TTL:   300,
    }
    
    // Wait for DNS propagation
    time.Sleep(5 * time.Minute)
    
    // Check DNS record
    for i := 0; i < 12; i++ { // Try for 1 hour
        if dm.checkDNSRecord(domain.Name, token) {
            domain.Verified = true
            domain.Status = DomainActive
            
            // Issue SSL certificate
            cert, err := dm.certManager.IssueCertificate(domain.Name)
            if err == nil {
                domain.Certificate = cert
            }
            
            dm.storage.UpdateDomain(domain)
            return
        }
        time.Sleep(5 * time.Minute)
    }
    
    // Verification failed
    domain.Status = DomainInactive
    dm.storage.UpdateDomain(domain)
}
```

#### 3. SSL Certificate Handler
```go
package hosting

import (
    "context"
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    "math/big"
    "sync"
    "time"
    
    "golang.org/x/crypto/acme"
    "golang.org/x/crypto/acme/autocert"
)

type CertificateManager struct {
    acmeClient   *acme.Client
    storage      CertificateStorage
    cache        *CertificateCache
    renewalQueue *RenewalQueue
    mu           sync.RWMutex
}

type Certificate struct {
    Domain      string
    Certificate []byte
    PrivateKey  []byte
    Chain       []byte
    NotBefore   time.Time
    NotAfter    time.Time
    Renewable   bool
}

func (cm *CertificateManager) IssueCertificate(domain string) (*Certificate, error) {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    
    // Check if certificate already exists
    if cert, err := cm.storage.GetCertificate(domain); err == nil && cert.IsValid() {
        return cert, nil
    }
    
    // Generate private key
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, fmt.Errorf("failed to generate private key: %w", err)
    }
    
    // Create certificate request
    template := x509.CertificateRequest{
        Subject: pkix.Name{
            CommonName: domain,
        },
        DNSNames: []string{domain, fmt.Sprintf("www.%s", domain)},
    }
    
    csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create CSR: %w", err)
    }
    
    // Request certificate from ACME
    ctx := context.Background()
    order, err := cm.acmeClient.AuthorizeOrder(ctx, acme.DomainIDs(domain))
    if err != nil {
        return nil, fmt.Errorf("failed to authorize order: %w", err)
    }
    
    // Complete challenges
    for _, authzURL := range order.AuthzURLs {
        authz, err := cm.acmeClient.GetAuthorization(ctx, authzURL)
        if err != nil {
            continue
        }
        
        if authz.Status == acme.StatusValid {
            continue
        }
        
        // Find HTTP-01 challenge
        var chal *acme.Challenge
        for _, c := range authz.Challenges {
            if c.Type == "http-01" {
                chal = c
                break
            }
        }
        
        if chal == nil {
            return nil, fmt.Errorf("no HTTP-01 challenge found")
        }
        
        // Respond to challenge
        token := chal.Token
        keyAuth, err := cm.acmeClient.HTTP01ChallengeResponse(token)
        if err != nil {
            return nil, fmt.Errorf("failed to get challenge response: %w", err)
        }
        
        // Set up HTTP handler for challenge
        cm.setupChallengeHandler(domain, token, keyAuth)
        
        // Accept challenge
        if _, err := cm.acmeClient.Accept(ctx, chal); err != nil {
            return nil, fmt.Errorf("failed to accept challenge: %w", err)
        }
        
        // Wait for validation
        if err := cm.waitForValidation(ctx, authzURL); err != nil {
            return nil, fmt.Errorf("validation failed: %w", err)
        }
    }
    
    // Finalize order
    order, err = cm.acmeClient.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
    if err != nil {
        return nil, fmt.Errorf("failed to finalize order: %w", err)
    }
    
    // Download certificate
    certs, err := cm.acmeClient.FetchCert(ctx, order.CertURL, true)
    if err != nil {
        return nil, fmt.Errorf("failed to fetch certificate: %w", err)
    }
    
    // Parse certificate
    cert, err := x509.ParseCertificate(certs[0])
    if err != nil {
        return nil, fmt.Errorf("failed to parse certificate: %w", err)
    }
    
    // Create certificate object
    certificate := &Certificate{
        Domain:      domain,
        Certificate: certs[0],
        PrivateKey:  x509.MarshalPKCS1PrivateKey(privateKey),
        Chain:       joinCertificates(certs[1:]),
        NotBefore:   cert.NotBefore,
        NotAfter:    cert.NotAfter,
        Renewable:   true,
    }
    
    // Save certificate
    if err := cm.storage.SaveCertificate(certificate); err != nil {
        return nil, fmt.Errorf("failed to save certificate: %w", err)
    }
    
    // Schedule renewal
    cm.renewalQueue.Schedule(certificate)
    
    return certificate, nil
}

func (cm *CertificateManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
    domain := hello.ServerName
    
    // Check cache
    if cached := cm.cache.Get(domain); cached != nil {
        return cached, nil
    }
    
    // Load from storage
    cert, err := cm.storage.GetCertificate(domain)
    if err != nil {
        return nil, err
    }
    
    // Check if renewal is needed
    if cert.NeedsRenewal() {
        go cm.renewCertificate(cert)
    }
    
    // Create TLS certificate
    tlsCert, err := tls.X509KeyPair(cert.Certificate, cert.PrivateKey)
    if err != nil {
        return nil, err
    }
    
    // Cache certificate
    cm.cache.Set(domain, &tlsCert)
    
    return &tlsCert, nil
}
```

#### 4. Content Deployment
```go
package hosting

import (
    "archive/zip"
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "io"
    "mime"
    "path/filepath"
    "strings"
    "sync"
    "time"
)

type DeploymentManager struct {
    storage       StorageBackend
    validator     *ContentValidator
    preprocessor  *ContentPreprocessor
    cdn           *CDNManager
    deployments   map[string]*Deployment
    mu            sync.RWMutex
}

type Deployment struct {
    ID          string
    SiteID      string
    Version     string
    Status      DeploymentStatus
    Files       map[string]*DeployedFile
    Manifest    *DeploymentManifest
    StartTime   time.Time
    EndTime     time.Time
    Error       string
}

type DeploymentStatus string

const (
    DeploymentPending    DeploymentStatus = "pending"
    DeploymentInProgress DeploymentStatus = "in_progress"
    DeploymentCompleted  DeploymentStatus = "completed"
    DeploymentFailed     DeploymentStatus = "failed"
    DeploymentRolledBack DeploymentStatus = "rolled_back"
)

type DeployedFile struct {
    Path        string
    Hash        string
    Size        int64
    ContentType string
    Compressed  bool
}

func (dm *DeploymentManager) Deploy(siteID string, content io.Reader) (*Deployment, error) {
    // Create deployment
    deployment := &Deployment{
        ID:        generateDeploymentID(),
        SiteID:    siteID,
        Version:   generateVersion(),
        Status:    DeploymentPending,
        Files:     make(map[string]*DeployedFile),
        StartTime: time.Now(),
    }
    
    dm.mu.Lock()
    dm.deployments[deployment.ID] = deployment
    dm.mu.Unlock()
    
    // Process deployment asynchronously
    go dm.processDeployment(deployment, content)
    
    return deployment, nil
}

func (dm *DeploymentManager) processDeployment(deployment *Deployment, content io.Reader) {
    deployment.Status = DeploymentInProgress
    
    // Extract files
    files, err := dm.extractFiles(content)
    if err != nil {
        dm.failDeployment(deployment, fmt.Errorf("failed to extract files: %w", err))
        return
    }
    
    // Validate content
    if err := dm.validator.ValidateFiles(files); err != nil {
        dm.failDeployment(deployment, fmt.Errorf("validation failed: %w", err))
        return
    }
    
    // Preprocess files
    processedFiles, err := dm.preprocessor.Process(files)
    if err != nil {
        dm.failDeployment(deployment, fmt.Errorf("preprocessing failed: %w", err))
        return
    }
    
    // Deploy files
    for path, content := range processedFiles {
        if err := dm.deployFile(deployment, path, content); err != nil {
            dm.failDeployment(deployment, fmt.Errorf("failed to deploy %s: %w", path, err))
            return
        }
    }
    
    // Generate deployment manifest
    deployment.Manifest = dm.generateManifest(deployment)
    
    // Update CDN
    if err := dm.cdn.InvalidateCache(deployment.SiteID); err != nil {
        // Log error but don't fail deployment
        fmt.Printf("CDN invalidation failed: %v\n", err)
    }
    
    // Complete deployment
    deployment.Status = DeploymentCompleted
    deployment.EndTime = time.Now()
}

func (dm *DeploymentManager) extractFiles(content io.Reader) (map[string][]byte, error) {
    // Read content into buffer
    buf := new(bytes.Buffer)
    if _, err := io.Copy(buf, content); err != nil {
        return nil, err
    }
    
    // Open zip reader
    reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
    if err != nil {
        return nil, err
    }
    
    files := make(map[string][]byte)
    
    // Extract files
    for _, file := range reader.File {
        if file.FileInfo().IsDir() {
            continue
        }
        
        // Open file
        rc, err := file.Open()
        if err != nil {
            return nil, err
        }
        
        // Read content
        content, err := io.ReadAll(rc)
        rc.Close()
        if err != nil {
            return nil, err
        }
        
        // Normalize path
        path := filepath.Clean(file.Name)
        if strings.HasPrefix(path, "/") {
            path = path[1:]
        }
        
        files[path] = content
    }
    
    return files, nil
}

func (dm *DeploymentManager) deployFile(deployment *Deployment, path string, 
    content []byte) error {
    // Calculate hash
    hash := sha256.Sum256(content)
    hashStr := hex.EncodeToString(hash[:])
    
    // Detect content type
    contentType := mime.TypeByExtension(filepath.Ext(path))
    if contentType == "" {
        contentType = "application/octet-stream"
    }
    
    // Compress if beneficial
    compressed := false
    if shouldCompress(contentType, len(content)) {
        content = compress(content)
        compressed = true
    }
    
    // Store file
    key := fmt.Sprintf("%s/%s/%s", deployment.SiteID, deployment.Version, path)
    if err := dm.storage.Store(key, content); err != nil {
        return err
    }
    
    // Record deployed file
    deployment.Files[path] = &DeployedFile{
        Path:        path,
        Hash:        hashStr,
        Size:        int64(len(content)),
        ContentType: contentType,
        Compressed:  compressed,
    }
    
    return nil
}

func (dm *DeploymentManager) Rollback(siteID, deploymentID string) error {
    dm.mu.RLock()
    deployment, exists := dm.deployments[deploymentID]
    dm.mu.RUnlock()
    
    if !exists {
        return fmt.Errorf("deployment not found")
    }
    
    if deployment.SiteID != siteID {
        return fmt.Errorf("deployment does not belong to site")
    }
    
    // Find previous deployment
    previous := dm.findPreviousDeployment(siteID, deployment)
    if previous == nil {
        return fmt.Errorf("no previous deployment found")
    }
    
    // Activate previous deployment
    if err := dm.activateDeployment(previous); err != nil {
        return fmt.Errorf("rollback failed: %w", err)
    }
    
    deployment.Status = DeploymentRolledBack
    
    return nil
}
```

### Integration Points

#### 1. P2P Network Integration
```go
type P2PHostingBridge struct {
    p2pNetwork   P2PNetwork
    hosting      *StaticSiteEngine
    replication  *ReplicationManager
}

func (phb *P2PHostingBridge) DistributeSite(site *Site) error {
    // Create content manifest
    manifest := phb.createManifest(site)
    
    // Distribute to P2P network
    nodes := phb.p2pNetwork.SelectNodes(3)
    for _, node := range nodes {
        go phb.replicateToNode(node, manifest)
    }
    
    return nil
}
```

#### 2. Storage Backend Integration
```go
type DistributedStorage struct {
    local      LocalStorage
    p2p        P2PStorage
    redundancy int
}

func (ds *DistributedStorage) Store(key string, content []byte) error {
    // Store locally first
    if err := ds.local.Store(key, content); err != nil {
        return err
    }
    
    // Replicate to P2P network
    return ds.p2p.Replicate(key, content, ds.redundancy)
}
```

### API Reference

#### REST API Endpoints
```yaml
/api/v1/sites:
  post:
    summary: Create new site
    requestBody:
      domain: string
      settings: object
    responses:
      201: Site created
      
/api/v1/sites/{siteId}/deploy:
  post:
    summary: Deploy site content
    requestBody:
      content: binary (zip file)
    responses:
      202: Deployment started
      
/api/v1/domains:
  post:
    summary: Add domain
    requestBody:
      domain: string
      siteId: string
    responses:
      201: Domain added
      
/api/v1/certificates/{domain}:
  get:
    summary: Get certificate status
    responses:
      200: Certificate details
```

### Configuration
```yaml
hosting:
  storage:
    type: distributed
    replication: 3
    cache_size: 1GB
    
  ssl:
    provider: letsencrypt
    email: admin@blackhole.network
    staging: false
    
  cdn:
    enabled: true
    cache_ttl: 3600
    edge_locations:
      - us-east
      - eu-west
      - asia-pacific
      
  limits:
    max_file_size: 10MB
    max_site_size: 1GB
    max_deployments: 100
```

### Deployment Guide

1. **Initial Setup**
   ```bash
   # Configure hosting service
   blackhole hosting init
   
   # Set up SSL
   blackhole hosting ssl configure
   
   # Start service
   blackhole hosting start
   ```

2. **Site Deployment**
   ```bash
   # Create site
   blackhole site create --domain example.com
   
   # Deploy content
   blackhole site deploy ./dist --site-id <id>
   
   # Check status
   blackhole site status <id>
   ```

3. **Domain Management**
   ```bash
   # Add domain
   blackhole domain add example.com --site <id>
   
   # Verify domain
   blackhole domain verify example.com
   
   # Issue certificate
   blackhole domain ssl example.com
   ```

### Security Considerations

1. **Content Security**
   - Input validation
   - XSS prevention
   - MIME type validation
   - Path traversal protection

2. **SSL/TLS Security**
   - Automatic certificate renewal
   - Strong cipher suites
   - HSTS headers
   - Certificate transparency

3. **Access Control**
   - API authentication
   - Rate limiting
   - DDoS protection
   - Content filtering

### Performance Optimization

1. **Caching Strategy**
   - Edge caching
   - Browser caching
   - ETag generation
   - Cache invalidation

2. **Content Optimization**
   - Automatic compression
   - Image optimization
   - Minification
   - Lazy loading

3. **CDN Integration**
   - Geographic distribution
   - Load balancing
   - Failover handling
   - Performance monitoring