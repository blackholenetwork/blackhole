# U44: SDK Libraries

## Overview
The SDK Libraries unit provides comprehensive client libraries and development tools for building applications on the Blackhole network, including API wrappers, language bindings, and automated documentation generation.

## Technical Specifications

### Core Components

#### 1. Client SDK Framework
```go
package sdk

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

type SDKClient struct {
    config     *Config
    httpClient *http.Client
    auth       AuthProvider
    middleware []Middleware
    retryPolicy *RetryPolicy
}

type Config struct {
    BaseURL     string
    APIKey      string
    Timeout     time.Duration
    UserAgent   string
    Debug       bool
    Region      string
}

type AuthProvider interface {
    GetAuthHeader() (string, error)
    RefreshToken() error
    IsValid() bool
}

type Middleware interface {
    Process(req *Request, next func(*Request) (*Response, error)) (*Response, error)
}

type Request struct {
    Method  string
    URL     string
    Headers map[string]string
    Body    interface{}
    Query   map[string]string
}

type Response struct {
    StatusCode int
    Headers    map[string]string
    Body       []byte
    Error      error
}

type RetryPolicy struct {
    MaxAttempts int
    BaseDelay   time.Duration
    MaxDelay    time.Duration
    Multiplier  float64
    Jitter      bool
}

func NewSDKClient(config *Config) *SDKClient {
    return &SDKClient{
        config: config,
        httpClient: &http.Client{
            Timeout: config.Timeout,
        },
        retryPolicy: &RetryPolicy{
            MaxAttempts: 3,
            BaseDelay:   time.Second,
            MaxDelay:    time.Second * 30,
            Multiplier:  2.0,
            Jitter:      true,
        },
    }
}

func (c *SDKClient) Request(ctx context.Context, req *Request) (*Response, error) {
    // Apply middleware
    return c.processWithMiddleware(req, func(r *Request) (*Response, error) {
        return c.executeRequest(ctx, r)
    })
}

func (c *SDKClient) executeRequest(ctx context.Context, req *Request) (*Response, error) {
    var lastErr error
    
    for attempt := 0; attempt < c.retryPolicy.MaxAttempts; attempt++ {
        response, err := c.doRequest(ctx, req)
        if err == nil && !c.shouldRetry(response) {
            return response, nil
        }
        
        lastErr = err
        if err != nil && !c.isRetryableError(err) {
            break
        }
        
        if attempt < c.retryPolicy.MaxAttempts-1 {
            delay := c.calculateDelay(attempt)
            select {
            case <-time.After(delay):
            case <-ctx.Done():
                return nil, ctx.Err()
            }
        }
    }
    
    return nil, fmt.Errorf("request failed after %d attempts: %w", 
        c.retryPolicy.MaxAttempts, lastErr)
}

func (c *SDKClient) doRequest(ctx context.Context, req *Request) (*Response, error) {
    // Build HTTP request
    httpReq, err := c.buildHTTPRequest(ctx, req)
    if err != nil {
        return nil, err
    }
    
    // Add authentication
    if c.auth != nil && c.auth.IsValid() {
        authHeader, err := c.auth.GetAuthHeader()
        if err != nil {
            return nil, err
        }
        httpReq.Header.Set("Authorization", authHeader)
    }
    
    // Execute request
    httpResp, err := c.httpClient.Do(httpReq)
    if err != nil {
        return nil, err
    }
    defer httpResp.Body.Close()
    
    // Read response
    body, err := io.ReadAll(httpResp.Body)
    if err != nil {
        return nil, err
    }
    
    response := &Response{
        StatusCode: httpResp.StatusCode,
        Headers:    make(map[string]string),
        Body:       body,
    }
    
    // Copy headers
    for key, values := range httpResp.Header {
        if len(values) > 0 {
            response.Headers[key] = values[0]
        }
    }
    
    // Check for API errors
    if httpResp.StatusCode >= 400 {
        response.Error = c.parseError(response)
    }
    
    return response, nil
}

// Service-specific clients

type StorageClient struct {
    sdk *SDKClient
}

func (sc *StorageClient) UploadFile(ctx context.Context, key string, 
    data []byte, metadata map[string]string) error {
    
    req := &Request{
        Method: "PUT",
        URL:    fmt.Sprintf("/storage/files/%s", key),
        Body:   data,
        Headers: map[string]string{
            "Content-Type": "application/octet-stream",
        },
    }
    
    // Add metadata headers
    for k, v := range metadata {
        req.Headers[fmt.Sprintf("X-Metadata-%s", k)] = v
    }
    
    resp, err := sc.sdk.Request(ctx, req)
    if err != nil {
        return err
    }
    
    if resp.StatusCode != 200 {
        return fmt.Errorf("upload failed: %s", resp.Error)
    }
    
    return nil
}

func (sc *StorageClient) DownloadFile(ctx context.Context, key string) ([]byte, error) {
    req := &Request{
        Method: "GET",
        URL:    fmt.Sprintf("/storage/files/%s", key),
    }
    
    resp, err := sc.sdk.Request(ctx, req)
    if err != nil {
        return nil, err
    }
    
    if resp.StatusCode != 200 {
        return nil, fmt.Errorf("download failed: %s", resp.Error)
    }
    
    return resp.Body, nil
}

type ComputeClient struct {
    sdk *SDKClient
}

type JobRequest struct {
    Image       string            `json:"image"`
    Command     []string          `json:"command"`
    Args        []string          `json:"args,omitempty"`
    Env         map[string]string `json:"env,omitempty"`
    Resources   ResourceLimits    `json:"resources,omitempty"`
    Timeout     int               `json:"timeout,omitempty"`
}

type ResourceLimits struct {
    CPU    string `json:"cpu"`
    Memory string `json:"memory"`
}

type Job struct {
    ID        string    `json:"id"`
    Status    string    `json:"status"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
    Output    string    `json:"output,omitempty"`
    Error     string    `json:"error,omitempty"`
}

func (cc *ComputeClient) SubmitJob(ctx context.Context, jobReq *JobRequest) (*Job, error) {
    req := &Request{
        Method: "POST",
        URL:    "/compute/jobs",
        Body:   jobReq,
    }
    
    resp, err := cc.sdk.Request(ctx, req)
    if err != nil {
        return nil, err
    }
    
    if resp.StatusCode != 201 {
        return nil, fmt.Errorf("job submission failed: %s", resp.Error)
    }
    
    var job Job
    if err := json.Unmarshal(resp.Body, &job); err != nil {
        return nil, err
    }
    
    return &job, nil
}

func (cc *ComputeClient) GetJob(ctx context.Context, jobID string) (*Job, error) {
    req := &Request{
        Method: "GET",
        URL:    fmt.Sprintf("/compute/jobs/%s", jobID),
    }
    
    resp, err := cc.sdk.Request(ctx, req)
    if err != nil {
        return nil, err
    }
    
    if resp.StatusCode != 200 {
        return nil, fmt.Errorf("failed to get job: %s", resp.Error)
    }
    
    var job Job
    if err := json.Unmarshal(resp.Body, &job); err != nil {
        return nil, err
    }
    
    return &job, nil
}
```

#### 2. Language Bindings Generator
```go
package generator

import (
    "fmt"
    "go/ast"
    "go/parser"
    "go/token"
    "path/filepath"
    "strings"
    "text/template"
)

type BindingGenerator struct {
    spec        *APISpec
    templates   map[string]*template.Template
    outputDir   string
    languages   []Language
}

type APISpec struct {
    Version    string
    BaseURL    string
    Services   []Service
    Types      []TypeDefinition
    Errors     []ErrorDefinition
}

type Service struct {
    Name        string
    Description string
    Methods     []Method
}

type Method struct {
    Name        string
    Description string
    HTTPMethod  string
    Path        string
    Parameters  []Parameter
    Request     *TypeReference
    Response    *TypeReference
    Errors      []string
}

type Parameter struct {
    Name        string
    Type        string
    Required    bool
    Location    string // query, path, header, body
    Description string
}

type TypeDefinition struct {
    Name        string
    Type        string // struct, enum, primitive
    Fields      []Field
    Description string
}

type Field struct {
    Name        string
    Type        string
    Required    bool
    Description string
    Tags        map[string]string
}

type Language struct {
    Name      string
    Extension string
    Templates map[string]string
    Config    map[string]interface{}
}

func NewBindingGenerator(spec *APISpec, outputDir string) *BindingGenerator {
    return &BindingGenerator{
        spec:      spec,
        templates: make(map[string]*template.Template),
        outputDir: outputDir,
        languages: []Language{
            {
                Name:      "go",
                Extension: ".go",
                Templates: map[string]string{
                    "client":   goClientTemplate,
                    "types":    goTypesTemplate,
                    "errors":   goErrorsTemplate,
                },
            },
            {
                Name:      "python",
                Extension: ".py",
                Templates: map[string]string{
                    "client": pythonClientTemplate,
                    "types":  pythonTypesTemplate,
                },
            },
            {
                Name:      "javascript",
                Extension: ".js",
                Templates: map[string]string{
                    "client": jsClientTemplate,
                    "types":  jsTypesTemplate,
                },
            },
        },
    }
}

func (bg *BindingGenerator) GenerateBindings() error {
    for _, language := range bg.languages {
        if err := bg.generateLanguageBindings(language); err != nil {
            return fmt.Errorf("failed to generate %s bindings: %w", language.Name, err)
        }
    }
    return nil
}

func (bg *BindingGenerator) generateLanguageBindings(language Language) error {
    langDir := filepath.Join(bg.outputDir, language.Name)
    if err := os.MkdirAll(langDir, 0755); err != nil {
        return err
    }
    
    // Load templates
    templates := make(map[string]*template.Template)
    for name, templateStr := range language.Templates {
        tmpl, err := template.New(name).Parse(templateStr)
        if err != nil {
            return fmt.Errorf("failed to parse template %s: %w", name, err)
        }
        templates[name] = tmpl
    }
    
    // Generate files
    for name, tmpl := range templates {
        if err := bg.generateFile(tmpl, name, language, langDir); err != nil {
            return err
        }
    }
    
    return nil
}

func (bg *BindingGenerator) generateFile(tmpl *template.Template, name string, 
    language Language, outputDir string) error {
    
    filename := fmt.Sprintf("%s%s", name, language.Extension)
    filepath := filepath.Join(outputDir, filename)
    
    file, err := os.Create(filepath)
    if err != nil {
        return err
    }
    defer file.Close()
    
    data := struct {
        Spec     *APISpec
        Language Language
    }{
        Spec:     bg.spec,
        Language: language,
    }
    
    return tmpl.Execute(file, data)
}

// Go client template
const goClientTemplate = `
package blackhole

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

type Client struct {
    baseURL    string
    httpClient *http.Client
    apiKey     string
    {{range .Spec.Services}}
    {{.Name}} *{{.Name}}Service
    {{end}}
}

func NewClient(apiKey string, options ...Option) *Client {
    client := &Client{
        baseURL: "{{.Spec.BaseURL}}",
        httpClient: &http.Client{
            Timeout: 30 * time.Second,
        },
        apiKey: apiKey,
    }
    
    // Apply options
    for _, option := range options {
        option(client)
    }
    
    // Initialize services
    {{range .Spec.Services}}
    client.{{.Name}} = &{{.Name}}Service{client: client}
    {{end}}
    
    return client
}

type Option func(*Client)

func WithTimeout(timeout time.Duration) Option {
    return func(c *Client) {
        c.httpClient.Timeout = timeout
    }
}

func WithBaseURL(baseURL string) Option {
    return func(c *Client) {
        c.baseURL = baseURL
    }
}

{{range .Spec.Services}}
type {{.Name}}Service struct {
    client *Client
}

{{range .Methods}}
func (s *{{$.Name}}Service) {{.Name}}(ctx context.Context{{range .Parameters}}, {{.Name}} {{.Type}}{{end}}) ({{if .Response}}*{{.Response.Name}}{{else}}error{{end}}, error) {
    // Implementation
    req, err := s.client.newRequest("{{.HTTPMethod}}", "{{.Path}}", {{if .Request}}request{{else}}nil{{end}})
    if err != nil {
        return {{if .Response}}nil, {{end}}err
    }
    
    {{if .Response}}
    var response {{.Response.Name}}
    _, err = s.client.do(ctx, req, &response)
    return &response, err
    {{else}}
    _, err = s.client.do(ctx, req, nil)
    return err
    {{end}}
}
{{end}}
{{end}}
`

// Python client template
const pythonClientTemplate = `
import requests
import json
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime

{{range .Spec.Types}}
@dataclass
class {{.Name}}:
    {{range .Fields}}
    {{.Name}}: {{.Type}}
    {{end}}
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> '{{.Name}}':
        return cls(**data)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            {{range .Fields}}
            '{{.Name}}': self.{{.Name}},
            {{end}}
        }
{{end}}

class BlackholeClient:
    def __init__(self, api_key: str, base_url: str = "{{.Spec.BaseURL}}", timeout: int = 30):
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'blackhole-python-sdk/1.0.0'
        })
        
        {{range .Spec.Services}}
        self.{{.Name}} = {{.Name}}Service(self)
        {{end}}
    
    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}{path}"
        response = self.session.request(method, url, timeout=self.timeout, **kwargs)
        response.raise_for_status()
        return response

{{range .Spec.Services}}
class {{.Name}}Service:
    def __init__(self, client: BlackholeClient):
        self.client = client
    
    {{range .Methods}}
    def {{.Name}}(self{{range .Parameters}}, {{.Name}}: {{.Type}}{{end}}) -> {{if .Response}}{{.Response.Name}}{{else}}None{{end}}:
        """{{.Description}}"""
        response = self.client._request('{{.HTTPMethod}}', '{{.Path}}'{{if .Request}}, json=request.to_dict(){{end}})
        {{if .Response}}
        return {{.Response.Name}}.from_dict(response.json())
        {{else}}
        return None
        {{end}}
    {{end}}
{{end}}
`

// JavaScript client template
const jsClientTemplate = `
class BlackholeClient {
    constructor(apiKey, options = {}) {
        this.apiKey = apiKey;
        this.baseURL = options.baseURL || '{{.Spec.BaseURL}}';
        this.timeout = options.timeout || 30000;
        
        {{range .Spec.Services}}
        this.{{.Name}} = new {{.Name}}Service(this);
        {{end}}
    }
    
    async request(method, path, options = {}) {
        const url = this.baseURL + path;
        const config = {
            method,
            headers: {
                'Authorization': 'Bearer ' + this.apiKey,
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };
        
        if (options.body) {
            config.body = JSON.stringify(options.body);
        }
        
        const response = await fetch(url, config);
        
        if (!response.ok) {
            throw new Error('Request failed: ' + response.statusText);
        }
        
        return response.json();
    }
}

{{range .Spec.Services}}
class {{.Name}}Service {
    constructor(client) {
        this.client = client;
    }
    
    {{range .Methods}}
    async {{.Name}}({{range $i, $p := .Parameters}}{{if $i}}, {{end}}{{$p.Name}}{{end}}) {
        const response = await this.client.request('{{.HTTPMethod}}', '{{.Path}}'{{if .Request}}, {
            body: request
        }{{end}});
        return response;
    }
    {{end}}
}
{{end}}

module.exports = BlackholeClient;
`
```

#### 3. API Wrapper Generator
```go
package wrapper

import (
    "fmt"
    "go/ast"
    "go/format"
    "go/parser"
    "go/token"
    "strings"
)

type APIWrapperGenerator struct {
    parser     *APIParser
    generator  *CodeGenerator
    validator  *SpecValidator
}

type APIParser struct {
    fileSet *token.FileSet
}

func (ap *APIParser) ParseGoPackage(packagePath string) (*APISpec, error) {
    pkgs, err := parser.ParseDir(ap.fileSet, packagePath, nil, parser.ParseComments)
    if err != nil {
        return nil, err
    }
    
    spec := &APISpec{
        Services: []Service{},
        Types:    []TypeDefinition{},
    }
    
    for _, pkg := range pkgs {
        for _, file := range pkg.Files {
            if err := ap.parseFile(file, spec); err != nil {
                return nil, err
            }
        }
    }
    
    return spec, nil
}

func (ap *APIParser) parseFile(file *ast.File, spec *APISpec) error {
    ast.Inspect(file, func(n ast.Node) bool {
        switch node := n.(type) {
        case *ast.TypeSpec:
            if structType, ok := node.Type.(*ast.StructType); ok {
                typeDefinition := ap.parseStruct(node.Name.Name, structType)
                spec.Types = append(spec.Types, typeDefinition)
            }
        case *ast.FuncDecl:
            if ap.isServiceMethod(node) {
                method := ap.parseMethod(node)
                ap.addMethodToService(spec, method)
            }
        }
        return true
    })
    
    return nil
}

func (ap *APIParser) parseStruct(name string, structType *ast.StructType) TypeDefinition {
    typeDef := TypeDefinition{
        Name:   name,
        Type:   "struct",
        Fields: []Field{},
    }
    
    for _, field := range structType.Fields.List {
        for _, name := range field.Names {
            fieldDef := Field{
                Name: name.Name,
                Type: ap.typeToString(field.Type),
            }
            
            // Parse struct tags
            if field.Tag != nil {
                tags := ap.parseStructTags(field.Tag.Value)
                fieldDef.Tags = tags
                
                // Check for JSON tags
                if jsonTag, ok := tags["json"]; ok {
                    parts := strings.Split(jsonTag, ",")
                    if len(parts) > 0 && parts[0] != "-" {
                        fieldDef.Name = parts[0]
                    }
                    fieldDef.Required = !strings.Contains(jsonTag, "omitempty")
                }
            }
            
            typeDef.Fields = append(typeDef.Fields, fieldDef)
        }
    }
    
    return typeDef
}

func (ap *APIParser) parseMethod(funcDecl *ast.FuncDecl) Method {
    method := Method{
        Name:       funcDecl.Name.Name,
        Parameters: []Parameter{},
    }
    
    // Parse function parameters
    if funcDecl.Type.Params != nil {
        for _, param := range funcDecl.Type.Params.List {
            for _, name := range param.Names {
                if name.Name == "ctx" { // Skip context parameter
                    continue
                }
                
                parameter := Parameter{
                    Name: name.Name,
                    Type: ap.typeToString(param.Type),
                }
                method.Parameters = append(method.Parameters, parameter)
            }
        }
    }
    
    // Parse return types
    if funcDecl.Type.Results != nil && len(funcDecl.Type.Results.List) > 0 {
        firstResult := funcDecl.Type.Results.List[0]
        if !ap.isErrorType(firstResult.Type) {
            method.Response = &TypeReference{
                Name: ap.typeToString(firstResult.Type),
            }
        }
    }
    
    // Extract HTTP method and path from comments
    if funcDecl.Doc != nil {
        for _, comment := range funcDecl.Doc.List {
            if strings.Contains(comment.Text, "@http") {
                method.HTTPMethod, method.Path = ap.parseHTTPComment(comment.Text)
            }
        }
    }
    
    return method
}

type CodeGenerator struct {
    templates map[string]*template.Template
}

func (cg *CodeGenerator) GenerateWrapper(spec *APISpec, language string) (string, error) {
    tmpl, exists := cg.templates[language]
    if !exists {
        return "", fmt.Errorf("template for language %s not found", language)
    }
    
    var buf strings.Builder
    if err := tmpl.Execute(&buf, spec); err != nil {
        return "", err
    }
    
    return buf.String(), nil
}

// OpenAPI Spec Generator
type OpenAPIGenerator struct {
    spec *APISpec
}

func (oag *OpenAPIGenerator) GenerateOpenAPISpec() (*OpenAPISpec, error) {
    openAPISpec := &OpenAPISpec{
        OpenAPI: "3.0.0",
        Info: Info{
            Title:   "Blackhole API",
            Version: oag.spec.Version,
        },
        Paths: make(map[string]PathItem),
        Components: Components{
            Schemas: make(map[string]Schema),
        },
    }
    
    // Generate schemas from types
    for _, typeDef := range oag.spec.Types {
        schema := oag.generateSchema(typeDef)
        openAPISpec.Components.Schemas[typeDef.Name] = schema
    }
    
    // Generate paths from services
    for _, service := range oag.spec.Services {
        for _, method := range service.Methods {
            pathItem := oag.generatePathItem(method)
            openAPISpec.Paths[method.Path] = pathItem
        }
    }
    
    return openAPISpec, nil
}

func (oag *OpenAPIGenerator) generateSchema(typeDef TypeDefinition) Schema {
    schema := Schema{
        Type:       "object",
        Properties: make(map[string]Property),
        Required:   []string{},
    }
    
    for _, field := range typeDef.Fields {
        property := Property{
            Type:        oag.mapGoTypeToOpenAPI(field.Type),
            Description: field.Description,
        }
        
        schema.Properties[field.Name] = property
        
        if field.Required {
            schema.Required = append(schema.Required, field.Name)
        }
    }
    
    return schema
}

type OpenAPISpec struct {
    OpenAPI    string                `json:"openapi"`
    Info       Info                  `json:"info"`
    Paths      map[string]PathItem   `json:"paths"`
    Components Components            `json:"components"`
}

type Info struct {
    Title       string `json:"title"`
    Description string `json:"description,omitempty"`
    Version     string `json:"version"`
}

type PathItem struct {
    Get    *Operation `json:"get,omitempty"`
    Post   *Operation `json:"post,omitempty"`
    Put    *Operation `json:"put,omitempty"`
    Delete *Operation `json:"delete,omitempty"`
}

type Operation struct {
    Summary     string              `json:"summary"`
    Description string              `json:"description,omitempty"`
    Parameters  []Parameter         `json:"parameters,omitempty"`
    RequestBody *RequestBody        `json:"requestBody,omitempty"`
    Responses   map[string]Response `json:"responses"`
}

type Components struct {
    Schemas map[string]Schema `json:"schemas"`
}

type Schema struct {
    Type        string              `json:"type"`
    Properties  map[string]Property `json:"properties,omitempty"`
    Required    []string            `json:"required,omitempty"`
    Description string              `json:"description,omitempty"`
}

type Property struct {
    Type        string `json:"type"`
    Description string `json:"description,omitempty"`
    Format      string `json:"format,omitempty"`
}
```

#### 4. Documentation Generator
```go
package documentation

import (
    "bytes"
    "fmt"
    "html/template"
    "path/filepath"
    "strings"
)

type DocumentationGenerator struct {
    spec      *APISpec
    templates map[string]*template.Template
    config    *DocumentationConfig
}

type DocumentationConfig struct {
    Title       string
    Version     string
    Description string
    Theme       string
    OutputDir   string
    Formats     []string // markdown, html, pdf
}

func NewDocumentationGenerator(spec *APISpec, config *DocumentationConfig) *DocumentationGenerator {
    return &DocumentationGenerator{
        spec:      spec,
        templates: loadDocumentationTemplates(),
        config:    config,
    }
}

func (dg *DocumentationGenerator) GenerateDocumentation() error {
    for _, format := range dg.config.Formats {
        switch format {
        case "markdown":
            if err := dg.generateMarkdown(); err != nil {
                return err
            }
        case "html":
            if err := dg.generateHTML(); err != nil {
                return err
            }
        case "pdf":
            if err := dg.generatePDF(); err != nil {
                return err
            }
        }
    }
    
    return nil
}

func (dg *DocumentationGenerator) generateMarkdown() error {
    var content strings.Builder
    
    // Generate README
    content.WriteString(dg.generateReadme())
    content.WriteString("\n\n")
    
    // Generate API reference
    content.WriteString(dg.generateAPIReference())
    content.WriteString("\n\n")
    
    // Generate examples
    content.WriteString(dg.generateExamples())
    
    // Write to file
    filename := filepath.Join(dg.config.OutputDir, "README.md")
    return writeFile(filename, content.String())
}

func (dg *DocumentationGenerator) generateReadme() string {
    tmpl := `# {{.Title}}

{{.Description}}

## Installation

### Go
` + "```bash" + `
go get github.com/blackhole/sdk-go
` + "```" + `

### Python
` + "```bash" + `
pip install blackhole-sdk
` + "```" + `

### JavaScript
` + "```bash" + `
npm install blackhole-sdk
` + "```" + `

## Quick Start

### Go
` + "```go" + `
package main

import (
    "context"
    "fmt"
    "github.com/blackhole/sdk-go"
)

func main() {
    client := blackhole.NewClient("your-api-key")
    
    // Example usage
    result, err := client.Storage.UploadFile(context.Background(), "test.txt", []byte("Hello, World!"))
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("File uploaded: %s\n", result.URL)
}
` + "```" + `

### Python
` + "```python" + `
from blackhole import BlackholeClient

client = BlackholeClient("your-api-key")

# Example usage
result = client.storage.upload_file("test.txt", b"Hello, World!")
print(f"File uploaded: {result.url}")
` + "```" + `

### JavaScript
` + "```javascript" + `
const BlackholeClient = require('blackhole-sdk');

const client = new BlackholeClient('your-api-key');

// Example usage
async function main() {
    const result = await client.storage.uploadFile('test.txt', Buffer.from('Hello, World!'));
    console.log('File uploaded:', result.url);
}

main().catch(console.error);
` + "```" + `

## Authentication

All API requests require authentication using an API key. You can obtain an API key by registering at [https://blackhole.network](https://blackhole.network).

` + "```bash" + `
curl -H "Authorization: Bearer YOUR_API_KEY" \
     https://api.blackhole.network/v1/ping
` + "```" + `

## Rate Limiting

The API implements rate limiting to ensure fair usage:

- **Free tier**: 1,000 requests per hour
- **Pro tier**: 10,000 requests per hour
- **Enterprise**: Custom limits

Rate limit headers are included in all responses:

- ` + "`X-RateLimit-Limit`" + `: Maximum requests per hour
- ` + "`X-RateLimit-Remaining`" + `: Remaining requests in current window
- ` + "`X-RateLimit-Reset`" + `: Unix timestamp when the rate limit resets

## Error Handling

The API uses standard HTTP status codes and returns errors in a consistent format:

` + "```json" + `
{
    "error": {
        "code": "INVALID_REQUEST",
        "message": "The request is invalid",
        "details": {
            "field": "name",
            "issue": "required"
        }
    }
}
` + "```" + `

Common error codes:

- ` + "`400 Bad Request`" + `: Invalid request parameters
- ` + "`401 Unauthorized`" + `: Invalid or missing API key
- ` + "`403 Forbidden`" + `: Insufficient permissions
- ` + "`404 Not Found`" + `: Resource not found
- ` + "`429 Too Many Requests`" + `: Rate limit exceeded
- ` + "`500 Internal Server Error`" + `: Server error
`
    
    var buf bytes.Buffer
    template.Must(template.New("readme").Parse(tmpl)).Execute(&buf, dg.config)
    return buf.String()
}

func (dg *DocumentationGenerator) generateAPIReference() string {
    var content strings.Builder
    
    content.WriteString("# API Reference\n\n")
    
    for _, service := range dg.spec.Services {
        content.WriteString(fmt.Sprintf("## %s\n\n", service.Name))
        content.WriteString(fmt.Sprintf("%s\n\n", service.Description))
        
        for _, method := range service.Methods {
            content.WriteString(dg.generateMethodDocumentation(method))
            content.WriteString("\n\n")
        }
    }
    
    content.WriteString("## Data Types\n\n")
    
    for _, typeDef := range dg.spec.Types {
        content.WriteString(dg.generateTypeDocumentation(typeDef))
        content.WriteString("\n\n")
    }
    
    return content.String()
}

func (dg *DocumentationGenerator) generateMethodDocumentation(method Method) string {
    var content strings.Builder
    
    content.WriteString(fmt.Sprintf("### %s\n\n", method.Name))
    content.WriteString(fmt.Sprintf("%s\n\n", method.Description))
    
    // HTTP method and path
    content.WriteString(fmt.Sprintf("**HTTP Method:** `%s`\n\n", method.HTTPMethod))
    content.WriteString(fmt.Sprintf("**Path:** `%s`\n\n", method.Path))
    
    // Parameters
    if len(method.Parameters) > 0 {
        content.WriteString("**Parameters:**\n\n")
        content.WriteString("| Name | Type | Required | Description |\n")
        content.WriteString("|------|------|----------|-------------|\n")
        
        for _, param := range method.Parameters {
            required := "No"
            if param.Required {
                required = "Yes"
            }
            content.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
                param.Name, param.Type, required, param.Description))
        }
        content.WriteString("\n")
    }
    
    // Request example
    content.WriteString("**Example Request:**\n\n")
    content.WriteString("```bash\n")
    content.WriteString(dg.generateCurlExample(method))
    content.WriteString("\n```\n\n")
    
    // Response example
    if method.Response != nil {
        content.WriteString("**Example Response:**\n\n")
        content.WriteString("```json\n")
        content.WriteString(dg.generateResponseExample(method.Response))
        content.WriteString("\n```\n")
    }
    
    return content.String()
}

func (dg *DocumentationGenerator) generateTypeDocumentation(typeDef TypeDefinition) string {
    var content strings.Builder
    
    content.WriteString(fmt.Sprintf("### %s\n\n", typeDef.Name))
    content.WriteString(fmt.Sprintf("%s\n\n", typeDef.Description))
    
    if len(typeDef.Fields) > 0 {
        content.WriteString("**Fields:**\n\n")
        content.WriteString("| Name | Type | Required | Description |\n")
        content.WriteString("|------|------|----------|-------------|\n")
        
        for _, field := range typeDef.Fields {
            required := "No"
            if field.Required {
                required = "Yes"
            }
            content.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
                field.Name, field.Type, required, field.Description))
        }
        content.WriteString("\n")
    }
    
    // JSON example
    content.WriteString("**JSON Example:**\n\n")
    content.WriteString("```json\n")
    content.WriteString(dg.generateTypeExample(typeDef))
    content.WriteString("\n```\n")
    
    return content.String()
}

func (dg *DocumentationGenerator) generateExamples() string {
    return `# Examples

## Storage Service

### Upload a File

` + "```go" + `
// Go
file, err := os.Open("document.pdf")
if err != nil {
    panic(err)
}
defer file.Close()

data, err := io.ReadAll(file)
if err != nil {
    panic(err)
}

result, err := client.Storage.UploadFile(ctx, "documents/document.pdf", data, map[string]string{
    "content-type": "application/pdf",
    "visibility":   "private",
})
` + "```" + `

` + "```python" + `
# Python
with open('document.pdf', 'rb') as f:
    data = f.read()

result = client.storage.upload_file(
    'documents/document.pdf',
    data,
    metadata={
        'content-type': 'application/pdf',
        'visibility': 'private'
    }
)
` + "```" + `

### Download a File

` + "```go" + `
// Go
data, err := client.Storage.DownloadFile(ctx, "documents/document.pdf")
if err != nil {
    panic(err)
}

err = os.WriteFile("downloaded.pdf", data, 0644)
` + "```" + `

` + "```python" + `
# Python
data = client.storage.download_file('documents/document.pdf')

with open('downloaded.pdf', 'wb') as f:
    f.write(data)
` + "```" + `

## Compute Service

### Submit a Job

` + "```go" + `
// Go
job, err := client.Compute.SubmitJob(ctx, &blackhole.JobRequest{
    Image:   "python:3.9",
    Command: []string{"python"},
    Args:    []string{"-c", "print('Hello from Blackhole!')"},
    Resources: blackhole.ResourceLimits{
        CPU:    "100m",
        Memory: "128Mi",
    },
    Timeout: 300,
})
` + "```" + `

` + "```python" + `
# Python
job = client.compute.submit_job({
    'image': 'python:3.9',
    'command': ['python'],
    'args': ['-c', "print('Hello from Blackhole!')"],
    'resources': {
        'cpu': '100m',
        'memory': '128Mi'
    },
    'timeout': 300
})
` + "```" + `

### Get Job Status

` + "```go" + `
// Go
job, err := client.Compute.GetJob(ctx, jobID)
if err != nil {
    panic(err)
}

fmt.Printf("Job Status: %s\n", job.Status)
if job.Status == "completed" {
    fmt.Printf("Output: %s\n", job.Output)
}
` + "```" + `

` + "```python" + `
# Python
job = client.compute.get_job(job_id)
print(f"Job Status: {job.status}")

if job.status == "completed":
    print(f"Output: {job.output}")
` + "```" + ``
}

func (dg *DocumentationGenerator) generateHTML() error {
    // Generate HTML documentation using templates
    return nil
}

func (dg *DocumentationGenerator) generatePDF() error {
    // Generate PDF documentation
    return nil
}
```

### Integration Points

#### 1. Code Generation Pipeline
```go
type CodeGenerationPipeline struct {
    parser     *APIParser
    generator  *BindingGenerator
    validator  *CodeValidator
    deployer   *SDKDeployer
}

func (cgp *CodeGenerationPipeline) GenerateSDKs(sourceDir string) error {
    // Parse API definitions
    spec, err := cgp.parser.ParseGoPackage(sourceDir)
    if err != nil {
        return err
    }
    
    // Generate bindings
    if err := cgp.generator.GenerateBindings(spec); err != nil {
        return err
    }
    
    // Validate generated code
    if err := cgp.validator.ValidateGeneratedCode(); err != nil {
        return err
    }
    
    // Deploy SDKs
    return cgp.deployer.Deploy()
}
```

#### 2. Testing Framework
```go
type SDKTestSuite struct {
    client  *SDKClient
    testCases []TestCase
}

type TestCase struct {
    Name     string
    Setup    func() error
    Test     func(*SDKClient) error
    Cleanup  func() error
}

func (sts *SDKTestSuite) RunTests() error {
    for _, testCase := range sts.testCases {
        if err := sts.runTestCase(testCase); err != nil {
            return fmt.Errorf("test %s failed: %w", testCase.Name, err)
        }
    }
    return nil
}
```

### Configuration
```yaml
sdk:
  generation:
    languages:
      - go
      - python
      - javascript
      - java
      - csharp
    
    output_dir: ./generated
    package_name: blackhole-sdk
    
  documentation:
    formats:
      - markdown
      - html
      - openapi
    
    theme: default
    include_examples: true
    
  deployment:
    npm_registry: https://registry.npmjs.org
    pypi_registry: https://pypi.org
    maven_registry: https://repo1.maven.org
```

### Security Considerations

1. **API Key Management**
   - Secure storage
   - Key rotation
   - Environment variables

2. **Request Signing**
   - HMAC signatures
   - Timestamp validation
   - Replay protection

3. **Input Validation**
   - Parameter validation
   - Type checking
   - Sanitization

### Performance Optimization

1. **Connection Pooling**
   - HTTP connection reuse
   - Keep-alive headers
   - Connection limits

2. **Caching**
   - Response caching
   - Schema caching
   - Authentication tokens

3. **Compression**
   - Request compression
   - Response compression
   - Efficient serialization