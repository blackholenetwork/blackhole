# U22: Access Control

## Overview
Role-Based Access Control (RBAC) implementation for BlackHole with permission management, resource-based access control, and a flexible policy engine for fine-grained authorization.

## Implementation

### Core Access Control Types

```go
package rbac

import (
    "fmt"
    "sync"
    "time"
)

// Role represents a collection of permissions
type Role struct {
    ID          string      `json:"id"`
    Name        string      `json:"name"`
    Description string      `json:"description"`
    Permissions []string    `json:"permissions"`
    Metadata    map[string]interface{} `json:"metadata,omitempty"`
    CreatedAt   time.Time   `json:"createdAt"`
    UpdatedAt   time.Time   `json:"updatedAt"`
}

// Permission represents an action that can be performed
type Permission struct {
    ID          string    `json:"id"`
    Resource    string    `json:"resource"`
    Action      string    `json:"action"`
    Description string    `json:"description"`
    Constraints []Constraint `json:"constraints,omitempty"`
    CreatedAt   time.Time `json:"createdAt"`
}

// Resource represents a protected resource
type Resource struct {
    ID         string                 `json:"id"`
    Type       string                 `json:"type"`
    Owner      string                 `json:"owner"`
    Attributes map[string]interface{} `json:"attributes"`
    Tags       []string               `json:"tags"`
    CreatedAt  time.Time              `json:"createdAt"`
    UpdatedAt  time.Time              `json:"updatedAt"`
}

// Policy represents an access control policy
type Policy struct {
    ID         string          `json:"id"`
    Name       string          `json:"name"`
    Effect     Effect          `json:"effect"`
    Subjects   []string        `json:"subjects"`
    Resources  []string        `json:"resources"`
    Actions    []string        `json:"actions"`
    Conditions []Condition     `json:"conditions"`
    Priority   int             `json:"priority"`
    CreatedAt  time.Time       `json:"createdAt"`
    UpdatedAt  time.Time       `json:"updatedAt"`
}

// Subject represents an entity that can be granted permissions
type Subject struct {
    ID         string                 `json:"id"`
    Type       SubjectType            `json:"type"`
    Roles      []string               `json:"roles"`
    Attributes map[string]interface{} `json:"attributes"`
}

// Constraint limits how a permission can be used
type Constraint struct {
    Type       string                 `json:"type"`
    Parameters map[string]interface{} `json:"parameters"`
}

// Condition for policy evaluation
type Condition struct {
    Type       string                 `json:"type"`
    Parameters map[string]interface{} `json:"parameters"`
}

// Effect of a policy
type Effect string

const (
    EffectAllow Effect = "allow"
    EffectDeny  Effect = "deny"
)

// SubjectType enumeration
type SubjectType string

const (
    SubjectTypeUser  SubjectType = "user"
    SubjectTypeGroup SubjectType = "group"
    SubjectTypeRole  SubjectType = "role"
)

// AccessRequest represents a request to access a resource
type AccessRequest struct {
    Subject    *Subject               `json:"subject"`
    Resource   string                 `json:"resource"`
    Action     string                 `json:"action"`
    Context    map[string]interface{} `json:"context"`
    RequestID  string                 `json:"requestId"`
    Timestamp  time.Time              `json:"timestamp"`
}

// AccessDecision represents the result of an access request
type AccessDecision struct {
    Allowed       bool     `json:"allowed"`
    Reason        string   `json:"reason"`
    AppliedPolicy *Policy  `json:"appliedPolicy,omitempty"`
    EvaluatedAt   time.Time `json:"evaluatedAt"`
}
```

### RBAC Manager

```go
package rbac

import (
    "fmt"
    "strings"
    "sync"
)

// Manager handles RBAC operations
type Manager struct {
    mu          sync.RWMutex
    roles       map[string]*Role
    permissions map[string]*Permission
    assignments map[string][]string // subject ID -> role IDs
    storage     Storage
}

// Storage interface for persistence
type Storage interface {
    // Roles
    StoreRole(role *Role) error
    GetRole(id string) (*Role, error)
    ListRoles() ([]*Role, error)
    DeleteRole(id string) error
    
    // Permissions
    StorePermission(perm *Permission) error
    GetPermission(id string) (*Permission, error)
    ListPermissions() ([]*Permission, error)
    DeletePermission(id string) error
    
    // Assignments
    StoreAssignment(subjectID string, roleIDs []string) error
    GetAssignment(subjectID string) ([]string, error)
    DeleteAssignment(subjectID string) error
}

// NewManager creates a new RBAC manager
func NewManager(storage Storage) *Manager {
    return &Manager{
        roles:       make(map[string]*Role),
        permissions: make(map[string]*Permission),
        assignments: make(map[string][]string),
        storage:     storage,
    }
}

// CreateRole creates a new role
func (m *Manager) CreateRole(name, description string, permissions []string) (*Role, error) {
    m.mu.Lock()
    defer m.mu.Unlock()

    // Validate permissions exist
    for _, permID := range permissions {
        if _, exists := m.permissions[permID]; !exists {
            return nil, fmt.Errorf("permission not found: %s", permID)
        }
    }

    role := &Role{
        ID:          generateID("role"),
        Name:        name,
        Description: description,
        Permissions: permissions,
        CreatedAt:   time.Now(),
        UpdatedAt:   time.Now(),
    }

    if err := m.storage.StoreRole(role); err != nil {
        return nil, fmt.Errorf("failed to store role: %w", err)
    }

    m.roles[role.ID] = role
    return role, nil
}

// CreatePermission creates a new permission
func (m *Manager) CreatePermission(resource, action, description string) (*Permission, error) {
    m.mu.Lock()
    defer m.mu.Unlock()

    perm := &Permission{
        ID:          fmt.Sprintf("%s:%s", resource, action),
        Resource:    resource,
        Action:      action,
        Description: description,
        CreatedAt:   time.Now(),
    }

    if err := m.storage.StorePermission(perm); err != nil {
        return nil, fmt.Errorf("failed to store permission: %w", err)
    }

    m.permissions[perm.ID] = perm
    return perm, nil
}

// AssignRole assigns roles to a subject
func (m *Manager) AssignRole(subjectID string, roleIDs ...string) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    // Validate roles exist
    for _, roleID := range roleIDs {
        if _, exists := m.roles[roleID]; !exists {
            return fmt.Errorf("role not found: %s", roleID)
        }
    }

    // Get existing assignments
    existing := m.assignments[subjectID]
    
    // Add new roles (avoid duplicates)
    roleMap := make(map[string]bool)
    for _, roleID := range existing {
        roleMap[roleID] = true
    }
    
    for _, roleID := range roleIDs {
        roleMap[roleID] = true
    }

    // Convert back to slice
    var allRoles []string
    for roleID := range roleMap {
        allRoles = append(allRoles, roleID)
    }

    if err := m.storage.StoreAssignment(subjectID, allRoles); err != nil {
        return fmt.Errorf("failed to store assignment: %w", err)
    }

    m.assignments[subjectID] = allRoles
    return nil
}

// RevokeRole revokes roles from a subject
func (m *Manager) RevokeRole(subjectID string, roleIDs ...string) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    existing := m.assignments[subjectID]
    if len(existing) == 0 {
        return fmt.Errorf("no roles assigned to subject")
    }

    // Remove specified roles
    roleMap := make(map[string]bool)
    for _, roleID := range existing {
        roleMap[roleID] = true
    }
    
    for _, roleID := range roleIDs {
        delete(roleMap, roleID)
    }

    // Convert back to slice
    var remainingRoles []string
    for roleID := range roleMap {
        remainingRoles = append(remainingRoles, roleID)
    }

    if len(remainingRoles) == 0 {
        return m.storage.DeleteAssignment(subjectID)
    }

    if err := m.storage.StoreAssignment(subjectID, remainingRoles); err != nil {
        return fmt.Errorf("failed to update assignment: %w", err)
    }

    m.assignments[subjectID] = remainingRoles
    return nil
}

// GetSubjectPermissions returns all permissions for a subject
func (m *Manager) GetSubjectPermissions(subjectID string) ([]*Permission, error) {
    m.mu.RLock()
    defer m.mu.RUnlock()

    roleIDs := m.assignments[subjectID]
    if len(roleIDs) == 0 {
        return nil, nil
    }

    permMap := make(map[string]*Permission)
    
    for _, roleID := range roleIDs {
        role, exists := m.roles[roleID]
        if !exists {
            continue
        }
        
        for _, permID := range role.Permissions {
            if perm, exists := m.permissions[permID]; exists {
                permMap[permID] = perm
            }
        }
    }

    var permissions []*Permission
    for _, perm := range permMap {
        permissions = append(permissions, perm)
    }

    return permissions, nil
}

// HasPermission checks if a subject has a specific permission
func (m *Manager) HasPermission(subjectID, resource, action string) (bool, error) {
    permissions, err := m.GetSubjectPermissions(subjectID)
    if err != nil {
        return false, err
    }

    permID := fmt.Sprintf("%s:%s", resource, action)
    for _, perm := range permissions {
        if perm.ID == permID {
            return true, nil
        }
        
        // Check for wildcard permissions
        if perm.Resource == "*" || perm.Action == "*" {
            return true, nil
        }
        
        // Check for prefix matching
        if strings.HasSuffix(perm.Resource, "*") {
            prefix := strings.TrimSuffix(perm.Resource, "*")
            if strings.HasPrefix(resource, prefix) && perm.Action == action {
                return true, nil
            }
        }
    }

    return false, nil
}
```

### Policy Engine

```go
package rbac

import (
    "fmt"
    "regexp"
    "sort"
    "strings"
)

// PolicyEngine evaluates access control policies
type PolicyEngine struct {
    mu         sync.RWMutex
    policies   map[string]*Policy
    evaluators map[string]ConditionEvaluator
    storage    PolicyStorage
}

// PolicyStorage interface for policy persistence
type PolicyStorage interface {
    StorePolicy(policy *Policy) error
    GetPolicy(id string) (*Policy, error)
    ListPolicies() ([]*Policy, error)
    DeletePolicy(id string) error
}

// ConditionEvaluator evaluates policy conditions
type ConditionEvaluator interface {
    Evaluate(condition *Condition, request *AccessRequest) (bool, error)
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(storage PolicyStorage) *PolicyEngine {
    engine := &PolicyEngine{
        policies:   make(map[string]*Policy),
        evaluators: make(map[string]ConditionEvaluator),
        storage:    storage,
    }

    // Register default evaluators
    engine.RegisterEvaluator("time", &TimeConditionEvaluator{})
    engine.RegisterEvaluator("ip", &IPConditionEvaluator{})
    engine.RegisterEvaluator("attribute", &AttributeConditionEvaluator{})

    return engine
}

// RegisterEvaluator registers a condition evaluator
func (pe *PolicyEngine) RegisterEvaluator(condType string, evaluator ConditionEvaluator) {
    pe.mu.Lock()
    defer pe.mu.Unlock()
    pe.evaluators[condType] = evaluator
}

// CreatePolicy creates a new policy
func (pe *PolicyEngine) CreatePolicy(policy *Policy) error {
    pe.mu.Lock()
    defer pe.mu.Unlock()

    policy.ID = generateID("policy")
    policy.CreatedAt = time.Now()
    policy.UpdatedAt = time.Now()

    if err := pe.storage.StorePolicy(policy); err != nil {
        return fmt.Errorf("failed to store policy: %w", err)
    }

    pe.policies[policy.ID] = policy
    return nil
}

// Evaluate evaluates an access request against all policies
func (pe *PolicyEngine) Evaluate(request *AccessRequest) (*AccessDecision, error) {
    pe.mu.RLock()
    defer pe.mu.RUnlock()

    // Get applicable policies
    applicable := pe.getApplicablePolicies(request)
    
    // Sort by priority (higher priority first)
    sort.Slice(applicable, func(i, j int) bool {
        return applicable[i].Priority > applicable[j].Priority
    })

    // Evaluate policies
    for _, policy := range applicable {
        match, err := pe.evaluatePolicy(policy, request)
        if err != nil {
            continue // Skip policies that error
        }

        if match {
            allowed := policy.Effect == EffectAllow
            reason := fmt.Sprintf("Policy %s (%s)", policy.Name, policy.Effect)
            
            return &AccessDecision{
                Allowed:       allowed,
                Reason:        reason,
                AppliedPolicy: policy,
                EvaluatedAt:   time.Now(),
            }, nil
        }
    }

    // Default deny
    return &AccessDecision{
        Allowed:     false,
        Reason:      "No matching policy found",
        EvaluatedAt: time.Now(),
    }, nil
}

// getApplicablePolicies returns policies that could apply to the request
func (pe *PolicyEngine) getApplicablePolicies(request *AccessRequest) []*Policy {
    var applicable []*Policy

    for _, policy := range pe.policies {
        // Check if subject matches
        if !pe.matchesSubject(policy, request.Subject) {
            continue
        }

        // Check if resource matches
        if !pe.matchesResource(policy, request.Resource) {
            continue
        }

        // Check if action matches
        if !pe.matchesAction(policy, request.Action) {
            continue
        }

        applicable = append(applicable, policy)
    }

    return applicable
}

// evaluatePolicy evaluates all conditions of a policy
func (pe *PolicyEngine) evaluatePolicy(policy *Policy, request *AccessRequest) (bool, error) {
    for _, condition := range policy.Conditions {
        evaluator, exists := pe.evaluators[condition.Type]
        if !exists {
            return false, fmt.Errorf("unknown condition type: %s", condition.Type)
        }

        match, err := evaluator.Evaluate(&condition, request)
        if err != nil {
            return false, err
        }

        if !match {
            return false, nil
        }
    }

    return true, nil
}

// matchesSubject checks if policy applies to subject
func (pe *PolicyEngine) matchesSubject(policy *Policy, subject *Subject) bool {
    for _, policySubject := range policy.Subjects {
        if policySubject == "*" {
            return true
        }

        if policySubject == subject.ID {
            return true
        }

        // Check roles
        for _, role := range subject.Roles {
            if policySubject == fmt.Sprintf("role:%s", role) {
                return true
            }
        }

        // Check type
        if policySubject == fmt.Sprintf("type:%s", subject.Type) {
            return true
        }
    }

    return false
}

// matchesResource checks if policy applies to resource
func (pe *PolicyEngine) matchesResource(policy *Policy, resource string) bool {
    for _, policyResource := range policy.Resources {
        if policyResource == "*" {
            return true
        }

        if policyResource == resource {
            return true
        }

        // Check glob patterns
        if matched, _ := filepath.Match(policyResource, resource); matched {
            return true
        }

        // Check regex patterns
        if strings.HasPrefix(policyResource, "regex:") {
            pattern := strings.TrimPrefix(policyResource, "regex:")
            if matched, _ := regexp.MatchString(pattern, resource); matched {
                return true
            }
        }
    }

    return false
}

// matchesAction checks if policy applies to action
func (pe *PolicyEngine) matchesAction(policy *Policy, action string) bool {
    for _, policyAction := range policy.Actions {
        if policyAction == "*" {
            return true
        }

        if policyAction == action {
            return true
        }

        // Check prefix matching
        if strings.HasSuffix(policyAction, "*") {
            prefix := strings.TrimSuffix(policyAction, "*")
            if strings.HasPrefix(action, prefix) {
                return true
            }
        }
    }

    return false
}
```

### Condition Evaluators

```go
package rbac

import (
    "fmt"
    "net"
    "time"
)

// TimeConditionEvaluator evaluates time-based conditions
type TimeConditionEvaluator struct{}

func (e *TimeConditionEvaluator) Evaluate(condition *Condition, request *AccessRequest) (bool, error) {
    // Get time range parameters
    startStr, _ := condition.Parameters["start"].(string)
    endStr, _ := condition.Parameters["end"].(string)
    
    if startStr == "" || endStr == "" {
        return false, fmt.Errorf("missing time range parameters")
    }

    start, err := time.Parse(time.RFC3339, startStr)
    if err != nil {
        return false, fmt.Errorf("invalid start time: %w", err)
    }

    end, err := time.Parse(time.RFC3339, endStr)
    if err != nil {
        return false, fmt.Errorf("invalid end time: %w", err)
    }

    now := request.Timestamp
    return now.After(start) && now.Before(end), nil
}

// IPConditionEvaluator evaluates IP-based conditions
type IPConditionEvaluator struct{}

func (e *IPConditionEvaluator) Evaluate(condition *Condition, request *AccessRequest) (bool, error) {
    // Get allowed IP ranges
    ranges, ok := condition.Parameters["ranges"].([]interface{})
    if !ok {
        return false, fmt.Errorf("missing IP ranges")
    }

    // Get request IP from context
    requestIP, ok := request.Context["ip"].(string)
    if !ok {
        return false, fmt.Errorf("no IP in request context")
    }

    ip := net.ParseIP(requestIP)
    if ip == nil {
        return false, fmt.Errorf("invalid IP address")
    }

    // Check each range
    for _, r := range ranges {
        rangeStr, ok := r.(string)
        if !ok {
            continue
        }

        _, ipNet, err := net.ParseCIDR(rangeStr)
        if err != nil {
            // Try as single IP
            if rangeIP := net.ParseIP(rangeStr); rangeIP != nil {
                if ip.Equal(rangeIP) {
                    return true, nil
                }
            }
            continue
        }

        if ipNet.Contains(ip) {
            return true, nil
        }
    }

    return false, nil
}

// AttributeConditionEvaluator evaluates attribute-based conditions
type AttributeConditionEvaluator struct{}

func (e *AttributeConditionEvaluator) Evaluate(condition *Condition, request *AccessRequest) (bool, error) {
    // Get attribute name and expected value
    attrName, _ := condition.Parameters["name"].(string)
    expectedValue := condition.Parameters["value"]
    operator, _ := condition.Parameters["operator"].(string)

    if attrName == "" {
        return false, fmt.Errorf("missing attribute name")
    }

    // Get actual value from subject attributes
    actualValue, exists := request.Subject.Attributes[attrName]
    if !exists {
        return false, nil
    }

    // Compare based on operator
    switch operator {
    case "equals", "":
        return fmt.Sprintf("%v", actualValue) == fmt.Sprintf("%v", expectedValue), nil
    
    case "not_equals":
        return fmt.Sprintf("%v", actualValue) != fmt.Sprintf("%v", expectedValue), nil
    
    case "contains":
        str := fmt.Sprintf("%v", actualValue)
        substr := fmt.Sprintf("%v", expectedValue)
        return strings.Contains(str, substr), nil
    
    case "greater_than":
        return compareNumeric(actualValue, expectedValue, ">")
    
    case "less_than":
        return compareNumeric(actualValue, expectedValue, "<")
    
    case "in":
        return checkInList(actualValue, expectedValue)
    
    default:
        return false, fmt.Errorf("unknown operator: %s", operator)
    }
}

// compareNumeric compares numeric values
func compareNumeric(a, b interface{}, op string) (bool, error) {
    aFloat, aOk := toFloat64(a)
    bFloat, bOk := toFloat64(b)
    
    if !aOk || !bOk {
        return false, fmt.Errorf("non-numeric comparison")
    }

    switch op {
    case ">":
        return aFloat > bFloat, nil
    case "<":
        return aFloat < bFloat, nil
    case ">=":
        return aFloat >= bFloat, nil
    case "<=":
        return aFloat <= bFloat, nil
    default:
        return false, fmt.Errorf("invalid operator")
    }
}

// toFloat64 converts interface to float64
func toFloat64(v interface{}) (float64, bool) {
    switch val := v.(type) {
    case float64:
        return val, true
    case float32:
        return float64(val), true
    case int:
        return float64(val), true
    case int64:
        return float64(val), true
    default:
        return 0, false
    }
}

// checkInList checks if value is in list
func checkInList(value, list interface{}) (bool, error) {
    listSlice, ok := list.([]interface{})
    if !ok {
        return false, fmt.Errorf("expected list for 'in' operator")
    }

    valueStr := fmt.Sprintf("%v", value)
    for _, item := range listSlice {
        if fmt.Sprintf("%v", item) == valueStr {
            return true, nil
        }
    }

    return false, nil
}
```

### Resource Manager

```go
package rbac

import (
    "fmt"
    "sync"
)

// ResourceManager manages protected resources
type ResourceManager struct {
    mu        sync.RWMutex
    resources map[string]*Resource
    storage   ResourceStorage
}

// ResourceStorage interface for resource persistence
type ResourceStorage interface {
    StoreResource(resource *Resource) error
    GetResource(id string) (*Resource, error)
    ListResources(filters map[string]interface{}) ([]*Resource, error)
    DeleteResource(id string) error
}

// NewResourceManager creates a new resource manager
func NewResourceManager(storage ResourceStorage) *ResourceManager {
    return &ResourceManager{
        resources: make(map[string]*Resource),
        storage:   storage,
    }
}

// CreateResource creates a new protected resource
func (rm *ResourceManager) CreateResource(resType, owner string, attributes map[string]interface{}) (*Resource, error) {
    rm.mu.Lock()
    defer rm.mu.Unlock()

    resource := &Resource{
        ID:         generateID("res"),
        Type:       resType,
        Owner:      owner,
        Attributes: attributes,
        Tags:       []string{},
        CreatedAt:  time.Now(),
        UpdatedAt:  time.Now(),
    }

    if err := rm.storage.StoreResource(resource); err != nil {
        return nil, fmt.Errorf("failed to store resource: %w", err)
    }

    rm.resources[resource.ID] = resource
    return resource, nil
}

// GetResource retrieves a resource
func (rm *ResourceManager) GetResource(id string) (*Resource, error) {
    rm.mu.RLock()
    defer rm.mu.RUnlock()

    resource, exists := rm.resources[id]
    if !exists {
        // Try loading from storage
        var err error
        resource, err = rm.storage.GetResource(id)
        if err != nil {
            return nil, fmt.Errorf("resource not found: %s", id)
        }
        rm.resources[id] = resource
    }

    return resource, nil
}

// UpdateResource updates a resource
func (rm *ResourceManager) UpdateResource(id string, updates map[string]interface{}) error {
    rm.mu.Lock()
    defer rm.mu.Unlock()

    resource, exists := rm.resources[id]
    if !exists {
        return fmt.Errorf("resource not found: %s", id)
    }

    // Apply updates
    if owner, ok := updates["owner"].(string); ok {
        resource.Owner = owner
    }

    if attrs, ok := updates["attributes"].(map[string]interface{}); ok {
        for k, v := range attrs {
            resource.Attributes[k] = v
        }
    }

    if tags, ok := updates["tags"].([]string); ok {
        resource.Tags = tags
    }

    resource.UpdatedAt = time.Now()

    if err := rm.storage.StoreResource(resource); err != nil {
        return fmt.Errorf("failed to update resource: %w", err)
    }

    return nil
}

// AddTag adds a tag to a resource
func (rm *ResourceManager) AddTag(resourceID, tag string) error {
    rm.mu.Lock()
    defer rm.mu.Unlock()

    resource, exists := rm.resources[resourceID]
    if !exists {
        return fmt.Errorf("resource not found: %s", resourceID)
    }

    // Check if tag already exists
    for _, t := range resource.Tags {
        if t == tag {
            return nil // Already has tag
        }
    }

    resource.Tags = append(resource.Tags, tag)
    resource.UpdatedAt = time.Now()

    return rm.storage.StoreResource(resource)
}

// FindResourcesByTag finds resources with a specific tag
func (rm *ResourceManager) FindResourcesByTag(tag string) ([]*Resource, error) {
    filters := map[string]interface{}{
        "tag": tag,
    }
    return rm.storage.ListResources(filters)
}

// CheckOwnership checks if a subject owns a resource
func (rm *ResourceManager) CheckOwnership(resourceID, subjectID string) (bool, error) {
    resource, err := rm.GetResource(resourceID)
    if err != nil {
        return false, err
    }

    return resource.Owner == subjectID, nil
}
```

### Access Control Service

```go
package rbac

import (
    "fmt"
    "sync"
)

// Service provides unified access control
type Service struct {
    mu        sync.RWMutex
    rbac      *Manager
    policy    *PolicyEngine
    resources *ResourceManager
    cache     Cache
}

// Cache interface for decision caching
type Cache interface {
    Get(key string) (*AccessDecision, bool)
    Set(key string, decision *AccessDecision)
    Delete(key string)
}

// NewService creates a new access control service
func NewService(rbac *Manager, policy *PolicyEngine, resources *ResourceManager, cache Cache) *Service {
    return &Service{
        rbac:      rbac,
        policy:    policy,
        resources: resources,
        cache:     cache,
    }
}

// CheckAccess checks if a subject can perform an action on a resource
func (s *Service) CheckAccess(request *AccessRequest) (*AccessDecision, error) {
    // Generate cache key
    cacheKey := fmt.Sprintf("%s:%s:%s", request.Subject.ID, request.Resource, request.Action)
    
    // Check cache
    if decision, found := s.cache.Get(cacheKey); found {
        return decision, nil
    }

    // Check RBAC permissions first
    hasPermission, err := s.rbac.HasPermission(request.Subject.ID, request.Resource, request.Action)
    if err != nil {
        return nil, fmt.Errorf("failed to check permissions: %w", err)
    }

    if hasPermission {
        // Still need to check policies for deny rules
        decision, err := s.policy.Evaluate(request)
        if err != nil {
            return nil, fmt.Errorf("failed to evaluate policies: %w", err)
        }

        s.cache.Set(cacheKey, decision)
        return decision, nil
    }

    // No RBAC permission, check policies
    decision, err := s.policy.Evaluate(request)
    if err != nil {
        return nil, fmt.Errorf("failed to evaluate policies: %w", err)
    }

    s.cache.Set(cacheKey, decision)
    return decision, nil
}

// CheckResourceAccess checks access with resource attributes
func (s *Service) CheckResourceAccess(subjectID, resourceID, action string, context map[string]interface{}) (*AccessDecision, error) {
    // Get resource
    resource, err := s.resources.GetResource(resourceID)
    if err != nil {
        return nil, fmt.Errorf("failed to get resource: %w", err)
    }

    // Get subject
    subject := &Subject{
        ID:   subjectID,
        Type: SubjectTypeUser,
    }

    // Get subject roles
    assignments := s.rbac.assignments[subjectID]
    subject.Roles = assignments

    // Add resource attributes to context
    if context == nil {
        context = make(map[string]interface{})
    }
    context["resource"] = resource
    context["resourceType"] = resource.Type
    context["resourceOwner"] = resource.Owner

    request := &AccessRequest{
        Subject:   subject,
        Resource:  resourceID,
        Action:    action,
        Context:   context,
        RequestID: generateID("req"),
        Timestamp: time.Now(),
    }

    return s.CheckAccess(request)
}

// GrantPermission grants a permission to a role
func (s *Service) GrantPermission(roleID, resource, action string) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    // Create permission if it doesn't exist
    permID := fmt.Sprintf("%s:%s", resource, action)
    if _, exists := s.rbac.permissions[permID]; !exists {
        _, err := s.rbac.CreatePermission(resource, action, fmt.Sprintf("Allow %s on %s", action, resource))
        if err != nil {
            return err
        }
    }

    // Add permission to role
    role, exists := s.rbac.roles[roleID]
    if !exists {
        return fmt.Errorf("role not found: %s", roleID)
    }

    // Check if already has permission
    for _, perm := range role.Permissions {
        if perm == permID {
            return nil // Already has permission
        }
    }

    role.Permissions = append(role.Permissions, permID)
    role.UpdatedAt = time.Now()

    // Clear cache for affected subjects
    for subjectID, roles := range s.rbac.assignments {
        for _, r := range roles {
            if r == roleID {
                s.clearSubjectCache(subjectID)
                break
            }
        }
    }

    return s.rbac.storage.StoreRole(role)
}

// clearSubjectCache clears cache entries for a subject
func (s *Service) clearSubjectCache(subjectID string) {
    // In a real implementation, this would clear all cache entries
    // that start with the subject ID
    s.cache.Delete(subjectID)
}
```

### Middleware Implementation

```go
package rbac

import (
    "context"
    "net/http"
)

// Middleware provides HTTP middleware for access control
type Middleware struct {
    service *Service
}

// NewMiddleware creates new access control middleware
func NewMiddleware(service *Service) *Middleware {
    return &Middleware{
        service: service,
    }
}

// RequirePermission creates middleware that requires specific permission
func (m *Middleware) RequirePermission(resource, action string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Get subject from context (set by auth middleware)
            subject := getSubjectFromContext(r.Context())
            if subject == nil {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            // Create access request
            request := &AccessRequest{
                Subject:   subject,
                Resource:  resource,
                Action:    action,
                Context:   extractRequestContext(r),
                RequestID: r.Header.Get("X-Request-ID"),
                Timestamp: time.Now(),
            }

            // Check access
            decision, err := m.service.CheckAccess(request)
            if err != nil {
                http.Error(w, "Internal error", http.StatusInternalServerError)
                return
            }

            if !decision.Allowed {
                http.Error(w, decision.Reason, http.StatusForbidden)
                return
            }

            // Add decision to context
            ctx := context.WithValue(r.Context(), "accessDecision", decision)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

// RequireResourceAccess creates middleware for resource-based access
func (m *Middleware) RequireResourceAccess(action string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Get subject from context
            subject := getSubjectFromContext(r.Context())
            if subject == nil {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            // Get resource ID from URL
            resourceID := getResourceID(r)
            if resourceID == "" {
                http.Error(w, "Resource not found", http.StatusNotFound)
                return
            }

            // Check access
            decision, err := m.service.CheckResourceAccess(
                subject.ID,
                resourceID,
                action,
                extractRequestContext(r),
            )
            
            if err != nil {
                http.Error(w, "Internal error", http.StatusInternalServerError)
                return
            }

            if !decision.Allowed {
                http.Error(w, decision.Reason, http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}

// getSubjectFromContext extracts subject from request context
func getSubjectFromContext(ctx context.Context) *Subject {
    if subject, ok := ctx.Value("subject").(*Subject); ok {
        return subject
    }
    return nil
}

// getResourceID extracts resource ID from request
func getResourceID(r *http.Request) string {
    // This is a simple example - in practice, you'd use a router
    // that provides path parameters
    parts := strings.Split(r.URL.Path, "/")
    if len(parts) >= 3 && parts[1] == "resources" {
        return parts[2]
    }
    return ""
}

// extractRequestContext extracts context from HTTP request
func extractRequestContext(r *http.Request) map[string]interface{} {
    return map[string]interface{}{
        "ip":         r.RemoteAddr,
        "method":     r.Method,
        "path":       r.URL.Path,
        "user_agent": r.Header.Get("User-Agent"),
    }
}
```

### Storage Implementation

```go
package rbac

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "os"
    "path/filepath"
    "sync"
)

// FileStorage implements file-based storage
type FileStorage struct {
    mu      sync.RWMutex
    baseDir string
}

// NewFileStorage creates new file storage
func NewFileStorage(baseDir string) (*FileStorage, error) {
    dirs := []string{
        filepath.Join(baseDir, "roles"),
        filepath.Join(baseDir, "permissions"),
        filepath.Join(baseDir, "assignments"),
        filepath.Join(baseDir, "policies"),
        filepath.Join(baseDir, "resources"),
    }

    for _, dir := range dirs {
        if err := os.MkdirAll(dir, 0755); err != nil {
            return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
        }
    }

    return &FileStorage{baseDir: baseDir}, nil
}

// Role storage methods
func (s *FileStorage) StoreRole(role *Role) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    data, err := json.MarshalIndent(role, "", "  ")
    if err != nil {
        return err
    }

    filename := filepath.Join(s.baseDir, "roles", role.ID+".json")
    return ioutil.WriteFile(filename, data, 0644)
}

func (s *FileStorage) GetRole(id string) (*Role, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    filename := filepath.Join(s.baseDir, "roles", id+".json")
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err
    }

    var role Role
    if err := json.Unmarshal(data, &role); err != nil {
        return nil, err
    }

    return &role, nil
}

func (s *FileStorage) ListRoles() ([]*Role, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    files, err := ioutil.ReadDir(filepath.Join(s.baseDir, "roles"))
    if err != nil {
        return nil, err
    }

    var roles []*Role
    for _, file := range files {
        if filepath.Ext(file.Name()) == ".json" {
            id := strings.TrimSuffix(file.Name(), ".json")
            role, err := s.GetRole(id)
            if err == nil {
                roles = append(roles, role)
            }
        }
    }

    return roles, nil
}

func (s *FileStorage) DeleteRole(id string) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    filename := filepath.Join(s.baseDir, "roles", id+".json")
    return os.Remove(filename)
}

// Similar implementations for permissions, assignments, policies, and resources...
```

### Utility Functions

```go
package rbac

import (
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "time"
)

// generateID generates a unique ID with prefix
func generateID(prefix string) string {
    b := make([]byte, 8)
    rand.Read(b)
    return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b))
}

// MemoryCache implements a simple in-memory cache
type MemoryCache struct {
    mu      sync.RWMutex
    entries map[string]*cacheEntry
}

type cacheEntry struct {
    decision  *AccessDecision
    expiresAt time.Time
}

// NewMemoryCache creates a new memory cache
func NewMemoryCache() *MemoryCache {
    cache := &MemoryCache{
        entries: make(map[string]*cacheEntry),
    }
    
    go cache.cleanup()
    return cache
}

func (c *MemoryCache) Get(key string) (*AccessDecision, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()

    entry, exists := c.entries[key]
    if !exists || time.Now().After(entry.expiresAt) {
        return nil, false
    }

    return entry.decision, true
}

func (c *MemoryCache) Set(key string, decision *AccessDecision) {
    c.mu.Lock()
    defer c.mu.Unlock()

    c.entries[key] = &cacheEntry{
        decision:  decision,
        expiresAt: time.Now().Add(5 * time.Minute),
    }
}

func (c *MemoryCache) Delete(key string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    delete(c.entries, key)
}

func (c *MemoryCache) cleanup() {
    ticker := time.NewTicker(time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        c.mu.Lock()
        now := time.Now()
        for key, entry := range c.entries {
            if now.After(entry.expiresAt) {
                delete(c.entries, key)
            }
        }
        c.mu.Unlock()
    }
}
```

## Usage Example

```go
// Initialize access control system
storage, _ := NewFileStorage("/var/blackhole/rbac")
rbacManager := NewManager(storage)
policyEngine := NewPolicyEngine(storage)
resourceManager := NewResourceManager(storage)
cache := NewMemoryCache()

service := NewService(rbacManager, policyEngine, resourceManager, cache)

// Create permissions
rbacManager.CreatePermission("files", "read", "Read files")
rbacManager.CreatePermission("files", "write", "Write files")
rbacManager.CreatePermission("files", "delete", "Delete files")

// Create roles
adminRole, _ := rbacManager.CreateRole("admin", "Administrator", []string{
    "files:read",
    "files:write",
    "files:delete",
})

userRole, _ := rbacManager.CreateRole("user", "Regular User", []string{
    "files:read",
})

// Assign roles
rbacManager.AssignRole("user123", userRole.ID)

// Create policy for time-based access
policy := &Policy{
    Name:      "business-hours-only",
    Effect:    EffectAllow,
    Subjects:  []string{"role:user"},
    Resources: []string{"files/*"},
    Actions:   []string{"read"},
    Conditions: []Condition{
        {
            Type: "time",
            Parameters: map[string]interface{}{
                "start": "09:00:00",
                "end":   "17:00:00",
            },
        },
    },
    Priority: 100,
}
policyEngine.CreatePolicy(policy)

// Check access
request := &AccessRequest{
    Subject: &Subject{
        ID:    "user123",
        Type:  SubjectTypeUser,
        Roles: []string{"user"},
    },
    Resource:  "files/document.txt",
    Action:    "read",
    Context:   map[string]interface{}{"ip": "192.168.1.100"},
    Timestamp: time.Now(),
}

decision, _ := service.CheckAccess(request)
fmt.Printf("Access allowed: %v\n", decision.Allowed)
```

## Security Considerations

1. **Principle of Least Privilege**: Default deny, explicit allow
2. **Separation of Duties**: Separate role and permission management
3. **Audit Logging**: Log all access decisions
4. **Cache Security**: Time-limited cache entries
5. **Policy Conflicts**: Priority-based resolution

## Performance Optimizations

1. **Decision Caching**: Cache access decisions
2. **Permission Indexing**: Fast permission lookups
3. **Policy Ordering**: Evaluate by priority
4. **Lazy Loading**: Load resources on demand

## Testing

```go
func TestRBACManager(t *testing.T) {
    storage := NewMockStorage()
    manager := NewManager(storage)
    
    // Create permission
    perm, err := manager.CreatePermission("test", "read", "Test read")
    assert.NoError(t, err)
    assert.Equal(t, "test:read", perm.ID)
    
    // Create role
    role, err := manager.CreateRole("tester", "Test Role", []string{perm.ID})
    assert.NoError(t, err)
    assert.Contains(t, role.Permissions, perm.ID)
    
    // Assign role
    err = manager.AssignRole("user1", role.ID)
    assert.NoError(t, err)
    
    // Check permission
    hasPerm, err := manager.HasPermission("user1", "test", "read")
    assert.NoError(t, err)
    assert.True(t, hasPerm)
}

func TestPolicyEngine(t *testing.T) {
    storage := NewMockPolicyStorage()
    engine := NewPolicyEngine(storage)
    
    // Create allow policy
    policy := &Policy{
        Name:      "allow-read",
        Effect:    EffectAllow,
        Subjects:  []string{"user:test"},
        Resources: []string{"doc:*"},
        Actions:   []string{"read"},
        Priority:  100,
    }
    
    err := engine.CreatePolicy(policy)
    assert.NoError(t, err)
    
    // Evaluate request
    request := &AccessRequest{
        Subject: &Subject{
            ID:   "user:test",
            Type: SubjectTypeUser,
        },
        Resource:  "doc:123",
        Action:    "read",
        Timestamp: time.Now(),
    }
    
    decision, err := engine.Evaluate(request)
    assert.NoError(t, err)
    assert.True(t, decision.Allowed)
}
```

## Next Steps

1. Implement attribute-based access control (ABAC)
2. Add support for dynamic policies
3. Create policy testing framework
4. Implement delegation mechanisms
5. Add compliance reporting features