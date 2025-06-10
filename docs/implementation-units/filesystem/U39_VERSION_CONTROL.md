# U39: Version Control Implementation

## Overview
Git-like versioning system for the distributed filesystem. Provides snapshotting, branching, merging, and history tracking capabilities with efficient storage using content-addressed blocks.

## Architecture

```
Version Control System
├── Snapshot Management
├── Branch Operations
├── Merge Engine
├── History Tracking
└── Content Addressing
```

## Complete Implementation

### 1. Core Version Control Structures

```go
package version

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "sort"
    "strings"
    "time"
)

type CommitHash string
type BranchName string
type TreeHash string
type BlobHash string

type Commit struct {
    Hash      CommitHash    `json:"hash"`
    Tree      TreeHash      `json:"tree"`
    Parents   []CommitHash  `json:"parents"`
    Author    Author        `json:"author"`
    Committer Author        `json:"committer"`
    Message   string        `json:"message"`
    Timestamp time.Time     `json:"timestamp"`
    Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type Author struct {
    Name  string `json:"name"`
    Email string `json:"email"`
}

type Tree struct {
    Hash    TreeHash    `json:"hash"`
    Entries []TreeEntry `json:"entries"`
}

type TreeEntry struct {
    Mode uint32    `json:"mode"`
    Name string    `json:"name"`
    Hash string    `json:"hash"` // BlobHash or TreeHash
    Type EntryType `json:"type"`
    Size uint64    `json:"size,omitempty"`
}

type EntryType string

const (
    EntryTypeBlob     EntryType = "blob"
    EntryTypeTree     EntryType = "tree"
    EntryTypeSymlink  EntryType = "symlink"
    EntryTypeSubmodule EntryType = "submodule"
)

type Blob struct {
    Hash BlobHash `json:"hash"`
    Size uint64   `json:"size"`
    Data []byte   `json:"data"`
}

type Branch struct {
    Name   BranchName `json:"name"`
    Head   CommitHash `json:"head"`
    Active bool       `json:"active"`
    Remote string     `json:"remote,omitempty"`
    Upstream BranchName `json:"upstream,omitempty"`
}

type Tag struct {
    Name      string     `json:"name"`
    Target    CommitHash `json:"target"`
    Tagger    Author     `json:"tagger"`
    Message   string     `json:"message"`
    Timestamp time.Time  `json:"timestamp"`
}

type Reference struct {
    Name   string     `json:"name"`
    Target CommitHash `json:"target"`
    Type   RefType    `json:"type"`
}

type RefType string

const (
    RefTypeBranch RefType = "branch"
    RefTypeTag    RefType = "tag"
    RefTypeRemote RefType = "remote"
)

type DiffEntry struct {
    OldPath string    `json:"old_path,omitempty"`
    NewPath string    `json:"new_path,omitempty"`
    OldHash string    `json:"old_hash,omitempty"`
    NewHash string    `json:"new_hash,omitempty"`
    Status  DiffStatus `json:"status"`
    Chunks  []DiffChunk `json:"chunks,omitempty"`
}

type DiffStatus string

const (
    DiffStatusAdded    DiffStatus = "added"
    DiffStatusDeleted  DiffStatus = "deleted"
    DiffStatusModified DiffStatus = "modified"
    DiffStatusRenamed  DiffStatus = "renamed"
    DiffStatusCopied   DiffStatus = "copied"
)

type DiffChunk struct {
    OldStart int      `json:"old_start"`
    OldCount int      `json:"old_count"`
    NewStart int      `json:"new_start"`
    NewCount int      `json:"new_count"`
    Lines    []string `json:"lines"`
}

type MergeResult struct {
    Hash       CommitHash    `json:"hash"`
    Conflicts  []Conflict    `json:"conflicts"`
    Success    bool          `json:"success"`
    Statistics MergeStats    `json:"statistics"`
}

type Conflict struct {
    Path    string      `json:"path"`
    Ours    string      `json:"ours"`
    Theirs  string      `json:"theirs"`
    Base    string      `json:"base,omitempty"`
    Type    ConflictType `json:"type"`
}

type ConflictType string

const (
    ConflictTypeContent  ConflictType = "content"
    ConflictTypeRename   ConflictType = "rename"
    ConflictTypeDelete   ConflictType = "delete"
    ConflictTypeMode     ConflictType = "mode"
)

type MergeStats struct {
    FilesChanged int `json:"files_changed"`
    Insertions   int `json:"insertions"`
    Deletions    int `json:"deletions"`
    Conflicts    int `json:"conflicts"`
}
```

### 2. Version Control Service

```go
package version

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "path/filepath"
    "strings"
    "sync"
    "time"
)

type VersionControlService struct {
    storage     *VersionStorage
    metadata    *MetadataService
    blockStore  BlockStore
    config      *VersionConfig
    mu          sync.RWMutex
    refs        map[string]*Reference
    branches    map[BranchName]*Branch
    currentBranch BranchName
}

type VersionConfig struct {
    DefaultBranch    BranchName    `yaml:"default_branch"`
    AutoGC          bool          `yaml:"auto_gc"`
    GCInterval      time.Duration `yaml:"gc_interval"`
    MaxHistoryDepth int           `yaml:"max_history_depth"`
    CompressionLevel int          `yaml:"compression_level"`
}

type BlockStore interface {
    Get(hash string) ([]byte, error)
    Put(hash string, data []byte) error
    Delete(hash string) error
    Exists(hash string) bool
    List() ([]string, error)
}

func NewVersionControlService(storage *VersionStorage, metadata *MetadataService, blockStore BlockStore, config *VersionConfig) *VersionControlService {
    if config == nil {
        config = DefaultVersionConfig()
    }
    
    vcs := &VersionControlService{
        storage:       storage,
        metadata:      metadata,
        blockStore:    blockStore,
        config:        config,
        refs:          make(map[string]*Reference),
        branches:      make(map[BranchName]*Branch),
        currentBranch: config.DefaultBranch,
    }
    
    // Initialize default branch if it doesn't exist
    if !vcs.BranchExists(config.DefaultBranch) {
        vcs.CreateBranch(config.DefaultBranch, "")
    }
    
    return vcs
}

func DefaultVersionConfig() *VersionConfig {
    return &VersionConfig{
        DefaultBranch:    "main",
        AutoGC:          true,
        GCInterval:      24 * time.Hour,
        MaxHistoryDepth: 1000,
        CompressionLevel: 6,
    }
}
```

### 3. Snapshot Management

```go
func (vcs *VersionControlService) CreateSnapshot(message string, author Author) (*Commit, error) {
    vcs.mu.Lock()
    defer vcs.mu.Unlock()
    
    // Get current working tree
    tree, err := vcs.buildTree("/")
    if err != nil {
        return nil, fmt.Errorf("failed to build tree: %v", err)
    }
    
    // Get parent commits
    var parents []CommitHash
    if currentBranch, exists := vcs.branches[vcs.currentBranch]; exists && currentBranch.Head != "" {
        parents = append(parents, currentBranch.Head)
    }
    
    // Create commit
    commit := &Commit{
        Tree:      tree.Hash,
        Parents:   parents,
        Author:    author,
        Committer: author,
        Message:   message,
        Timestamp: time.Now(),
        Metadata:  make(map[string]interface{}),
    }
    
    // Calculate commit hash
    commit.Hash = vcs.calculateCommitHash(commit)
    
    // Store commit
    if err := vcs.storage.StoreCommit(commit); err != nil {
        return nil, fmt.Errorf("failed to store commit: %v", err)
    }
    
    // Update branch head
    if err := vcs.updateBranchHead(vcs.currentBranch, commit.Hash); err != nil {
        return nil, fmt.Errorf("failed to update branch head: %v", err)
    }
    
    return commit, nil
}

func (vcs *VersionControlService) buildTree(path string) (*Tree, error) {
    entries, err := vcs.metadata.ListDirectory(path)
    if err != nil {
        return nil, err
    }
    
    var treeEntries []TreeEntry
    
    for _, entry := range entries {
        if entry.Name == "." || entry.Name == ".." {
            continue
        }
        
        fullPath := filepath.Join(path, entry.Name)
        inode, err := vcs.metadata.GetInode(fullPath)
        if err != nil {
            continue
        }
        
        var hash string
        var entryType EntryType
        
        if inode.IsDir() {
            // Recursively build subtree
            subtree, err := vcs.buildTree(fullPath)
            if err != nil {
                return nil, err
            }
            hash = string(subtree.Hash)
            entryType = EntryTypeTree
            
            // Store subtree
            if err := vcs.storage.StoreTree(subtree); err != nil {
                return nil, err
            }
        } else if inode.IsSymlink() {
            // Handle symlink
            target, err := vcs.metadata.ReadSymlink(fullPath)
            if err != nil {
                return nil, err
            }
            blob := &Blob{
                Data: []byte(target),
                Size: uint64(len(target)),
            }
            blob.Hash = vcs.calculateBlobHash(blob)
            hash = string(blob.Hash)
            entryType = EntryTypeSymlink
            
            // Store blob
            if err := vcs.storage.StoreBlob(blob); err != nil {
                return nil, err
            }
        } else {
            // Regular file - create blob from blocks
            blob, err := vcs.createBlobFromBlocks(inode.Blocks)
            if err != nil {
                return nil, err
            }
            hash = string(blob.Hash)
            entryType = EntryTypeBlob
            
            // Store blob
            if err := vcs.storage.StoreBlob(blob); err != nil {
                return nil, err
            }
        }
        
        treeEntry := TreeEntry{
            Mode: inode.Mode,
            Name: entry.Name,
            Hash: hash,
            Type: entryType,
            Size: inode.Size,
        }
        
        treeEntries = append(treeEntries, treeEntry)
    }
    
    // Sort entries by name for consistent hashing
    sort.Slice(treeEntries, func(i, j int) bool {
        return treeEntries[i].Name < treeEntries[j].Name
    })
    
    tree := &Tree{
        Entries: treeEntries,
    }
    tree.Hash = vcs.calculateTreeHash(tree)
    
    return tree, nil
}

func (vcs *VersionControlService) createBlobFromBlocks(blockHashes []string) (*Blob, error) {
    var data []byte
    
    for _, blockHash := range blockHashes {
        blockData, err := vcs.blockStore.Get(blockHash)
        if err != nil {
            return nil, fmt.Errorf("failed to get block %s: %v", blockHash, err)
        }
        data = append(data, blockData...)
    }
    
    blob := &Blob{
        Data: data,
        Size: uint64(len(data)),
    }
    blob.Hash = vcs.calculateBlobHash(blob)
    
    return blob, nil
}

func (vcs *VersionControlService) RestoreSnapshot(commitHash CommitHash) error {
    commit, err := vcs.storage.GetCommit(commitHash)
    if err != nil {
        return fmt.Errorf("commit not found: %v", err)
    }
    
    // Get tree
    tree, err := vcs.storage.GetTree(commit.Tree)
    if err != nil {
        return fmt.Errorf("tree not found: %v", err)
    }
    
    // Restore filesystem state
    return vcs.restoreTree(tree, "/")
}

func (vcs *VersionControlService) restoreTree(tree *Tree, basePath string) error {
    // First, remove existing entries that aren't in the snapshot
    existing, err := vcs.metadata.ListDirectory(basePath)
    if err != nil && basePath != "/" {
        // Create directory if it doesn't exist
        if err := vcs.metadata.CreateDirectory(basePath, 0755, 0, 0); err != nil {
            return err
        }
        existing = []DirectoryEntry{}
    }
    
    // Build map of entries in snapshot
    snapshotEntries := make(map[string]bool)
    for _, entry := range tree.Entries {
        snapshotEntries[entry.Name] = true
    }
    
    // Remove entries not in snapshot
    for _, entry := range existing {
        if entry.Name == "." || entry.Name == ".." {
            continue
        }
        
        if !snapshotEntries[entry.Name] {
            fullPath := filepath.Join(basePath, entry.Name)
            inode, err := vcs.metadata.GetInode(fullPath)
            if err != nil {
                continue
            }
            
            if inode.IsDir() {
                vcs.metadata.RemoveDirectory(fullPath)
            } else {
                vcs.metadata.RemoveFile(fullPath)
            }
        }
    }
    
    // Restore entries from snapshot
    for _, entry := range tree.Entries {
        fullPath := filepath.Join(basePath, entry.Name)
        
        switch entry.Type {
        case EntryTypeTree:
            // Create or update directory
            if _, err := vcs.metadata.GetInode(fullPath); err != nil {
                if err := vcs.metadata.CreateDirectory(fullPath, entry.Mode, 0, 0); err != nil {
                    return err
                }
            }
            
            // Recursively restore subtree
            subtree, err := vcs.storage.GetTree(TreeHash(entry.Hash))
            if err != nil {
                return err
            }
            
            if err := vcs.restoreTree(subtree, fullPath); err != nil {
                return err
            }
            
        case EntryTypeBlob:
            // Restore regular file
            blob, err := vcs.storage.GetBlob(BlobHash(entry.Hash))
            if err != nil {
                return err
            }
            
            if err := vcs.restoreFile(fullPath, blob, entry.Mode); err != nil {
                return err
            }
            
        case EntryTypeSymlink:
            // Restore symlink
            blob, err := vcs.storage.GetBlob(BlobHash(entry.Hash))
            if err != nil {
                return err
            }
            
            target := string(blob.Data)
            if err := vcs.metadata.CreateSymlink(fullPath, target); err != nil {
                return err
            }
        }
    }
    
    return nil
}

func (vcs *VersionControlService) restoreFile(path string, blob *Blob, mode uint32) error {
    // Remove existing file if it exists
    if _, err := vcs.metadata.GetInode(path); err == nil {
        vcs.metadata.RemoveFile(path)
    }
    
    // Create new file
    inode, err := vcs.metadata.CreateFile(path, mode, 0, 0)
    if err != nil {
        return err
    }
    
    // Split blob data into blocks and store
    blockSize := 64 * 1024 // 64KB blocks
    var blockHashes []string
    
    for i := 0; i < len(blob.Data); i += blockSize {
        end := i + blockSize
        if end > len(blob.Data) {
            end = len(blob.Data)
        }
        
        blockData := blob.Data[i:end]
        blockHash := vcs.calculateBlockHash(blockData)
        
        if err := vcs.blockStore.Put(blockHash, blockData); err != nil {
            return err
        }
        
        blockHashes = append(blockHashes, blockHash)
    }
    
    // Update inode with block hashes
    return vcs.metadata.UpdateInode(path, &InodeUpdate{
        Blocks: &blockHashes,
        Size:   &blob.Size,
    })
}
```

### 4. Branch Operations

```go
func (vcs *VersionControlService) CreateBranch(name BranchName, startPoint string) error {
    vcs.mu.Lock()
    defer vcs.mu.Unlock()
    
    if _, exists := vcs.branches[name]; exists {
        return fmt.Errorf("branch %s already exists", name)
    }
    
    var head CommitHash
    if startPoint != "" {
        // Parse start point (could be commit hash, branch name, or tag)
        var err error
        head, err = vcs.resolveReference(startPoint)
        if err != nil {
            return fmt.Errorf("invalid start point %s: %v", startPoint, err)
        }
    }
    
    branch := &Branch{
        Name:   name,
        Head:   head,
        Active: false,
    }
    
    vcs.branches[name] = branch
    
    // Store branch reference
    ref := &Reference{
        Name:   fmt.Sprintf("refs/heads/%s", name),
        Target: head,
        Type:   RefTypeBranch,
    }
    
    return vcs.storage.StoreReference(ref)
}

func (vcs *VersionControlService) DeleteBranch(name BranchName, force bool) error {
    vcs.mu.Lock()
    defer vcs.mu.Unlock()
    
    if name == vcs.currentBranch {
        return fmt.Errorf("cannot delete current branch %s", name)
    }
    
    branch, exists := vcs.branches[name]
    if !exists {
        return fmt.Errorf("branch %s does not exist", name)
    }
    
    if !force {
        // Check if branch is merged
        merged, err := vcs.isBranchMerged(name)
        if err != nil {
            return err
        }
        if !merged {
            return fmt.Errorf("branch %s is not merged, use force to delete", name)
        }
    }
    
    delete(vcs.branches, name)
    
    // Remove branch reference
    refName := fmt.Sprintf("refs/heads/%s", name)
    return vcs.storage.DeleteReference(refName)
}

func (vcs *VersionControlService) CheckoutBranch(name BranchName) error {
    vcs.mu.Lock()
    defer vcs.mu.Unlock()
    
    branch, exists := vcs.branches[name]
    if !exists {
        return fmt.Errorf("branch %s does not exist", name)
    }
    
    // Mark current branch as inactive
    if currentBranch, exists := vcs.branches[vcs.currentBranch]; exists {
        currentBranch.Active = false
    }
    
    // Restore filesystem to branch state
    if branch.Head != "" {
        if err := vcs.RestoreSnapshot(branch.Head); err != nil {
            return fmt.Errorf("failed to restore branch state: %v", err)
        }
    }
    
    // Set new current branch
    vcs.currentBranch = name
    branch.Active = true
    
    return nil
}

func (vcs *VersionControlService) ListBranches() ([]*Branch, error) {
    vcs.mu.RLock()
    defer vcs.mu.RUnlock()
    
    var branches []*Branch
    for _, branch := range vcs.branches {
        branchCopy := *branch
        branches = append(branches, &branchCopy)
    }
    
    // Sort by name
    sort.Slice(branches, func(i, j int) bool {
        return branches[i].Name < branches[j].Name
    })
    
    return branches, nil
}

func (vcs *VersionControlService) GetCurrentBranch() BranchName {
    vcs.mu.RLock()
    defer vcs.mu.RUnlock()
    return vcs.currentBranch
}

func (vcs *VersionControlService) BranchExists(name BranchName) bool {
    vcs.mu.RLock()
    defer vcs.mu.RUnlock()
    _, exists := vcs.branches[name]
    return exists
}

func (vcs *VersionControlService) isBranchMerged(name BranchName) (bool, error) {
    branch := vcs.branches[name]
    if branch.Head == "" {
        return true, nil
    }
    
    // Check if branch head is reachable from default branch
    defaultBranch := vcs.branches[vcs.config.DefaultBranch]
    if defaultBranch.Head == "" {
        return false, nil
    }
    
    return vcs.isCommitReachable(branch.Head, defaultBranch.Head)
}

func (vcs *VersionControlService) isCommitReachable(target, from CommitHash) (bool, error) {
    if target == from {
        return true, nil
    }
    
    visited := make(map[CommitHash]bool)
    queue := []CommitHash{from}
    
    for len(queue) > 0 {
        current := queue[0]
        queue = queue[1:]
        
        if visited[current] {
            continue
        }
        visited[current] = true
        
        if current == target {
            return true, nil
        }
        
        commit, err := vcs.storage.GetCommit(current)
        if err != nil {
            continue
        }
        
        for _, parent := range commit.Parents {
            if !visited[parent] {
                queue = append(queue, parent)
            }
        }
    }
    
    return false, nil
}
```

### 5. Merge Engine

```go
func (vcs *VersionControlService) MergeBranch(sourceBranch BranchName, message string, author Author) (*MergeResult, error) {
    vcs.mu.Lock()
    defer vcs.mu.Unlock()
    
    source, exists := vcs.branches[sourceBranch]
    if !exists {
        return nil, fmt.Errorf("source branch %s does not exist", sourceBranch)
    }
    
    target := vcs.branches[vcs.currentBranch]
    
    // Check if merge is needed
    if source.Head == target.Head {
        return &MergeResult{
            Success: true,
            Statistics: MergeStats{},
        }, nil
    }
    
    // Find merge base
    mergeBase, err := vcs.findMergeBase(source.Head, target.Head)
    if err != nil {
        return nil, fmt.Errorf("failed to find merge base: %v", err)
    }
    
    // Check for fast-forward merge
    if mergeBase == target.Head {
        // Fast-forward merge
        return vcs.fastForwardMerge(source.Head)
    }
    
    // Three-way merge
    return vcs.threeWayMerge(mergeBase, target.Head, source.Head, message, author)
}

func (vcs *VersionControlService) fastForwardMerge(sourceHead CommitHash) (*MergeResult, error) {
    // Update current branch head
    if err := vcs.updateBranchHead(vcs.currentBranch, sourceHead); err != nil {
        return nil, err
    }
    
    // Update filesystem
    if err := vcs.RestoreSnapshot(sourceHead); err != nil {
        return nil, err
    }
    
    return &MergeResult{
        Hash:    sourceHead,
        Success: true,
        Statistics: MergeStats{
            FilesChanged: 0, // TODO: Calculate actual stats
        },
    }, nil
}

func (vcs *VersionControlService) threeWayMerge(base, ours, theirs CommitHash, message string, author Author) (*MergeResult, error) {
    // Get trees for all three commits
    baseTree, err := vcs.getCommitTree(base)
    if err != nil {
        return nil, err
    }
    
    oursTree, err := vcs.getCommitTree(ours)
    if err != nil {
        return nil, err
    }
    
    theirsTree, err := vcs.getCommitTree(theirs)
    if err != nil {
        return nil, err
    }
    
    // Perform three-way merge
    mergedTree, conflicts, err := vcs.mergeTreesThreeWay(baseTree, oursTree, theirsTree)
    if err != nil {
        return nil, err
    }
    
    result := &MergeResult{
        Conflicts: conflicts,
        Success:   len(conflicts) == 0,
        Statistics: MergeStats{
            Conflicts: len(conflicts),
        },
    }
    
    if result.Success {
        // Create merge commit
        commit := &Commit{
            Tree:      mergedTree.Hash,
            Parents:   []CommitHash{ours, theirs},
            Author:    author,
            Committer: author,
            Message:   message,
            Timestamp: time.Now(),
        }
        commit.Hash = vcs.calculateCommitHash(commit)
        
        // Store commit and update branch
        if err := vcs.storage.StoreCommit(commit); err != nil {
            return nil, err
        }
        
        if err := vcs.updateBranchHead(vcs.currentBranch, commit.Hash); err != nil {
            return nil, err
        }
        
        result.Hash = commit.Hash
        
        // Update filesystem
        if err := vcs.RestoreSnapshot(commit.Hash); err != nil {
            return nil, err
        }
    }
    
    return result, nil
}

func (vcs *VersionControlService) mergeTreesThreeWay(base, ours, theirs *Tree) (*Tree, []Conflict, error) {
    // Build maps for easier comparison
    baseEntries := make(map[string]TreeEntry)
    oursEntries := make(map[string]TreeEntry)
    theirsEntries := make(map[string]TreeEntry)
    
    for _, entry := range base.Entries {
        baseEntries[entry.Name] = entry
    }
    for _, entry := range ours.Entries {
        oursEntries[entry.Name] = entry
    }
    for _, entry := range theirs.Entries {
        theirsEntries[entry.Name] = entry
    }
    
    // Collect all unique file names
    allNames := make(map[string]bool)
    for name := range baseEntries {
        allNames[name] = true
    }
    for name := range oursEntries {
        allNames[name] = true
    }
    for name := range theirsEntries {
        allNames[name] = true
    }
    
    var mergedEntries []TreeEntry
    var conflicts []Conflict
    
    for name := range allNames {
        baseEntry, inBase := baseEntries[name]
        oursEntry, inOurs := oursEntries[name]
        theirsEntry, inTheirs := theirsEntries[name]
        
        conflict, mergedEntry := vcs.mergeTreeEntry(name, baseEntry, oursEntry, theirsEntry, inBase, inOurs, inTheirs)
        
        if conflict != nil {
            conflicts = append(conflicts, *conflict)
        } else if mergedEntry != nil {
            mergedEntries = append(mergedEntries, *mergedEntry)
        }
    }
    
    // Sort entries for consistent hashing
    sort.Slice(mergedEntries, func(i, j int) bool {
        return mergedEntries[i].Name < mergedEntries[j].Name
    })
    
    mergedTree := &Tree{
        Entries: mergedEntries,
    }
    mergedTree.Hash = vcs.calculateTreeHash(mergedTree)
    
    // Store merged tree
    if err := vcs.storage.StoreTree(mergedTree); err != nil {
        return nil, conflicts, err
    }
    
    return mergedTree, conflicts, nil
}

func (vcs *VersionControlService) mergeTreeEntry(name string, base, ours, theirs TreeEntry, inBase, inOurs, inTheirs bool) (*Conflict, *TreeEntry) {
    // File added in both branches
    if !inBase && inOurs && inTheirs {
        if ours.Hash == theirs.Hash {
            return nil, &ours // Same content, no conflict
        }
        return &Conflict{
            Path:   name,
            Ours:   ours.Hash,
            Theirs: theirs.Hash,
            Type:   ConflictTypeContent,
        }, nil
    }
    
    // File deleted in one branch, modified in another
    if inBase && !inOurs && inTheirs && base.Hash != theirs.Hash {
        return &Conflict{
            Path:   name,
            Ours:   "", // deleted
            Theirs: theirs.Hash,
            Base:   base.Hash,
            Type:   ConflictTypeDelete,
        }, nil
    }
    
    if inBase && inOurs && !inTheirs && base.Hash != ours.Hash {
        return &Conflict{
            Path:   name,
            Ours:   ours.Hash,
            Theirs: "", // deleted
            Base:   base.Hash,
            Type:   ConflictTypeDelete,
        }, nil
    }
    
    // File modified in both branches
    if inBase && inOurs && inTheirs {
        oursChanged := base.Hash != ours.Hash
        theirsChanged := base.Hash != theirs.Hash
        
        if oursChanged && theirsChanged {
            if ours.Hash == theirs.Hash {
                return nil, &ours // Same changes, no conflict
            }
            
            // Content conflict - need to merge file contents
            if ours.Type == EntryTypeBlob && theirs.Type == EntryTypeBlob {
                mergedEntry, conflict := vcs.mergeFileContents(name, base.Hash, ours.Hash, theirs.Hash)
                return conflict, mergedEntry
            }
            
            return &Conflict{
                Path:   name,
                Ours:   ours.Hash,
                Theirs: theirs.Hash,
                Base:   base.Hash,
                Type:   ConflictTypeContent,
            }, nil
        }
        
        if oursChanged {
            return nil, &ours
        }
        if theirsChanged {
            return nil, &theirs
        }
        
        return nil, &base // No changes
    }
    
    // File exists in only one branch
    if inOurs {
        return nil, &ours
    }
    if inTheirs {
        return nil, &theirs
    }
    
    return nil, nil // File doesn't exist in any branch
}

func (vcs *VersionControlService) mergeFileContents(path, baseHash, oursHash, theirsHash string) (*TreeEntry, *Conflict) {
    // Get file contents
    baseBlob, _ := vcs.storage.GetBlob(BlobHash(baseHash))
    oursBlob, _ := vcs.storage.GetBlob(BlobHash(oursHash))
    theirsBlob, _ := vcs.storage.GetBlob(BlobHash(theirsHash))
    
    if baseBlob == nil || oursBlob == nil || theirsBlob == nil {
        return nil, &Conflict{
            Path:   path,
            Ours:   oursHash,
            Theirs: theirsHash,
            Base:   baseHash,
            Type:   ConflictTypeContent,
        }
    }
    
    // Simple line-based merge
    baseLines := strings.Split(string(baseBlob.Data), "\n")
    oursLines := strings.Split(string(oursBlob.Data), "\n")
    theirsLines := strings.Split(string(theirsBlob.Data), "\n")
    
    mergedLines, hasConflict := vcs.mergeLines(baseLines, oursLines, theirsLines)
    
    if hasConflict {
        return nil, &Conflict{
            Path:   path,
            Ours:   oursHash,
            Theirs: theirsHash,
            Base:   baseHash,
            Type:   ConflictTypeContent,
        }
    }
    
    // Create merged blob
    mergedContent := strings.Join(mergedLines, "\n")
    mergedBlob := &Blob{
        Data: []byte(mergedContent),
        Size: uint64(len(mergedContent)),
    }
    mergedBlob.Hash = vcs.calculateBlobHash(mergedBlob)
    
    // Store merged blob
    if err := vcs.storage.StoreBlob(mergedBlob); err != nil {
        return nil, &Conflict{
            Path:   path,
            Ours:   oursHash,
            Theirs: theirsHash,
            Base:   baseHash,
            Type:   ConflictTypeContent,
        }
    }
    
    // Create tree entry for merged file
    // Use ours entry as template and update hash
    oursBlob, _ = vcs.storage.GetBlob(BlobHash(oursHash))
    entry := TreeEntry{
        Mode: 0644, // Default file mode
        Name: path,
        Hash: string(mergedBlob.Hash),
        Type: EntryTypeBlob,
        Size: mergedBlob.Size,
    }
    
    return &entry, nil
}

func (vcs *VersionControlService) mergeLines(base, ours, theirs []string) ([]string, bool) {
    // Simple three-way merge algorithm
    // This is a simplified version - a real implementation would use a more sophisticated algorithm
    
    var result []string
    hasConflict := false
    
    i, j, k := 0, 0, 0
    
    for i < len(base) && j < len(ours) && k < len(theirs) {
        if base[i] == ours[j] && base[i] == theirs[k] {
            // No changes
            result = append(result, base[i])
            i++
            j++
            k++
        } else if base[i] == ours[j] && base[i] != theirs[k] {
            // Changed in theirs only
            result = append(result, theirs[k])
            i++
            j++
            k++
        } else if base[i] != ours[j] && base[i] == theirs[k] {
            // Changed in ours only
            result = append(result, ours[j])
            i++
            j++
            k++
        } else {
            // Conflict - changed in both
            hasConflict = true
            result = append(result, "<<<<<<< ours")
            result = append(result, ours[j])
            result = append(result, "=======")
            result = append(result, theirs[k])
            result = append(result, ">>>>>>> theirs")
            i++
            j++
            k++
        }
    }
    
    // Handle remaining lines
    for j < len(ours) {
        result = append(result, ours[j])
        j++
    }
    for k < len(theirs) {
        result = append(result, theirs[k])
        k++
    }
    
    return result, hasConflict
}

func (vcs *VersionControlService) findMergeBase(commit1, commit2 CommitHash) (CommitHash, error) {
    // Find common ancestor using simple algorithm
    ancestors1 := make(map[CommitHash]bool)
    
    // Get all ancestors of commit1
    queue := []CommitHash{commit1}
    for len(queue) > 0 {
        current := queue[0]
        queue = queue[1:]
        
        if ancestors1[current] {
            continue
        }
        ancestors1[current] = true
        
        commit, err := vcs.storage.GetCommit(current)
        if err != nil {
            continue
        }
        
        for _, parent := range commit.Parents {
            queue = append(queue, parent)
        }
    }
    
    // Find first common ancestor from commit2
    queue = []CommitHash{commit2}
    visited := make(map[CommitHash]bool)
    
    for len(queue) > 0 {
        current := queue[0]
        queue = queue[1:]
        
        if visited[current] {
            continue
        }
        visited[current] = true
        
        if ancestors1[current] {
            return current, nil
        }
        
        commit, err := vcs.storage.GetCommit(current)
        if err != nil {
            continue
        }
        
        for _, parent := range commit.Parents {
            if !visited[parent] {
                queue = append(queue, parent)
            }
        }
    }
    
    return "", fmt.Errorf("no common ancestor found")
}

func (vcs *VersionControlService) getCommitTree(commitHash CommitHash) (*Tree, error) {
    if commitHash == "" {
        // Empty tree
        return &Tree{Entries: []TreeEntry{}}, nil
    }
    
    commit, err := vcs.storage.GetCommit(commitHash)
    if err != nil {
        return nil, err
    }
    
    return vcs.storage.GetTree(commit.Tree)
}
```

### 6. History and Diff Operations

```go
func (vcs *VersionControlService) GetCommitHistory(branch BranchName, limit int) ([]*Commit, error) {
    vcs.mu.RLock()
    defer vcs.mu.RUnlock()
    
    branchObj, exists := vcs.branches[branch]
    if !exists {
        return nil, fmt.Errorf("branch %s does not exist", branch)
    }
    
    if branchObj.Head == "" {
        return []*Commit{}, nil
    }
    
    var commits []*Commit
    visited := make(map[CommitHash]bool)
    queue := []CommitHash{branchObj.Head}
    
    for len(queue) > 0 && (limit == 0 || len(commits) < limit) {
        current := queue[0]
        queue = queue[1:]
        
        if visited[current] {
            continue
        }
        visited[current] = true
        
        commit, err := vcs.storage.GetCommit(current)
        if err != nil {
            continue
        }
        
        commits = append(commits, commit)
        
        // Add parents to queue
        for _, parent := range commit.Parents {
            if !visited[parent] {
                queue = append(queue, parent)
            }
        }
    }
    
    return commits, nil
}

func (vcs *VersionControlService) GetCommit(hash CommitHash) (*Commit, error) {
    return vcs.storage.GetCommit(hash)
}

func (vcs *VersionControlService) DiffCommits(from, to CommitHash) ([]DiffEntry, error) {
    fromTree, err := vcs.getCommitTree(from)
    if err != nil {
        return nil, err
    }
    
    toTree, err := vcs.getCommitTree(to)
    if err != nil {
        return nil, err
    }
    
    return vcs.diffTrees(fromTree, toTree)
}

func (vcs *VersionControlService) diffTrees(from, to *Tree) ([]DiffEntry, error) {
    fromEntries := make(map[string]TreeEntry)
    toEntries := make(map[string]TreeEntry)
    
    for _, entry := range from.Entries {
        fromEntries[entry.Name] = entry
    }
    for _, entry := range to.Entries {
        toEntries[entry.Name] = entry
    }
    
    // Collect all unique names
    allNames := make(map[string]bool)
    for name := range fromEntries {
        allNames[name] = true
    }
    for name := range toEntries {
        allNames[name] = true
    }
    
    var diffs []DiffEntry
    
    for name := range allNames {
        fromEntry, inFrom := fromEntries[name]
        toEntry, inTo := toEntries[name]
        
        if !inFrom && inTo {
            // Added
            diffs = append(diffs, DiffEntry{
                NewPath: name,
                NewHash: toEntry.Hash,
                Status:  DiffStatusAdded,
            })
        } else if inFrom && !inTo {
            // Deleted
            diffs = append(diffs, DiffEntry{
                OldPath: name,
                OldHash: fromEntry.Hash,
                Status:  DiffStatusDeleted,
            })
        } else if inFrom && inTo {
            if fromEntry.Hash != toEntry.Hash {
                // Modified
                diff := DiffEntry{
                    OldPath: name,
                    NewPath: name,
                    OldHash: fromEntry.Hash,
                    NewHash: toEntry.Hash,
                    Status:  DiffStatusModified,
                }
                
                // Add content diff for files
                if fromEntry.Type == EntryTypeBlob && toEntry.Type == EntryTypeBlob {
                    chunks, err := vcs.diffFileContents(fromEntry.Hash, toEntry.Hash)
                    if err == nil {
                        diff.Chunks = chunks
                    }
                }
                
                diffs = append(diffs, diff)
            }
        }
    }
    
    return diffs, nil
}

func (vcs *VersionControlService) diffFileContents(fromHash, toHash string) ([]DiffChunk, error) {
    fromBlob, err := vcs.storage.GetBlob(BlobHash(fromHash))
    if err != nil {
        return nil, err
    }
    
    toBlob, err := vcs.storage.GetBlob(BlobHash(toHash))
    if err != nil {
        return nil, err
    }
    
    fromLines := strings.Split(string(fromBlob.Data), "\n")
    toLines := strings.Split(string(toBlob.Data), "\n")
    
    // Simple diff algorithm (Myers algorithm would be better)
    var chunks []DiffChunk
    
    i, j := 0, 0
    for i < len(fromLines) || j < len(toLines) {
        // Find matching lines
        matchFound := false
        for di := 0; di < 10 && i+di < len(fromLines); di++ {
            for dj := 0; dj < 10 && j+dj < len(toLines); dj++ {
                if fromLines[i+di] == toLines[j+dj] {
                    // Found match, create chunk for differences before match
                    if di > 0 || dj > 0 {
                        chunk := DiffChunk{
                            OldStart: i + 1,
                            OldCount: di,
                            NewStart: j + 1,
                            NewCount: dj,
                        }
                        
                        for k := 0; k < di; k++ {
                            chunk.Lines = append(chunk.Lines, "-"+fromLines[i+k])
                        }
                        for k := 0; k < dj; k++ {
                            chunk.Lines = append(chunk.Lines, "+"+toLines[j+k])
                        }
                        
                        chunks = append(chunks, chunk)
                    }
                    
                    i += di + 1
                    j += dj + 1
                    matchFound = true
                    break
                }
            }
            if matchFound {
                break
            }
        }
        
        if !matchFound {
            // No match found, treat as all different
            oldCount := len(fromLines) - i
            newCount := len(toLines) - j
            
            chunk := DiffChunk{
                OldStart: i + 1,
                OldCount: oldCount,
                NewStart: j + 1,
                NewCount: newCount,
            }
            
            for k := i; k < len(fromLines); k++ {
                chunk.Lines = append(chunk.Lines, "-"+fromLines[k])
            }
            for k := j; k < len(toLines); k++ {
                chunk.Lines = append(chunk.Lines, "+"+toLines[k])
            }
            
            chunks = append(chunks, chunk)
            break
        }
    }
    
    return chunks, nil
}
```

### 7. Hash Calculation Functions

```go
func (vcs *VersionControlService) calculateCommitHash(commit *Commit) CommitHash {
    data := fmt.Sprintf("commit\x00tree %s\n", commit.Tree)
    
    for _, parent := range commit.Parents {
        data += fmt.Sprintf("parent %s\n", parent)
    }
    
    data += fmt.Sprintf("author %s <%s> %d\n", commit.Author.Name, commit.Author.Email, commit.Timestamp.Unix())
    data += fmt.Sprintf("committer %s <%s> %d\n", commit.Committer.Name, commit.Committer.Email, commit.Timestamp.Unix())
    data += "\n" + commit.Message
    
    hash := sha256.Sum256([]byte(data))
    return CommitHash(hex.EncodeToString(hash[:]))
}

func (vcs *VersionControlService) calculateTreeHash(tree *Tree) TreeHash {
    var data strings.Builder
    data.WriteString("tree\x00")
    
    for _, entry := range tree.Entries {
        data.WriteString(fmt.Sprintf("%o %s\x00%s", entry.Mode, entry.Name, entry.Hash))
    }
    
    hash := sha256.Sum256([]byte(data.String()))
    return TreeHash(hex.EncodeToString(hash[:]))
}

func (vcs *VersionControlService) calculateBlobHash(blob *Blob) BlobHash {
    data := fmt.Sprintf("blob %d\x00", blob.Size)
    data += string(blob.Data)
    
    hash := sha256.Sum256([]byte(data))
    return BlobHash(hex.EncodeToString(hash[:]))
}

func (vcs *VersionControlService) calculateBlockHash(data []byte) string {
    hash := sha256.Sum256(data)
    return hex.EncodeToString(hash[:])
}
```

### 8. Utility Functions

```go
func (vcs *VersionControlService) resolveReference(ref string) (CommitHash, error) {
    // Try as commit hash first
    if len(ref) == 64 { // SHA-256 hex
        if _, err := vcs.storage.GetCommit(CommitHash(ref)); err == nil {
            return CommitHash(ref), nil
        }
    }
    
    // Try as branch name
    if branch, exists := vcs.branches[BranchName(ref)]; exists {
        return branch.Head, nil
    }
    
    // Try as tag name
    if tag, err := vcs.storage.GetTag(ref); err == nil {
        return tag.Target, nil
    }
    
    // Try as reference name
    if reference, err := vcs.storage.GetReference(ref); err == nil {
        return reference.Target, nil
    }
    
    return "", fmt.Errorf("reference %s not found", ref)
}

func (vcs *VersionControlService) updateBranchHead(branch BranchName, head CommitHash) error {
    if branchObj, exists := vcs.branches[branch]; exists {
        branchObj.Head = head
        
        // Update reference
        ref := &Reference{
            Name:   fmt.Sprintf("refs/heads/%s", branch),
            Target: head,
            Type:   RefTypeBranch,
        }
        
        return vcs.storage.StoreReference(ref)
    }
    
    return fmt.Errorf("branch %s not found", branch)
}
```

### 9. Tag Operations

```go
func (vcs *VersionControlService) CreateTag(name string, target CommitHash, message string, author Author) error {
    vcs.mu.Lock()
    defer vcs.mu.Unlock()
    
    // Check if tag already exists
    if _, err := vcs.storage.GetTag(name); err == nil {
        return fmt.Errorf("tag %s already exists", name)
    }
    
    // Verify target commit exists
    if _, err := vcs.storage.GetCommit(target); err != nil {
        return fmt.Errorf("target commit %s not found", target)
    }
    
    tag := &Tag{
        Name:      name,
        Target:    target,
        Tagger:    author,
        Message:   message,
        Timestamp: time.Now(),
    }
    
    if err := vcs.storage.StoreTag(tag); err != nil {
        return err
    }
    
    // Create reference
    ref := &Reference{
        Name:   fmt.Sprintf("refs/tags/%s", name),
        Target: target,
        Type:   RefTypeTag,
    }
    
    return vcs.storage.StoreReference(ref)
}

func (vcs *VersionControlService) DeleteTag(name string) error {
    vcs.mu.Lock()
    defer vcs.mu.Unlock()
    
    if err := vcs.storage.DeleteTag(name); err != nil {
        return err
    }
    
    refName := fmt.Sprintf("refs/tags/%s", name)
    return vcs.storage.DeleteReference(refName)
}

func (vcs *VersionControlService) ListTags() ([]*Tag, error) {
    return vcs.storage.ListTags()
}
```

This version control implementation provides comprehensive Git-like functionality with snapshotting, branching, merging, and history tracking, all optimized for the distributed filesystem architecture.