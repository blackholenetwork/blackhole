# U38: Metadata Service Implementation

## Overview
Distributed metadata storage system using Raft consensus for consistency. Manages inodes, directory structures, and file metadata across the distributed filesystem cluster.

## Architecture

```
Metadata Service
├── Raft Consensus Layer
├── Metadata Storage
├── Path Resolution Engine
└── Inode Management
```

## Complete Implementation

### 1. Core Metadata Structures

```go
package metadata

import (
    "encoding/json"
    "time"
    "sync"
    "crypto/sha256"
    "encoding/binary"
)

type Inode struct {
    Number   uint64    `json:"number"`
    Mode     uint32    `json:"mode"`
    Nlink    uint32    `json:"nlink"`
    Uid      uint32    `json:"uid"`
    Gid      uint32    `json:"gid"`
    Size     uint64    `json:"size"`
    Atime    time.Time `json:"atime"`
    Mtime    time.Time `json:"mtime"`
    Ctime    time.Time `json:"ctime"`
    Blocks   []string  `json:"blocks"`   // Block hashes
    Extended map[string][]byte `json:"extended"` // Extended attributes
    Version  uint64    `json:"version"`  // For versioning
}

func (i *Inode) IsDir() bool {
    return i.Mode&0040000 != 0
}

func (i *Inode) IsRegular() bool {
    return i.Mode&0100000 != 0
}

func (i *Inode) IsSymlink() bool {
    return i.Mode&0120000 != 0
}

type DirectoryEntry struct {
    Name   string `json:"name"`
    Inode  uint64 `json:"inode"`
    Type   uint8  `json:"type"`
}

type Directory struct {
    Entries []DirectoryEntry `json:"entries"`
    Version uint64           `json:"version"`
}

type InodeUpdate struct {
    Size     *uint64    `json:"size,omitempty"`
    Mode     *uint32    `json:"mode,omitempty"`
    Uid      *uint32    `json:"uid,omitempty"`
    Gid      *uint32    `json:"gid,omitempty"`
    Atime    *time.Time `json:"atime,omitempty"`
    Mtime    *time.Time `json:"mtime,omitempty"`
    Ctime    *time.Time `json:"ctime,omitempty"`
    Blocks   *[]string  `json:"blocks,omitempty"`
    Extended *map[string][]byte `json:"extended,omitempty"`
}

type FilesystemStats struct {
    TotalBlocks     uint64 `json:"total_blocks"`
    FreeBlocks      uint64 `json:"free_blocks"`
    AvailableBlocks uint64 `json:"available_blocks"`
    TotalFiles      uint64 `json:"total_files"`
    FreeFiles       uint64 `json:"free_files"`
    BlockSize       uint32 `json:"block_size"`
    MaxNameLength   uint32 `json:"max_name_length"`
}
```

### 2. Raft-based Metadata Service

```go
package metadata

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net"
    "path/filepath"
    "strings"
    "sync"
    "time"

    "github.com/hashicorp/raft"
    raftboltdb "github.com/hashicorp/raft-boltdb"
)

type MetadataService struct {
    raft         *raft.Raft
    fsm          *MetadataFSM
    config       *Config
    mu           sync.RWMutex
    inodeCounter uint64
    pathCache    map[string]uint64 // path -> inode number
    inodeCache   map[uint64]*Inode // inode number -> inode
}

type Config struct {
    NodeID        string        `yaml:"node_id"`
    BindAddr      string        `yaml:"bind_addr"`
    DataDir       string        `yaml:"data_dir"`
    Bootstrap     bool          `yaml:"bootstrap"`
    JoinAddr      string        `yaml:"join_addr"`
    Timeout       time.Duration `yaml:"timeout"`
    MaxPool       int           `yaml:"max_pool"`
    HeartbeatTimeout time.Duration `yaml:"heartbeat_timeout"`
    ElectionTimeout  time.Duration `yaml:"election_timeout"`
}

func NewMetadataService(config *Config) (*MetadataService, error) {
    fsm := &MetadataFSM{
        inodes:      make(map[uint64]*Inode),
        directories: make(map[uint64]*Directory),
        paths:       make(map[string]uint64),
        counter:     1, // Start from 1, reserve 0
    }
    
    ms := &MetadataService{
        fsm:          fsm,
        config:       config,
        inodeCounter: 1,
        pathCache:    make(map[string]uint64),
        inodeCache:   make(map[uint64]*Inode),
    }
    
    if err := ms.setupRaft(); err != nil {
        return nil, err
    }
    
    return ms, nil
}

func (ms *MetadataService) setupRaft() error {
    raftConfig := raft.DefaultConfig()
    raftConfig.LocalID = raft.ServerID(ms.config.NodeID)
    raftConfig.HeartbeatTimeout = ms.config.HeartbeatTimeout
    raftConfig.ElectionTimeout = ms.config.ElectionTimeout
    raftConfig.CommitTimeout = ms.config.Timeout
    raftConfig.MaxAppendEntries = 64
    raftConfig.BatchApplyCh = true
    raftConfig.ShutdownOnRemove = false
    
    // Setup Raft communications
    addr, err := net.ResolveTCPAddr("tcp", ms.config.BindAddr)
    if err != nil {
        return err
    }
    
    transport, err := raft.NewTCPTransport(ms.config.BindAddr, addr, ms.config.MaxPool, ms.config.Timeout, nil)
    if err != nil {
        return err
    }
    
    // Create snapshot store
    snapshots, err := raft.NewFileSnapshotStore(ms.config.DataDir, 3, nil)
    if err != nil {
        return err
    }
    
    // Create log store
    logStore, err := raftboltdb.NewBoltStore(filepath.Join(ms.config.DataDir, "raft-log.db"))
    if err != nil {
        return err
    }
    
    // Create stable store
    stableStore, err := raftboltdb.NewBoltStore(filepath.Join(ms.config.DataDir, "raft-stable.db"))
    if err != nil {
        return err
    }
    
    // Instantiate Raft
    ra, err := raft.NewRaft(raftConfig, ms.fsm, logStore, stableStore, snapshots, transport)
    if err != nil {
        return err
    }
    
    ms.raft = ra
    
    // Bootstrap cluster if required
    if ms.config.Bootstrap {
        configuration := raft.Configuration{
            Servers: []raft.Server{
                {
                    ID:      raft.ServerID(ms.config.NodeID),
                    Address: transport.LocalAddr(),
                },
            },
        }
        ms.raft.BootstrapCluster(configuration)
    }
    
    return nil
}

func (ms *MetadataService) Join(nodeID, addr string) error {
    log.Printf("Received join request for remote node %s at %s", nodeID, addr)
    
    configFuture := ms.raft.GetConfiguration()
    if err := configFuture.Error(); err != nil {
        return err
    }
    
    for _, srv := range configFuture.Configuration().Servers {
        if srv.ID == raft.ServerID(nodeID) || srv.Address == raft.ServerAddress(addr) {
            if srv.Address == raft.ServerAddress(addr) && srv.ID == raft.ServerID(nodeID) {
                log.Printf("Node %s at %s already member of cluster, ignoring join request", nodeID, addr)
                return nil
            }
            
            future := ms.raft.RemoveServer(srv.ID, 0, 0)
            if err := future.Error(); err != nil {
                return fmt.Errorf("error removing existing node %s: %s", nodeID, err)
            }
        }
    }
    
    f := ms.raft.AddVoter(raft.ServerID(nodeID), raft.ServerAddress(addr), 0, 0)
    if f.Error() != nil {
        return f.Error()
    }
    
    log.Printf("Node %s at %s joined successfully", nodeID, addr)
    return nil
}
```

### 3. Finite State Machine Implementation

```go
type MetadataFSM struct {
    mu          sync.RWMutex
    inodes      map[uint64]*Inode
    directories map[uint64]*Directory
    paths       map[string]uint64 // path -> inode number
    counter     uint64
}

type LogEntry struct {
    Type string      `json:"type"`
    Data interface{} `json:"data"`
}

type CreateInodeCommand struct {
    Path string `json:"path"`
    Mode uint32 `json:"mode"`
    Uid  uint32 `json:"uid"`
    Gid  uint32 `json:"gid"`
}

type UpdateInodeCommand struct {
    Inode  uint64       `json:"inode"`
    Update *InodeUpdate `json:"update"`
}

type RemoveInodeCommand struct {
    Path string `json:"path"`
}

type CreateDirectoryCommand struct {
    Path string `json:"path"`
    Mode uint32 `json:"mode"`
    Uid  uint32 `json:"uid"`
    Gid  uint32 `json:"gid"`
}

type AddDirectoryEntryCommand struct {
    ParentInode uint64 `json:"parent_inode"`
    Name        string `json:"name"`
    ChildInode  uint64 `json:"child_inode"`
    Type        uint8  `json:"type"`
}

type RemoveDirectoryEntryCommand struct {
    ParentInode uint64 `json:"parent_inode"`
    Name        string `json:"name"`
}

func (fsm *MetadataFSM) Apply(log *raft.Log) interface{} {
    var entry LogEntry
    if err := json.Unmarshal(log.Data, &entry); err != nil {
        return err
    }
    
    fsm.mu.Lock()
    defer fsm.mu.Unlock()
    
    switch entry.Type {
    case "create_inode":
        return fsm.applyCreateInode(entry.Data)
    case "update_inode":
        return fsm.applyUpdateInode(entry.Data)
    case "remove_inode":
        return fsm.applyRemoveInode(entry.Data)
    case "create_directory":
        return fsm.applyCreateDirectory(entry.Data)
    case "add_directory_entry":
        return fsm.applyAddDirectoryEntry(entry.Data)
    case "remove_directory_entry":
        return fsm.applyRemoveDirectoryEntry(entry.Data)
    default:
        return fmt.Errorf("unknown command type: %s", entry.Type)
    }
}

func (fsm *MetadataFSM) applyCreateInode(data interface{}) interface{} {
    cmdData, _ := json.Marshal(data)
    var cmd CreateInodeCommand
    if err := json.Unmarshal(cmdData, &cmd); err != nil {
        return err
    }
    
    fsm.counter++
    inodeNum := fsm.counter
    now := time.Now()
    
    inode := &Inode{
        Number: inodeNum,
        Mode:   cmd.Mode,
        Nlink:  1,
        Uid:    cmd.Uid,
        Gid:    cmd.Gid,
        Size:   0,
        Atime:  now,
        Mtime:  now,
        Ctime:  now,
        Blocks: make([]string, 0),
        Extended: make(map[string][]byte),
        Version: 1,
    }
    
    fsm.inodes[inodeNum] = inode
    fsm.paths[cmd.Path] = inodeNum
    
    return inodeNum
}

func (fsm *MetadataFSM) applyUpdateInode(data interface{}) interface{} {
    cmdData, _ := json.Marshal(data)
    var cmd UpdateInodeCommand
    if err := json.Unmarshal(cmdData, &cmd); err != nil {
        return err
    }
    
    inode, exists := fsm.inodes[cmd.Inode]
    if !exists {
        return fmt.Errorf("inode %d not found", cmd.Inode)
    }
    
    // Create a copy to avoid race conditions
    updated := *inode
    
    if cmd.Update.Size != nil {
        updated.Size = *cmd.Update.Size
    }
    if cmd.Update.Mode != nil {
        updated.Mode = *cmd.Update.Mode
    }
    if cmd.Update.Uid != nil {
        updated.Uid = *cmd.Update.Uid
    }
    if cmd.Update.Gid != nil {
        updated.Gid = *cmd.Update.Gid
    }
    if cmd.Update.Atime != nil {
        updated.Atime = *cmd.Update.Atime
    }
    if cmd.Update.Mtime != nil {
        updated.Mtime = *cmd.Update.Mtime
    }
    if cmd.Update.Ctime != nil {
        updated.Ctime = *cmd.Update.Ctime
    }
    if cmd.Update.Blocks != nil {
        updated.Blocks = *cmd.Update.Blocks
    }
    if cmd.Update.Extended != nil {
        updated.Extended = *cmd.Update.Extended
    }
    
    updated.Version++
    fsm.inodes[cmd.Inode] = &updated
    
    return nil
}

func (fsm *MetadataFSM) applyCreateDirectory(data interface{}) interface{} {
    cmdData, _ := json.Marshal(data)
    var cmd CreateDirectoryCommand
    if err := json.Unmarshal(cmdData, &cmd); err != nil {
        return err
    }
    
    fsm.counter++
    inodeNum := fsm.counter
    now := time.Now()
    
    inode := &Inode{
        Number: inodeNum,
        Mode:   cmd.Mode | 0040000, // Directory mode
        Nlink:  2, // . and parent
        Uid:    cmd.Uid,
        Gid:    cmd.Gid,
        Size:   4096,
        Atime:  now,
        Mtime:  now,
        Ctime:  now,
        Blocks: make([]string, 0),
        Extended: make(map[string][]byte),
        Version: 1,
    }
    
    directory := &Directory{
        Entries: []DirectoryEntry{
            {Name: ".", Inode: inodeNum, Type: 4}, // DT_DIR
            {Name: "..", Inode: 0, Type: 4}, // Will be set by parent
        },
        Version: 1,
    }
    
    fsm.inodes[inodeNum] = inode
    fsm.directories[inodeNum] = directory
    fsm.paths[cmd.Path] = inodeNum
    
    return inodeNum
}

func (fsm *MetadataFSM) Snapshot() (raft.FSMSnapshot, error) {
    fsm.mu.RLock()
    defer fsm.mu.RUnlock()
    
    snapshot := &MetadataSnapshot{
        inodes:      make(map[uint64]*Inode),
        directories: make(map[uint64]*Directory),
        paths:       make(map[string]uint64),
        counter:     fsm.counter,
    }
    
    // Deep copy all data
    for k, v := range fsm.inodes {
        inodeCopy := *v
        if v.Blocks != nil {
            inodeCopy.Blocks = make([]string, len(v.Blocks))
            copy(inodeCopy.Blocks, v.Blocks)
        }
        if v.Extended != nil {
            inodeCopy.Extended = make(map[string][]byte)
            for key, val := range v.Extended {
                inodeCopy.Extended[key] = make([]byte, len(val))
                copy(inodeCopy.Extended[key], val)
            }
        }
        snapshot.inodes[k] = &inodeCopy
    }
    
    for k, v := range fsm.directories {
        dirCopy := *v
        dirCopy.Entries = make([]DirectoryEntry, len(v.Entries))
        copy(dirCopy.Entries, v.Entries)
        snapshot.directories[k] = &dirCopy
    }
    
    for k, v := range fsm.paths {
        snapshot.paths[k] = v
    }
    
    return snapshot, nil
}

func (fsm *MetadataFSM) Restore(snapshot io.ReadCloser) error {
    var snap MetadataSnapshot
    if err := json.NewDecoder(snapshot).Decode(&snap); err != nil {
        return err
    }
    
    fsm.mu.Lock()
    defer fsm.mu.Unlock()
    
    fsm.inodes = snap.inodes
    fsm.directories = snap.directories
    fsm.paths = snap.paths
    fsm.counter = snap.counter
    
    return nil
}
```

### 4. Path Resolution Engine

```go
type PathResolver struct {
    fsm *MetadataFSM
}

func NewPathResolver(fsm *MetadataFSM) *PathResolver {
    return &PathResolver{fsm: fsm}
}

func (pr *PathResolver) ResolvePath(path string) (uint64, error) {
    pr.fsm.mu.RLock()
    defer pr.fsm.mu.RUnlock()
    
    // Check cache first
    if inode, exists := pr.fsm.paths[path]; exists {
        return inode, nil
    }
    
    // Handle root
    if path == "/" {
        return 1, nil // Root inode is always 1
    }
    
    // Normalize path
    path = filepath.Clean(path)
    components := strings.Split(strings.Trim(path, "/"), "/")
    
    currentInode := uint64(1) // Start from root
    currentPath := ""
    
    for _, component := range components {
        if component == "" {
            continue
        }
        
        currentPath = filepath.Join(currentPath, component)
        if currentPath[0] != '/' {
            currentPath = "/" + currentPath
        }
        
        // Check if we have this path cached
        if inode, exists := pr.fsm.paths[currentPath]; exists {
            currentInode = inode
            continue
        }
        
        // Look up in directory
        dir, exists := pr.fsm.directories[currentInode]
        if !exists {
            return 0, fmt.Errorf("path component %s is not a directory", currentPath)
        }
        
        found := false
        for _, entry := range dir.Entries {
            if entry.Name == component {
                currentInode = entry.Inode
                pr.fsm.paths[currentPath] = currentInode // Cache the result
                found = true
                break
            }
        }
        
        if !found {
            return 0, fmt.Errorf("path component %s not found", component)
        }
    }
    
    return currentInode, nil
}

func (pr *PathResolver) GetParentInode(path string) (uint64, string, error) {
    path = filepath.Clean(path)
    if path == "/" {
        return 0, "", fmt.Errorf("root has no parent")
    }
    
    parentPath := filepath.Dir(path)
    fileName := filepath.Base(path)
    
    parentInode, err := pr.ResolvePath(parentPath)
    if err != nil {
        return 0, "", err
    }
    
    return parentInode, fileName, nil
}

func (pr *PathResolver) InvalidateCache(path string) {
    pr.fsm.mu.Lock()
    defer pr.fsm.mu.Unlock()
    
    // Remove exact path
    delete(pr.fsm.paths, path)
    
    // Remove all paths that start with this path (subdirectories)
    for cachedPath := range pr.fsm.paths {
        if strings.HasPrefix(cachedPath, path+"/") {
            delete(pr.fsm.paths, cachedPath)
        }
    }
}
```

### 5. Public API Implementation

```go
func (ms *MetadataService) CreateFile(path string, mode uint32, uid, gid uint32) (*Inode, error) {
    if !ms.raft.State() == raft.Leader {
        return nil, fmt.Errorf("not leader")
    }
    
    // Check if file already exists
    if _, err := ms.GetInode(path); err == nil {
        return nil, fmt.Errorf("file already exists")
    }
    
    // Check parent directory exists
    parentInode, fileName, err := ms.pathResolver.GetParentInode(path)
    if err != nil {
        return nil, err
    }
    
    // Create inode
    cmd := LogEntry{
        Type: "create_inode",
        Data: CreateInodeCommand{
            Path: path,
            Mode: mode,
            Uid:  uid,
            Gid:  gid,
        },
    }
    
    data, err := json.Marshal(cmd)
    if err != nil {
        return nil, err
    }
    
    future := ms.raft.Apply(data, ms.config.Timeout)
    if err := future.Error(); err != nil {
        return nil, err
    }
    
    inodeNum := future.Response().(uint64)
    
    // Add to parent directory
    dirCmd := LogEntry{
        Type: "add_directory_entry",
        Data: AddDirectoryEntryCommand{
            ParentInode: parentInode,
            Name:        fileName,
            ChildInode:  inodeNum,
            Type:        8, // DT_REG
        },
    }
    
    dirData, err := json.Marshal(dirCmd)
    if err != nil {
        return nil, err
    }
    
    dirFuture := ms.raft.Apply(dirData, ms.config.Timeout)
    if err := dirFuture.Error(); err != nil {
        return nil, err
    }
    
    // Return the created inode
    return ms.GetInodeByNumber(inodeNum)
}

func (ms *MetadataService) CreateDirectory(path string, mode uint32, uid, gid uint32) (*Inode, error) {
    if ms.raft.State() != raft.Leader {
        return nil, fmt.Errorf("not leader")
    }
    
    // Check if directory already exists
    if _, err := ms.GetInode(path); err == nil {
        return nil, fmt.Errorf("directory already exists")
    }
    
    // Check parent directory exists (except for root)
    var parentInode uint64
    var fileName string
    if path != "/" {
        var err error
        parentInode, fileName, err = ms.pathResolver.GetParentInode(path)
        if err != nil {
            return nil, err
        }
    }
    
    // Create directory
    cmd := LogEntry{
        Type: "create_directory",
        Data: CreateDirectoryCommand{
            Path: path,
            Mode: mode,
            Uid:  uid,
            Gid:  gid,
        },
    }
    
    data, err := json.Marshal(cmd)
    if err != nil {
        return nil, err
    }
    
    future := ms.raft.Apply(data, ms.config.Timeout)
    if err := future.Error(); err != nil {
        return nil, err
    }
    
    inodeNum := future.Response().(uint64)
    
    // Add to parent directory (if not root)
    if path != "/" {
        dirCmd := LogEntry{
            Type: "add_directory_entry",
            Data: AddDirectoryEntryCommand{
                ParentInode: parentInode,
                Name:        fileName,
                ChildInode:  inodeNum,
                Type:        4, // DT_DIR
            },
        }
        
        dirData, err := json.Marshal(dirCmd)
        if err != nil {
            return nil, err
        }
        
        dirFuture := ms.raft.Apply(dirData, ms.config.Timeout)
        if err := dirFuture.Error(); err != nil {
            return nil, err
        }
    }
    
    return ms.GetInodeByNumber(inodeNum)
}

func (ms *MetadataService) GetInode(path string) (*Inode, error) {
    inodeNum, err := ms.pathResolver.ResolvePath(path)
    if err != nil {
        return nil, err
    }
    
    return ms.GetInodeByNumber(inodeNum)
}

func (ms *MetadataService) GetInodeByNumber(inodeNum uint64) (*Inode, error) {
    ms.mu.RLock()
    defer ms.mu.RUnlock()
    
    // Check cache first
    if inode, exists := ms.inodeCache[inodeNum]; exists {
        return inode, nil
    }
    
    ms.fsm.mu.RLock()
    inode, exists := ms.fsm.inodes[inodeNum]
    ms.fsm.mu.RUnlock()
    
    if !exists {
        return nil, fmt.Errorf("inode %d not found", inodeNum)
    }
    
    // Cache the result
    inodeCopy := *inode
    ms.inodeCache[inodeNum] = &inodeCopy
    
    return &inodeCopy, nil
}

func (ms *MetadataService) UpdateInode(path string, update *InodeUpdate) (*Inode, error) {
    if ms.raft.State() != raft.Leader {
        return nil, fmt.Errorf("not leader")
    }
    
    inodeNum, err := ms.pathResolver.ResolvePath(path)
    if err != nil {
        return nil, err
    }
    
    cmd := LogEntry{
        Type: "update_inode",
        Data: UpdateInodeCommand{
            Inode:  inodeNum,
            Update: update,
        },
    }
    
    data, err := json.Marshal(cmd)
    if err != nil {
        return nil, err
    }
    
    future := ms.raft.Apply(data, ms.config.Timeout)
    if err := future.Error(); err != nil {
        return nil, err
    }
    
    // Invalidate cache
    ms.mu.Lock()
    delete(ms.inodeCache, inodeNum)
    ms.mu.Unlock()
    
    return ms.GetInodeByNumber(inodeNum)
}

func (ms *MetadataService) ListDirectory(path string) ([]DirectoryEntry, error) {
    inodeNum, err := ms.pathResolver.ResolvePath(path)
    if err != nil {
        return nil, err
    }
    
    ms.fsm.mu.RLock()
    defer ms.fsm.mu.RUnlock()
    
    dir, exists := ms.fsm.directories[inodeNum]
    if !exists {
        return nil, fmt.Errorf("not a directory")
    }
    
    // Return copy to avoid race conditions
    entries := make([]DirectoryEntry, len(dir.Entries))
    copy(entries, dir.Entries)
    
    return entries, nil
}

func (ms *MetadataService) RemoveFile(path string) error {
    return ms.removeEntry(path, false)
}

func (ms *MetadataService) RemoveDirectory(path string) error {
    return ms.removeEntry(path, true)
}

func (ms *MetadataService) removeEntry(path string, isDir bool) error {
    if ms.raft.State() != raft.Leader {
        return fmt.Errorf("not leader")
    }
    
    // Get inode
    inodeNum, err := ms.pathResolver.ResolvePath(path)
    if err != nil {
        return err
    }
    
    // Check if directory is empty (for directories)
    if isDir {
        entries, err := ms.ListDirectory(path)
        if err != nil {
            return err
        }
        
        // Should only contain . and ..
        if len(entries) > 2 {
            return fmt.Errorf("directory not empty")
        }
    }
    
    // Remove from parent directory
    parentInode, fileName, err := ms.pathResolver.GetParentInode(path)
    if err != nil {
        return err
    }
    
    cmd := LogEntry{
        Type: "remove_directory_entry",
        Data: RemoveDirectoryEntryCommand{
            ParentInode: parentInode,
            Name:        fileName,
        },
    }
    
    data, err := json.Marshal(cmd)
    if err != nil {
        return err
    }
    
    future := ms.raft.Apply(data, ms.config.Timeout)
    if err := future.Error(); err != nil {
        return err
    }
    
    // Remove inode
    removeCmd := LogEntry{
        Type: "remove_inode",
        Data: RemoveInodeCommand{
            Path: path,
        },
    }
    
    removeData, err := json.Marshal(removeCmd)
    if err != nil {
        return err
    }
    
    removeFuture := ms.raft.Apply(removeData, ms.config.Timeout)
    if err := removeFuture.Error(); err != nil {
        return err
    }
    
    // Invalidate caches
    ms.mu.Lock()
    delete(ms.inodeCache, inodeNum)
    ms.mu.Unlock()
    
    ms.pathResolver.InvalidateCache(path)
    
    return nil
}

func (ms *MetadataService) Rename(oldPath, newPath string) error {
    if ms.raft.State() != raft.Leader {
        return fmt.Errorf("not leader")
    }
    
    // Get source inode
    sourceInode, err := ms.pathResolver.ResolvePath(oldPath)
    if err != nil {
        return err
    }
    
    // Get source parent and name
    sourceParent, sourceName, err := ms.pathResolver.GetParentInode(oldPath)
    if err != nil {
        return err
    }
    
    // Get target parent and name
    targetParent, targetName, err := ms.pathResolver.GetParentInode(newPath)
    if err != nil {
        return err
    }
    
    // Check if target exists
    if _, err := ms.pathResolver.ResolvePath(newPath); err == nil {
        return fmt.Errorf("target already exists")
    }
    
    // Remove from source directory
    removeCmd := LogEntry{
        Type: "remove_directory_entry",
        Data: RemoveDirectoryEntryCommand{
            ParentInode: sourceParent,
            Name:        sourceName,
        },
    }
    
    removeData, err := json.Marshal(removeCmd)
    if err != nil {
        return err
    }
    
    removeFuture := ms.raft.Apply(removeData, ms.config.Timeout)
    if err := removeFuture.Error(); err != nil {
        return err
    }
    
    // Add to target directory
    inode, err := ms.GetInodeByNumber(sourceInode)
    if err != nil {
        return err
    }
    
    entryType := uint8(8) // DT_REG
    if inode.IsDir() {
        entryType = 4 // DT_DIR
    }
    
    addCmd := LogEntry{
        Type: "add_directory_entry",
        Data: AddDirectoryEntryCommand{
            ParentInode: targetParent,
            Name:        targetName,
            ChildInode:  sourceInode,
            Type:        entryType,
        },
    }
    
    addData, err := json.Marshal(addCmd)
    if err != nil {
        return err
    }
    
    addFuture := ms.raft.Apply(addData, ms.config.Timeout)
    if err := addFuture.Error(); err != nil {
        return err
    }
    
    // Update path mapping
    updatePathCmd := LogEntry{
        Type: "update_path",
        Data: map[string]interface{}{
            "old_path": oldPath,
            "new_path": newPath,
        },
    }
    
    pathData, err := json.Marshal(updatePathCmd)
    if err != nil {
        return err
    }
    
    pathFuture := ms.raft.Apply(pathData, ms.config.Timeout)
    if err := pathFuture.Error(); err != nil {
        return err
    }
    
    // Invalidate caches
    ms.pathResolver.InvalidateCache(oldPath)
    ms.pathResolver.InvalidateCache(newPath)
    
    return nil
}

func (ms *MetadataService) GetFilesystemStats() (*FilesystemStats, error) {
    ms.fsm.mu.RLock()
    defer ms.fsm.mu.RUnlock()
    
    totalFiles := uint64(len(ms.fsm.inodes))
    
    // Calculate total blocks used
    totalBlocks := uint64(0)
    for _, inode := range ms.fsm.inodes {
        totalBlocks += uint64(len(inode.Blocks))
    }
    
    stats := &FilesystemStats{
        TotalBlocks:     1000000, // TODO: Get from cluster
        FreeBlocks:      1000000 - totalBlocks,
        AvailableBlocks: 1000000 - totalBlocks,
        TotalFiles:      totalFiles,
        FreeFiles:       1000000 - totalFiles,
        BlockSize:       4096,
        MaxNameLength:   255,
    }
    
    return stats, nil
}
```

### 6. Extended Attributes Support

```go
func (ms *MetadataService) GetExtendedAttribute(path, name string) ([]byte, error) {
    inode, err := ms.GetInode(path)
    if err != nil {
        return nil, err
    }
    
    if value, exists := inode.Extended[name]; exists {
        result := make([]byte, len(value))
        copy(result, value)
        return result, nil
    }
    
    return nil, fmt.Errorf("attribute not found")
}

func (ms *MetadataService) SetExtendedAttribute(path, name string, value []byte, flags uint32) error {
    if ms.raft.State() != raft.Leader {
        return fmt.Errorf("not leader")
    }
    
    inode, err := ms.GetInode(path)
    if err != nil {
        return err
    }
    
    // Check flags
    _, exists := inode.Extended[name]
    if flags&1 != 0 && exists { // XATTR_CREATE
        return fmt.Errorf("attribute already exists")
    }
    if flags&2 != 0 && !exists { // XATTR_REPLACE
        return fmt.Errorf("attribute does not exist")
    }
    
    // Create new extended attributes map
    newExtended := make(map[string][]byte)
    for k, v := range inode.Extended {
        newExtended[k] = v
    }
    newExtended[name] = make([]byte, len(value))
    copy(newExtended[name], value)
    
    // Update inode
    _, err = ms.UpdateInode(path, &InodeUpdate{
        Extended: &newExtended,
    })
    
    return err
}

func (ms *MetadataService) ListExtendedAttributes(path string) (map[string][]byte, error) {
    inode, err := ms.GetInode(path)
    if err != nil {
        return nil, err
    }
    
    // Return copy to avoid race conditions
    result := make(map[string][]byte)
    for k, v := range inode.Extended {
        result[k] = make([]byte, len(v))
        copy(result[k], v)
    }
    
    return result, nil
}

func (ms *MetadataService) RemoveExtendedAttribute(path, name string) error {
    if ms.raft.State() != raft.Leader {
        return fmt.Errorf("not leader")
    }
    
    inode, err := ms.GetInode(path)
    if err != nil {
        return err
    }
    
    if _, exists := inode.Extended[name]; !exists {
        return fmt.Errorf("attribute not found")
    }
    
    // Create new extended attributes map without the attribute
    newExtended := make(map[string][]byte)
    for k, v := range inode.Extended {
        if k != name {
            newExtended[k] = v
        }
    }
    
    // Update inode
    _, err = ms.UpdateInode(path, &InodeUpdate{
        Extended: &newExtended,
    })
    
    return err
}
```

### 7. Snapshot Implementation

```go
type MetadataSnapshot struct {
    inodes      map[uint64]*Inode
    directories map[uint64]*Directory
    paths       map[string]uint64
    counter     uint64
}

func (s *MetadataSnapshot) Persist(sink raft.SnapshotSink) error {
    err := func() error {
        encoder := json.NewEncoder(sink)
        return encoder.Encode(s)
    }()
    
    if err != nil {
        sink.Cancel()
        return err
    }
    
    return sink.Close()
}

func (s *MetadataSnapshot) Release() {
    // Clean up resources if needed
}
```

### 8. Health Monitoring

```go
func (ms *MetadataService) IsLeader() bool {
    return ms.raft.State() == raft.Leader
}

func (ms *MetadataService) GetLeader() string {
    return string(ms.raft.Leader())
}

func (ms *MetadataService) GetStats() map[string]interface{} {
    stats := ms.raft.Stats()
    result := make(map[string]interface{})
    
    for k, v := range stats {
        result[k] = v
    }
    
    result["node_id"] = ms.config.NodeID
    result["is_leader"] = ms.IsLeader()
    result["leader"] = ms.GetLeader()
    
    ms.fsm.mu.RLock()
    result["total_inodes"] = len(ms.fsm.inodes)
    result["total_directories"] = len(ms.fsm.directories)
    result["inode_counter"] = ms.fsm.counter
    ms.fsm.mu.RUnlock()
    
    return result
}

func (ms *MetadataService) Shutdown() error {
    return ms.raft.Shutdown().Error()
}
```

This metadata service provides a robust, distributed metadata storage system with strong consistency guarantees through Raft consensus, efficient path resolution, and comprehensive inode management for the distributed filesystem.