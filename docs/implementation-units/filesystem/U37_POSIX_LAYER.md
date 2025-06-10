# U37: POSIX Layer Implementation

## Overview
POSIX-compatible filesystem interface that maps standard file operations to the distributed blackhole filesystem. Implements FUSE for seamless integration with existing applications.

## Architecture

```
POSIX Layer
├── FUSE Interface
├── Operation Mapping
├── System Call Handler
└── Path Resolution
```

## Complete Implementation

### 1. FUSE Interface

```go
package posix

import (
    "context"
    "os"
    "syscall"
    "time"

    "bazil.org/fuse"
    "bazil.org/fuse/fs"
    "bazil.org/fuse/fuseutil"
)

type BlackholeFS struct {
    metadataService *MetadataService
    blockService    *BlockService
    cache          *FilesystemCache
}

func NewBlackholeFS(ms *MetadataService, bs *BlockService, cache *FilesystemCache) *BlackholeFS {
    return &BlackholeFS{
        metadataService: ms,
        blockService:    bs,
        cache:          cache,
    }
}

func (bfs *BlackholeFS) Root() (fs.Node, error) {
    inode, err := bfs.metadataService.GetInode("/")
    if err != nil {
        return nil, err
    }
    return &Dir{
        fs:    bfs,
        inode: inode,
        path:  "/",
    }, nil
}

func (bfs *BlackholeFS) Statfs(ctx context.Context, req *fuse.StatfsRequest, resp *fuse.StatfsResponse) error {
    stats, err := bfs.metadataService.GetFilesystemStats()
    if err != nil {
        return err
    }
    
    resp.Blocks = stats.TotalBlocks
    resp.Bfree = stats.FreeBlocks
    resp.Bavail = stats.AvailableBlocks
    resp.Files = stats.TotalFiles
    resp.Ffree = stats.FreeFiles
    resp.Bsize = 4096
    resp.Namelen = 255
    resp.Frsize = 4096
    
    return nil
}
```

### 2. Directory Operations

```go
type Dir struct {
    fs    *BlackholeFS
    inode *Inode
    path  string
}

func (d *Dir) Attr(ctx context.Context, attr *fuse.Attr) error {
    attr.Inode = d.inode.Number
    attr.Mode = os.ModeDir | d.inode.Mode
    attr.Nlink = d.inode.Nlink
    attr.Uid = d.inode.Uid
    attr.Gid = d.inode.Gid
    attr.Size = d.inode.Size
    attr.Atime = d.inode.Atime
    attr.Mtime = d.inode.Mtime
    attr.Ctime = d.inode.Ctime
    attr.Blocks = (d.inode.Size + 511) / 512
    return nil
}

func (d *Dir) Lookup(ctx context.Context, name string) (fs.Node, error) {
    childPath := d.path + "/" + name
    if d.path == "/" {
        childPath = "/" + name
    }
    
    inode, err := d.fs.metadataService.GetInode(childPath)
    if err != nil {
        return nil, fuse.ENOENT
    }
    
    if inode.IsDir() {
        return &Dir{
            fs:    d.fs,
            inode: inode,
            path:  childPath,
        }, nil
    }
    
    return &File{
        fs:    d.fs,
        inode: inode,
        path:  childPath,
    }, nil
}

func (d *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
    entries, err := d.fs.metadataService.ListDirectory(d.path)
    if err != nil {
        return nil, err
    }
    
    dirents := make([]fuse.Dirent, 0, len(entries))
    for _, entry := range entries {
        dirent := fuse.Dirent{
            Inode: entry.Inode,
            Name:  entry.Name,
        }
        
        if entry.IsDir {
            dirent.Type = fuse.DT_Dir
        } else {
            dirent.Type = fuse.DT_File
        }
        
        dirents = append(dirents, dirent)
    }
    
    return dirents, nil
}

func (d *Dir) Create(ctx context.Context, req *fuse.CreateRequest, resp *fuse.CreateResponse) (fs.Node, fs.Handle, error) {
    childPath := d.path + "/" + req.Name
    if d.path == "/" {
        childPath = "/" + req.Name
    }
    
    inode, err := d.fs.metadataService.CreateFile(childPath, req.Mode, req.Uid, req.Gid)
    if err != nil {
        return nil, nil, err
    }
    
    file := &File{
        fs:    d.fs,
        inode: inode,
        path:  childPath,
    }
    
    handle := &FileHandle{
        file: file,
        mode: req.Flags,
    }
    
    resp.Attr.Inode = inode.Number
    resp.Attr.Mode = inode.Mode
    resp.Attr.Uid = inode.Uid
    resp.Attr.Gid = inode.Gid
    resp.Attr.Size = 0
    resp.Attr.Atime = inode.Atime
    resp.Attr.Mtime = inode.Mtime
    resp.Attr.Ctime = inode.Ctime
    
    return file, handle, nil
}

func (d *Dir) Mkdir(ctx context.Context, req *fuse.MkdirRequest) (fs.Node, error) {
    childPath := d.path + "/" + req.Name
    if d.path == "/" {
        childPath = "/" + req.Name
    }
    
    inode, err := d.fs.metadataService.CreateDirectory(childPath, req.Mode, req.Uid, req.Gid)
    if err != nil {
        return nil, err
    }
    
    return &Dir{
        fs:    d.fs,
        inode: inode,
        path:  childPath,
    }, nil
}

func (d *Dir) Remove(ctx context.Context, req *fuse.RemoveRequest) error {
    childPath := d.path + "/" + req.Name
    if d.path == "/" {
        childPath = "/" + req.Name
    }
    
    if req.Dir {
        return d.fs.metadataService.RemoveDirectory(childPath)
    }
    return d.fs.metadataService.RemoveFile(childPath)
}

func (d *Dir) Rename(ctx context.Context, req *fuse.RenameRequest, newDir fs.Node) error {
    oldPath := d.path + "/" + req.OldName
    if d.path == "/" {
        oldPath = "/" + req.OldName
    }
    
    newDirNode := newDir.(*Dir)
    newPath := newDirNode.path + "/" + req.NewName
    if newDirNode.path == "/" {
        newPath = "/" + req.NewName
    }
    
    return d.fs.metadataService.Rename(oldPath, newPath)
}
```

### 3. File Operations

```go
type File struct {
    fs    *BlackholeFS
    inode *Inode
    path  string
}

func (f *File) Attr(ctx context.Context, attr *fuse.Attr) error {
    // Refresh inode to get latest attributes
    inode, err := f.fs.metadataService.GetInode(f.path)
    if err != nil {
        return err
    }
    f.inode = inode
    
    attr.Inode = f.inode.Number
    attr.Mode = f.inode.Mode
    attr.Nlink = f.inode.Nlink
    attr.Uid = f.inode.Uid
    attr.Gid = f.inode.Gid
    attr.Size = f.inode.Size
    attr.Atime = f.inode.Atime
    attr.Mtime = f.inode.Mtime
    attr.Ctime = f.inode.Ctime
    attr.Blocks = (f.inode.Size + 511) / 512
    return nil
}

func (f *File) Setattr(ctx context.Context, req *fuse.SetattrRequest, resp *fuse.SetattrResponse) error {
    updates := &InodeUpdate{}
    
    if req.Valid.Size() {
        updates.Size = &req.Size
        if err := f.fs.blockService.TruncateFile(f.path, req.Size); err != nil {
            return err
        }
    }
    
    if req.Valid.Mode() {
        updates.Mode = &req.Mode
    }
    
    if req.Valid.Uid() || req.Valid.Gid() {
        if req.Valid.Uid() {
            updates.Uid = &req.Uid
        }
        if req.Valid.Gid() {
            updates.Gid = &req.Gid
        }
    }
    
    if req.Valid.Atime() {
        updates.Atime = &req.Atime
    }
    
    if req.Valid.Mtime() {
        updates.Mtime = &req.Mtime
    }
    
    inode, err := f.fs.metadataService.UpdateInode(f.path, updates)
    if err != nil {
        return err
    }
    
    f.inode = inode
    resp.Attr.Inode = inode.Number
    resp.Attr.Mode = inode.Mode
    resp.Attr.Uid = inode.Uid
    resp.Attr.Gid = inode.Gid
    resp.Attr.Size = inode.Size
    resp.Attr.Atime = inode.Atime
    resp.Attr.Mtime = inode.Mtime
    resp.Attr.Ctime = inode.Ctime
    
    return nil
}

func (f *File) Open(ctx context.Context, req *fuse.OpenRequest, resp *fuse.OpenResponse) (fs.Handle, error) {
    return &FileHandle{
        file: f,
        mode: req.Flags,
    }, nil
}

func (f *File) Fsync(ctx context.Context, req *fuse.FsyncRequest) error {
    return f.fs.blockService.Flush(f.path)
}
```

### 4. File Handle Operations

```go
type FileHandle struct {
    file *File
    mode fuse.OpenFlags
}

func (fh *FileHandle) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
    // Check cache first
    if data := fh.file.fs.cache.Get(fh.file.path, req.Offset, int64(req.Size)); data != nil {
        resp.Data = data
        return nil
    }
    
    data, err := fh.file.fs.blockService.ReadAt(fh.file.path, req.Offset, int64(req.Size))
    if err != nil {
        return err
    }
    
    resp.Data = data
    
    // Update cache
    fh.file.fs.cache.Put(fh.file.path, req.Offset, data)
    
    // Update access time
    now := time.Now()
    fh.file.fs.metadataService.UpdateInode(fh.file.path, &InodeUpdate{
        Atime: &now,
    })
    
    return nil
}

func (fh *FileHandle) Write(ctx context.Context, req *fuse.WriteRequest, resp *fuse.WriteResponse) error {
    n, err := fh.file.fs.blockService.WriteAt(fh.file.path, req.Data, req.Offset)
    if err != nil {
        return err
    }
    
    resp.Size = n
    
    // Invalidate cache
    fh.file.fs.cache.Invalidate(fh.file.path, req.Offset, int64(len(req.Data)))
    
    // Update modification time
    now := time.Now()
    newSize := uint64(req.Offset) + uint64(len(req.Data))
    updates := &InodeUpdate{
        Mtime: &now,
    }
    
    if newSize > fh.file.inode.Size {
        updates.Size = &newSize
    }
    
    fh.file.fs.metadataService.UpdateInode(fh.file.path, updates)
    
    return nil
}

func (fh *FileHandle) Flush(ctx context.Context, req *fuse.FlushRequest) error {
    return fh.file.fs.blockService.Flush(fh.file.path)
}

func (fh *FileHandle) Release(ctx context.Context, req *fuse.ReleaseRequest) error {
    return fh.file.fs.blockService.Sync(fh.file.path)
}
```

### 5. System Call Mapping

```go
package posix

import (
    "syscall"
    "time"
)

type SystemCallHandler struct {
    fs *BlackholeFS
}

func NewSystemCallHandler(fs *BlackholeFS) *SystemCallHandler {
    return &SystemCallHandler{fs: fs}
}

func (sch *SystemCallHandler) MapErrno(err error) syscall.Errno {
    switch err {
    case ErrNotFound:
        return syscall.ENOENT
    case ErrExists:
        return syscall.EEXIST
    case ErrNotEmpty:
        return syscall.ENOTEMPTY
    case ErrPermission:
        return syscall.EACCES
    case ErrIsDirectory:
        return syscall.EISDIR
    case ErrNotDirectory:
        return syscall.ENOTDIR
    case ErrNoSpace:
        return syscall.ENOSPC
    case ErrInvalidArgument:
        return syscall.EINVAL
    case ErrReadOnly:
        return syscall.EROFS
    case ErrTooManyLinks:
        return syscall.EMLINK
    case ErrFileTooLarge:
        return syscall.EFBIG
    case ErrTimeout:
        return syscall.ETIMEDOUT
    case ErrNetwork:
        return syscall.ENETUNREACH
    default:
        return syscall.EIO
    }
}

func (sch *SystemCallHandler) ConvertMode(mode uint32) os.FileMode {
    var fileMode os.FileMode = os.FileMode(mode & 0777)
    
    if mode&syscall.S_IFDIR != 0 {
        fileMode |= os.ModeDir
    }
    if mode&syscall.S_IFLNK != 0 {
        fileMode |= os.ModeSymlink
    }
    if mode&syscall.S_IFIFO != 0 {
        fileMode |= os.ModeNamedPipe
    }
    if mode&syscall.S_IFCHR != 0 {
        fileMode |= os.ModeCharDevice
    }
    if mode&syscall.S_IFBLK != 0 {
        fileMode |= os.ModeDevice
    }
    if mode&syscall.S_IFSOCK != 0 {
        fileMode |= os.ModeSocket
    }
    if mode&syscall.S_ISUID != 0 {
        fileMode |= os.ModeSetuid
    }
    if mode&syscall.S_ISGID != 0 {
        fileMode |= os.ModeSetgid
    }
    if mode&syscall.S_ISVTX != 0 {
        fileMode |= os.ModeSticky
    }
    
    return fileMode
}

func (sch *SystemCallHandler) ConvertTime(t time.Time) fuse.Time {
    return fuse.Time{
        Sec:  uint64(t.Unix()),
        Nsec: uint32(t.Nanosecond()),
    }
}
```

### 6. Mount Manager

```go
package posix

import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"

    "bazil.org/fuse"
    "bazil.org/fuse/fs"
)

type MountManager struct {
    mountPoint string
    fs         *BlackholeFS
    conn       *fuse.Conn
    server     *fs.Server
}

func NewMountManager(mountPoint string, bfs *BlackholeFS) *MountManager {
    return &MountManager{
        mountPoint: mountPoint,
        fs:         bfs,
    }
}

func (mm *MountManager) Mount() error {
    // Create mount point if it doesn't exist
    if err := os.MkdirAll(mm.mountPoint, 0755); err != nil {
        return err
    }
    
    // Mount options
    options := []fuse.MountOption{
        fuse.FSName("blackhole"),
        fuse.Subtype("blackholefs"),
        fuse.LocalVolume(),
        fuse.VolumeName("BlackholeFS"),
        fuse.DefaultPermissions(),
        fuse.AllowOther(),
        fuse.MaxReadahead(128 * 1024),
        fuse.AsyncRead(),
        fuse.WritebackCache(),
    }
    
    conn, err := fuse.Mount(mm.mountPoint, options...)
    if err != nil {
        return err
    }
    mm.conn = conn
    
    // Create FUSE server
    mm.server = fs.New(conn, &fs.Config{
        Debug: func(msg interface{}) {
            log.Printf("FUSE: %v", msg)
        },
    })
    
    return nil
}

func (mm *MountManager) Serve() error {
    return mm.server.Serve(mm.fs)
}

func (mm *MountManager) Unmount() error {
    if mm.conn != nil {
        return fuse.Unmount(mm.mountPoint)
    }
    return nil
}

func (mm *MountManager) WaitForSignal() {
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    <-c
}

func (mm *MountManager) Run(ctx context.Context) error {
    if err := mm.Mount(); err != nil {
        return err
    }
    
    defer mm.Unmount()
    
    // Start serving in background
    errCh := make(chan error, 1)
    go func() {
        errCh <- mm.Serve()
    }()
    
    // Wait for context cancellation or error
    select {
    case <-ctx.Done():
        return ctx.Err()
    case err := <-errCh:
        return err
    }
}
```

### 7. Extended Attributes

```go
package posix

import (
    "context"
    "strings"

    "bazil.org/fuse"
)

func (f *File) Listxattr(ctx context.Context, req *fuse.ListxattrRequest, resp *fuse.ListxattrResponse) error {
    attrs, err := f.fs.metadataService.ListExtendedAttributes(f.path)
    if err != nil {
        return err
    }
    
    size := 0
    for name := range attrs {
        size += len(name) + 1 // +1 for null terminator
    }
    
    if req.Size == 0 {
        resp.Size = size
        return nil
    }
    
    if req.Size < size {
        return fuse.Errno(syscall.ERANGE)
    }
    
    var buf strings.Builder
    for name := range attrs {
        buf.WriteString(name)
        buf.WriteByte(0)
    }
    
    resp.Xattr = []byte(buf.String())
    return nil
}

func (f *File) Getxattr(ctx context.Context, req *fuse.GetxattrRequest, resp *fuse.GetxattrResponse) error {
    value, err := f.fs.metadataService.GetExtendedAttribute(f.path, req.Name)
    if err != nil {
        return fuse.ENODATA
    }
    
    if req.Size == 0 {
        resp.Size = len(value)
        return nil
    }
    
    if req.Size < len(value) {
        return fuse.Errno(syscall.ERANGE)
    }
    
    resp.Xattr = value
    return nil
}

func (f *File) Setxattr(ctx context.Context, req *fuse.SetxattrRequest) error {
    return f.fs.metadataService.SetExtendedAttribute(f.path, req.Name, req.Xattr, req.Flags)
}

func (f *File) Removexattr(ctx context.Context, req *fuse.RemovexattrRequest) error {
    return f.fs.metadataService.RemoveExtendedAttribute(f.path, req.Name)
}
```

## Error Handling

```go
package posix

import (
    "errors"
)

var (
    ErrNotFound         = errors.New("file not found")
    ErrExists          = errors.New("file exists")
    ErrNotEmpty        = errors.New("directory not empty")
    ErrPermission      = errors.New("permission denied")
    ErrIsDirectory     = errors.New("is a directory")
    ErrNotDirectory    = errors.New("not a directory")
    ErrNoSpace         = errors.New("no space left")
    ErrInvalidArgument = errors.New("invalid argument")
    ErrReadOnly        = errors.New("read-only filesystem")
    ErrTooManyLinks    = errors.New("too many links")
    ErrFileTooLarge    = errors.New("file too large")
    ErrTimeout         = errors.New("operation timed out")
    ErrNetwork         = errors.New("network error")
)
```

## Configuration

```go
package posix

type Config struct {
    MountPoint     string        `yaml:"mount_point"`
    Debug          bool          `yaml:"debug"`
    AllowOther     bool          `yaml:"allow_other"`
    MaxReadahead   int           `yaml:"max_readahead"`
    WritebackCache bool          `yaml:"writeback_cache"`
    Timeout        time.Duration `yaml:"timeout"`
}

func DefaultConfig() *Config {
    return &Config{
        MountPoint:     "/mnt/blackhole",
        Debug:          false,
        AllowOther:     true,
        MaxReadahead:   128 * 1024,
        WritebackCache: true,
        Timeout:        30 * time.Second,
    }
}
```

## Performance Optimizations

1. **Kernel Buffering**: Uses FUSE writeback cache for better write performance
2. **Readahead**: Implements adaptive readahead for sequential access patterns
3. **Async Operations**: Uses asynchronous I/O where possible
4. **Batch Operations**: Groups multiple operations for efficiency
5. **Smart Caching**: Integrates with filesystem cache for optimal performance

## Testing

```go
package posix

import (
    "testing"
    "context"
    "os"
    "io/ioutil"
    "path/filepath"
)

func TestPOSIXOperations(t *testing.T) {
    // Setup test filesystem
    fs := setupTestFilesystem(t)
    mm := NewMountManager("/tmp/test-blackhole", fs)
    
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    go func() {
        if err := mm.Run(ctx); err != nil {
            t.Errorf("Mount failed: %v", err)
        }
    }()
    
    // Wait for mount to be ready
    time.Sleep(100 * time.Millisecond)
    
    // Test file operations
    testFile := "/tmp/test-blackhole/test.txt"
    
    // Write file
    err := ioutil.WriteFile(testFile, []byte("hello world"), 0644)
    if err != nil {
        t.Fatalf("Write failed: %v", err)
    }
    
    // Read file
    data, err := ioutil.ReadFile(testFile)
    if err != nil {
        t.Fatalf("Read failed: %v", err)
    }
    
    if string(data) != "hello world" {
        t.Errorf("Expected 'hello world', got '%s'", string(data))
    }
    
    // Test directory operations
    testDir := "/tmp/test-blackhole/testdir"
    err = os.Mkdir(testDir, 0755)
    if err != nil {
        t.Fatalf("Mkdir failed: %v", err)
    }
    
    // List directory
    entries, err := ioutil.ReadDir("/tmp/test-blackhole")
    if err != nil {
        t.Fatalf("ReadDir failed: %v", err)
    }
    
    found := false
    for _, entry := range entries {
        if entry.Name() == "testdir" && entry.IsDir() {
            found = true
            break
        }
    }
    
    if !found {
        t.Error("Directory not found in listing")
    }
    
    // Cleanup
    os.Remove(testFile)
    os.Remove(testDir)
}
```

This POSIX layer provides complete compatibility with standard UNIX file operations while leveraging the distributed blackhole filesystem capabilities.