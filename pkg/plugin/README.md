# Internal Plugin Framework

This package provides the internal plugin framework for Blackhole Network core components.

## Purpose

- **Internal Use Only**: This framework is for building core Blackhole Network components
- **Compiled Into Binary**: All plugins using this framework become part of the main executable
- **High Performance**: Direct function calls, no network overhead
- **Type Safe**: Full Go type checking and compile-time verification

## Components

- `plugin.go` - Core interfaces and types
- `registry.go` - Plugin registration and lifecycle management
- `base.go` - Base implementations and helpers
- `utils/` - Common utilities for plugin development

## Usage

This framework is used internally for:
- Networking component (libp2p integration)
- Storage component (erasure coding)
- Security component (DID management)
- Monitoring component (metrics collection)

## NOT for External Plugins

If you're looking to build external plugins for Blackhole Network, you'll need the Blackhole SDK (coming soon as a separate package).

### Internal Plugin Example

```go
package main

import (
    "github.com/blackholenetwork/blackhole/pkg/plugin"
)

type MyInternalPlugin struct {
    *plugin.BasePlugin
}

func (p *MyInternalPlugin) Start(ctx context.Context) error {
    // Internal implementation
    return nil
}
```

### External Plugin (Future SDK)

External plugins will use a separate SDK package:
```go
import "github.com/blackholenetwork/sdk"  // Separate module
```