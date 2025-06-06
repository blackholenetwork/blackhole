# ADR-001: Use Go as Primary Language

## Status
Accepted

## Context
We need to choose a programming language for building a distributed system that will run on diverse hardware (home computers) with requirements for:
- High performance
- Low memory footprint
- Easy deployment (single binary)
- Good networking libraries
- Strong concurrency support

## Decision
We will use Go as the primary programming language.

## Rationale
- **Single binary deployment**: Go compiles to a single static binary, making distribution easy
- **Performance**: Near C-level performance with garbage collection
- **Concurrency**: Goroutines and channels are perfect for P2P networking
- **Library ecosystem**: Excellent support for networking (libp2p), crypto, and web services
- **Memory efficiency**: Lower footprint than JVM or Node.js
- **Cross-compilation**: Easy to build for multiple platforms

## Consequences
### Positive
- Easy deployment to end users
- Efficient resource usage on home computers
- Strong standard library reduces dependencies
- Built-in testing and profiling tools

### Negative
- No generics (until Go 1.18+) leading to some code duplication
- Error handling can be verbose
- Smaller talent pool compared to JavaScript/Python
- Less mature web framework ecosystem compared to other languages

## Alternatives Considered
- **Rust**: Better memory safety but steeper learning curve and longer compile times
- **Node.js**: Larger ecosystem but higher memory usage and deployment complexity
- **Java**: Mature ecosystem but JVM overhead and complex deployment
- **Python**: Easier development but poor performance and complex deployment
