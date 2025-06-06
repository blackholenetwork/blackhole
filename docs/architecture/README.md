# Architecture Documentation

This folder contains high-level architectural documentation and decisions.

## Documents

### 📋 [Technical Architecture](./TECHNICAL_ARCHITECTURE.md)
The complete technical overview of Blackhole Network:
- System architecture overview
- Technology stack and choices
- Layered implementation strategy
- Development approach
- Deployment strategy

### 🧩 [Module Boundaries](./MODULE_BOUNDARIES.md)
Rules and guidelines for component dependencies:
- Dependency hierarchy
- Forbidden dependencies
- Interface ownership
- Testing boundaries

### 📝 Architecture Decision Records (ADRs)
Document important architectural decisions:
- [ADR-001: Use Go](./ADR-001-use-go.md) - Why Go was chosen

## When to Update

- **Technical Architecture**: When adding new major components or changing technology stack
- **Module Boundaries**: When adding new packages or changing dependency rules
- **ADRs**: When making significant architectural decisions

## Creating New ADRs

Use this template for new ADRs:

```markdown
# ADR-XXX: Title

## Status
Proposed/Accepted/Deprecated/Superseded

## Context
What is the issue we're facing?

## Decision
What have we decided to do?

## Rationale
Why did we make this decision?

## Consequences
What are the positive and negative outcomes?

## Alternatives Considered
What other options did we evaluate?
```

Name format: `ADR-XXX-short-description.md`
