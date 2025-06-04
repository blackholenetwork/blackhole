# Blackhole Network Documentation

Welcome to the Blackhole Network documentation. This guide will help you navigate our comprehensive documentation.

## 📁 Documentation Structure

### 🏗️ [Architecture](./architecture/)
High-level system design and architectural decisions
- **[Technical Architecture](./architecture/TECHNICAL_ARCHITECTURE.md)** - System overview and technology choices
- **[Module Boundaries](./architecture/MODULE_BOUNDARIES.md)** - Component dependencies and rules
- **[ADR-001: Use Go](./architecture/ADR-001-use-go.md)** - Why we chose Go as our language

### 🎨 [Design](./design/)
Detailed component design and interactions
- **[System Design](./design/SYSTEM_DESIGN.md)** - Complete component implementations
- **[Interfaces](./design/INTERFACES.md)** - All component contracts
- **[Component Interactions](./design/COMPONENT_INTERACTIONS.md)** - How components communicate

### 📏 [Standards](./standards/)
Coding standards and best practices
- **[Overview](./standards/README.md)** - Index of all standards
- **[Coding Standards](./standards/CODING_STANDARDS.md)** - How to write code
- **[API Standards](./standards/API_STANDARDS.md)** - REST, WebSocket, GraphQL conventions
- **[Security Standards](./standards/SECURITY_STANDARDS.md)** - Security requirements
- **[Performance Standards](./standards/PERFORMANCE_STANDARDS.md)** - Performance targets
- **[And more...](./standards/)**

### 🛠️ [Development](./development/)
Development guides and tooling
- **[Code Design Principles](./development/CODE_DESIGN_PRINCIPLES.md)** - Fundamental design principles
- **[Tooling](./development/TOOLING.md)** - Development tools and automation

### 📚 [Patterns](./patterns/)
Reusable patterns and solutions
- **[Common Patterns](./patterns/COMMON_PATTERNS.md)** - Copy-paste solutions for common problems

## 🚀 Quick Start for Developers

1. **New to the project?**
   - Start with [Technical Architecture](./architecture/TECHNICAL_ARCHITECTURE.md)
   - Review [Coding Standards](./standards/CODING_STANDARDS.md)
   - Check [Developer Checklist](./standards/DEVELOPER_CHECKLIST.md)

2. **Starting development?**
   - Read [Module Boundaries](./architecture/MODULE_BOUNDARIES.md)
   - Use [Common Patterns](./patterns/COMMON_PATTERNS.md)
   - Follow [Development Practices](./standards/DEVELOPMENT_PRACTICES.md)

3. **Implementing a feature?**
   - Check [Component Interactions](./design/COMPONENT_INTERACTIONS.md)
   - Review relevant [Interfaces](./design/INTERFACES.md)
   - Apply [Design Principles](./development/CODE_DESIGN_PRINCIPLES.md)

## 📋 Document Categories

### By Purpose
- **🎯 Architecture**: Big picture, system design
- **📐 Design**: Detailed implementations
- **✅ Standards**: Rules and conventions
- **🔧 Development**: How to build
- **🎨 Patterns**: Reusable solutions

### By Audience
- **👨‍💼 Architects**: Architecture, Design folders
- **👩‍💻 Developers**: Standards, Development, Patterns
- **🚀 DevOps**: Standards (Deployment), Architecture
- **🔒 Security**: Standards (Security), Design

## 🔍 Finding Information

### "How do I...?"
- **Write code?** → [Coding Standards](./standards/CODING_STANDARDS.md)
- **Design a component?** → [System Design](./design/SYSTEM_DESIGN.md)
- **Handle errors?** → [Error Handling Strategy](./standards/ERROR_HANDLING_STRATEGY.md)
- **Add a feature?** → [Component Interactions](./design/COMPONENT_INTERACTIONS.md)
- **Deploy?** → [Deployment Standards](./standards/DEPLOYMENT_STANDARDS.md)

### "Where is...?"
- **Component interfaces?** → [Interfaces](./design/INTERFACES.md)
- **API conventions?** → [API Standards](./standards/API_STANDARDS.md)
- **Common utilities?** → `/pkg/common/`
- **Middleware?** → `/pkg/middleware/`

## 📝 Documentation Maintenance

- **Architecture docs**: Update when making architectural changes
- **Design docs**: Update when changing component interactions
- **Standards**: Propose changes via PR with team discussion
- **Patterns**: Add new patterns as they emerge

Remember: Good documentation is a living artifact. Keep it updated!