# Roles and Responsibilities Matrix

## Quick Reference Guide

This matrix provides a clear overview of who does what in each cycle and activity. Use the RACI model:
- **R** = Responsible (does the work)
- **A** = Accountable (final decision maker)
- **C** = Consulted (provides input)
- **I** = Informed (kept updated)

---

## Cycle 1: Discovery & Vision

| Activity | Product Owner | Scrum Master | Tech Lead | Developers | DevOps | QA | Security | UX Designer |
|----------|--------------|--------------|-----------|------------|--------|----|-----------|----|
| **Business Discovery** |
| Stakeholder Mapping | R/A | C | I | - | - | - | - | C |
| Problem Definition | R/A | C | C | I | - | I | - | C |
| Success Metrics | R/A | C | C | C | - | C | - | C |
| Scope Definition | R/A | C | C | C | - | C | - | C |
| **Technical Discovery** |
| System Assessment | C | I | R/A | C | C | C | C | I |
| Technology Evaluation | C | I | R/A | R | C | I | C | I |
| Security Review | I | I | R | C | C | I | R/A | - |
| Infrastructure Planning | I | I | C | I | R/A | I | C | - |
| **Team Formation** |
| Team Composition | C | R/A | C | I | I | I | I | I |
| Team Charter | C | R/A | C | R | R | R | R | R |
| Environment Setup | I | C | C | R | R/A | C | I | - |

---

## Cycle 2: Foundation & Design

| Activity | Product Owner | Scrum Master | Tech Lead | Developers | DevOps | QA | Security | UX Designer |
|----------|--------------|--------------|-----------|------------|--------|----|-----------|----|
| **Architecture Design** |
| Architecture Vision | C | I | R/A | R | C | I | C | C |
| Domain Modeling | C | I | R/A | R | I | I | I | I |
| Component Design | I | - | R/A | R | C | C | C | C |
| Database Design | I | - | A | R | I | I | C | - |
| **Technical Foundation** |
| CI/CD Setup | I | I | C | C | R/A | C | C | - |
| Code Standards | I | C | R/A | R | I | C | I | - |
| Test Strategy | C | C | C | C | C | R/A | I | I |
| Security Framework | I | I | C | C | C | I | R/A | - |
| **Process Setup** |
| Definition of Done | C | R/A | C | R | R | R | C | C |
| Review Process | I | R/A | R | R | C | R | C | I |
| **Backlog Creation** |
| Epic Definition | R/A | C | C | I | - | I | - | C |
| Story Writing | R/A | C | C | C | - | C | - | C |
| Prioritization | R/A | C | C | I | - | I | - | I |

---

## Cycle 3: Development Iterations

| Activity | Product Owner | Scrum Master | Tech Lead | Developers | DevOps | QA | Security | UX Designer |
|----------|--------------|--------------|-----------|------------|--------|----|-----------|----|
| **Iteration Planning** |
| Backlog Refinement | R/A | R | C | C | I | C | I | C |
| Story Estimation | A | R | C | R | I | C | - | I |
| Goal Setting | R/A | R | C | C | - | I | - | I |
| Task Breakdown | C | R | C | R/A | C | C | - | I |
| **Daily Development** |
| Daily Standup | C | R/A | R | R | R | R | I | I |
| Development | I | I | C | R/A | I | I | I | C |
| Code Review | - | - | R | R/A | I | C | C | - |
| Testing | I | I | I | R | I | R/A | I | I |
| CI/CD Monitoring | - | I | I | C | R/A | C | I | - |
| **Iteration Closure** |
| Demo Preparation | R | C | C | R/A | I | C | - | C |
| Stakeholder Demo | R/A | R | C | R | I | C | - | C |
| Metrics Review | C | R/A | C | I | C | C | I | - |
| Retrospective | R | R/A | R | R | R | R | R | R |

---

## Cycle 4: Release & Operations

| Activity | Product Owner | Scrum Master | Tech Lead | Developers | DevOps | QA | Security | UX Designer |
|----------|--------------|--------------|-----------|------------|--------|----|-----------|----|
| **Release Preparation** |
| Release Testing | C | I | C | C | I | R/A | C | I |
| Release Notes | R/A | C | C | C | I | C | I | I |
| Deployment Planning | C | C | C | I | R/A | C | C | - |
| Readiness Review | A | C | R | C | R | R | R | I |
| **Deployment** |
| Pre-deployment | I | I | C | I | R/A | C | C | - |
| Deployment | I | I | I | I | R/A | I | I | - |
| Validation | C | I | C | C | R | R/A | C | I |
| Communication | R/A | R | I | I | I | I | I | I |
| **Operations** |
| Monitoring | I | I | I | I | R/A | I | C | - |
| Incident Response | I | I | C | C | R/A | C | C | - |
| Performance Tuning | I | - | C | R | R/A | C | - | - |
| Feedback Collection | R/A | C | I | I | I | C | I | C |

---

## Role Descriptions

### Product Owner
**Primary Focus**: Business value and stakeholder satisfaction
- Owns product vision and roadmap
- Manages and prioritizes backlog
- Accepts completed work
- Communicates with stakeholders

### Scrum Master
**Primary Focus**: Process effectiveness and team health
- Facilitates ceremonies and meetings
- Removes impediments
- Coaches team on agile practices
- Tracks and reports metrics

### Tech Lead
**Primary Focus**: Technical excellence and architecture
- Makes architectural decisions
- Mentors developers
- Reviews critical code
- Ensures technical standards

### Developers
**Primary Focus**: Implementation and quality
- Write code and tests
- Participate in reviews
- Collaborate on design
- Support deployments

### DevOps Engineer
**Primary Focus**: Infrastructure and automation
- Maintains CI/CD pipelines
- Manages environments
- Monitors system health
- Responds to incidents

### QA Engineer
**Primary Focus**: Quality assurance and testing
- Creates test strategies
- Executes test plans
- Automates tests
- Reports on quality

### Security Champion
**Primary Focus**: Security and compliance
- Reviews security requirements
- Conducts security testing
- Monitors vulnerabilities
- Ensures compliance

### UX Designer
**Primary Focus**: User experience and design
- Creates user interfaces
- Conducts user research
- Ensures accessibility
- Maintains design system

---

## Accountability Guidelines

### Single Accountability Rule
Each activity should have only one "A" (Accountable) role to avoid confusion

### Responsibility Distribution
- Avoid overloading single roles with too many "R" assignments
- Ensure critical activities have backup responsible parties

### Consultation Balance
- Include relevant expertise as "C" without over-consulting
- Balance speed with thoroughness

### Information Flow
- Keep stakeholders informed ("I") without overwhelming them
- Use automated notifications where possible

---

## Using This Matrix

### For Planning
1. Review activities for upcoming cycle
2. Confirm role assignments match team composition
3. Identify any gaps in coverage
4. Plan for missing skills

### For Execution
1. Reference during planning sessions
2. Clarify responsibilities when conflicts arise
3. Update based on team changes
4. Use for onboarding new members

### For Improvement
1. Review effectiveness in retrospectives
2. Adjust assignments based on outcomes
3. Document exceptions and learnings
4. Share updates with team

---

## Customization Notes

- **Small Teams**: Combine roles (one person may have multiple roles)
- **Large Teams**: May have multiple people in same role
- **Specialized Domains**: Add domain-specific roles as needed
- **Tool Constraints**: Adjust based on available tooling and automation