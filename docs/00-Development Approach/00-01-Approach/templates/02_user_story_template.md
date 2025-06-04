# User Story Template

## Story Information
**Story ID:** US-[Number]
**Epic:** [Epic Name]
**Feature:** [Feature Name]
**Sprint:** [Sprint Number or Backlog]
**Story Points:** [1, 2, 3, 5, 8, 13]
**Priority:** Critical/High/Medium/Low
**Business Value:** [1-10]
**Risk Level:** High/Medium/Low

## User Story Statement

**As a** [type of user/persona]  
**I want** [goal/desire/functionality]  
**So that** [benefit/value/reason]

### Story Context
[Additional context about why this story is important, any background information that helps understand the user's need]

## Acceptance Criteria

### Functional Criteria

#### Scenario 1: [Happy Path - Primary Use Case]
**Given** [initial context/state/precondition]  
**When** [action taken by user]  
**Then** [expected outcome/postcondition]  
**And** [additional outcomes if any]

#### Scenario 2: [Alternative Path]
**Given** [initial context]  
**When** [alternative action]  
**Then** [expected outcome]

#### Scenario 3: [Error/Edge Case]
**Given** [error condition]  
**When** [action attempted]  
**Then** [error handling behavior]

### Non-Functional Criteria

#### Performance
- [ ] Response time < [X] seconds
- [ ] Support [X] concurrent users
- [ ] Process [X] records per minute

#### Security
- [ ] Authentication required: [Yes/No]
- [ ] Authorization level: [Role/Permission]
- [ ] Data encryption: [Requirements]

#### Usability
- [ ] Accessible via keyboard navigation
- [ ] Mobile responsive
- [ ] Follows design system guidelines

## Technical Details

### API Endpoints
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | /api/resource | Retrieve data |
| POST | /api/resource | Create new item |

### Data Model Changes
```yaml
Entity: [Name]
New Fields:
  - fieldName: type, constraints
  - fieldName: type, constraints
Modified Fields:
  - fieldName: changes
```

### Integration Points
- **System:** [Name] - [Purpose of integration]
- **Service:** [Name] - [Data exchange description]

### Architecture Impact
- [ ] New service/component required
- [ ] Database schema changes
- [ ] API contract changes
- [ ] Performance considerations

## Definition of Done

### Development
- [ ] Code implemented according to acceptance criteria
- [ ] Unit tests written and passing (coverage > 80%)
- [ ] Integration tests implemented
- [ ] Code reviewed and approved by team
- [ ] No critical code analysis issues

### Testing
- [ ] All acceptance criteria verified
- [ ] Edge cases tested
- [ ] Cross-browser testing completed (if UI)
- [ ] Performance requirements met
- [ ] Security scan passed

### Documentation
- [ ] API documentation updated
- [ ] User documentation created/updated
- [ ] Technical documentation updated
- [ ] Release notes prepared

### Deployment
- [ ] Deployed to staging environment
- [ ] Smoke tests passed
- [ ] Feature flag configured (if applicable)
- [ ] Monitoring alerts configured
- [ ] Rollback plan documented

## Dependencies

### Blocked By
- [ ] [US-XXX]: [Description of dependency]
- [ ] [External dependency]: [Description]

### Blocks
- [ ] [US-XXX]: [Description of dependent story]

### Related Stories
- [US-XXX]: [Relationship description]
- [US-XXX]: [Relationship description]

## Design & Mockups

### UI/UX References
- **Mockups:** [Link to design files]
- **Prototype:** [Link to interactive prototype]
- **Design System:** [Component references]

### User Flow
```
[Start] → [Step 1] → [Decision] → [Step 2] → [End]
                          ↓
                     [Alt Step] → [End]
```

## Test Cases

### Test Case 1: [Primary Function]
**Preconditions:** [Setup required]
**Steps:**
1. [Action 1]
2. [Action 2]
3. [Verify result]

**Expected Result:** [What should happen]

### Test Case 2: [Error Handling]
**Preconditions:** [Setup for error condition]
**Steps:**
1. [Action to trigger error]
2. [Verify error message]

**Expected Result:** [Error handling behavior]

## Implementation Notes

### Technical Approach
[Brief description of how to implement this story]

### Potential Challenges
1. [Challenge 1] - [Mitigation approach]
2. [Challenge 2] - [Mitigation approach]

### Performance Considerations
- [Database query optimization needs]
- [Caching strategy]
- [Async processing requirements]

## Estimation Rationale

### Complexity Factors
- **Business Logic:** Simple/Medium/Complex
- **UI Changes:** None/Minor/Major
- **Integration:** None/Simple/Complex
- **Data Migration:** None/Simple/Complex

### Story Point Breakdown
- Development: [X] points
- Testing: [X] points
- Documentation: [X] points
- **Total:** [X] points

## Questions & Assumptions

### Open Questions
- [ ] [Question for Product Owner]
- [ ] [Technical clarification needed]

### Assumptions
1. [Assumption about user behavior]
2. [Technical assumption]
3. [Business rule assumption]

## Conversation History

### [Date] - Initial Discussion
- Participants: [Names]
- Key Decisions: [Summary]

### [Date] - Refinement Session
- Participants: [Names]
- Changes: [What was modified]

## Metrics & Analytics

### Success Metrics
- **Usage:** [Expected usage pattern]
- **Performance:** [Key performance indicator]
- **Business Impact:** [Measurable outcome]

### Analytics Events
- [ ] Event: `feature_used` - Properties: [list]
- [ ] Event: `action_completed` - Properties: [list]

---

## Template Usage Notes

1. **Story ID**: Use sequential numbering or link to your tracking system
2. **Story Points**: Use Fibonacci sequence for relative sizing
3. **Acceptance Criteria**: Write from user's perspective, be specific
4. **Definition of Done**: Customize based on team standards
5. **Dependencies**: Keep updated throughout development
6. **Test Cases**: Add more as edge cases are discovered

Remember: A good user story is:
- **I**ndependent
- **N**egotiable  
- **V**aluable
- **E**stimable
- **S**mall
- **T**estable