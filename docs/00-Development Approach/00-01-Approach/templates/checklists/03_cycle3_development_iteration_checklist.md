# Cycle 3: Development Iteration - Sprint Checklist

**Project Name:** ___________________________  
**Sprint Number:** ___________________________  
**Sprint Start Date:** ___________________________  
**Sprint End Date:** ___________________________  
**Sprint Lead:** ___________________________  

## Sprint Overview
**Objective:** Deliver working software incrementally with continuous feedback and quality.

**Sprint Goal:** _____________________________________________________________
_________________________________________________________________________

**Success Criteria:**
- [ ] Sprint goal achieved
- [ ] All committed stories meet Definition of Done
- [ ] No regression in quality metrics
- [ ] Stakeholder feedback collected

---

## Section 3.1: Sprint Planning

### ✅ 3.1.1 Backlog Refinement

**Objective:** Ensure stories are ready for development with clear requirements.

**Responsible:** Product Owner  
**Participants:** Development Team  
**Time Estimate:** 2-3 hours (before sprint planning)

**Instructions:**
1. Review upcoming backlog items
2. Clarify acceptance criteria
3. Identify dependencies and risks
4. Split stories that are too large
5. Ensure stories meet "Ready" criteria

**Actions:**
- [ ] Schedule refinement session (mid-sprint)
- [ ] Review next 2 sprints worth of stories
- [ ] Update acceptance criteria
- [ ] Identify technical dependencies
- [ ] Break down stories > 8 points
- [ ] Add technical tasks to stories
- [ ] Confirm external dependencies resolved
- [ ] Mark stories as "Ready"

**Deliverables:**
- [ ] Refined stories marked "Ready"
- [ ] Dependencies documented
- [ ] Technical tasks identified

**Notes/Issues:**
_________________________________
_________________________________

---

### ✅ 3.1.2 Story Estimation

**Objective:** Size work accurately to plan sprint capacity effectively.

**Responsible:** Development Team  
**Participants:** Scrum Master (facilitator)  
**Time Estimate:** 1-2 hours

**Instructions:**
1. Use Planning Poker or similar technique
2. Discuss complexity, effort, and risk
3. Consider technical work needed
4. Reach team consensus on estimates
5. Flag high-risk items

**Actions:**
- [ ] Review story details as team
- [ ] Conduct Planning Poker rounds
- [ ] Discuss divergent estimates
- [ ] Consider technical complexity
- [ ] Factor in testing effort
- [ ] Include documentation time
- [ ] Reach consensus on points
- [ ] Update story estimates

**Deliverables:**
- [ ] All stories estimated
- [ ] Risk factors noted
- [ ] Velocity calculation updated

**Notes/Issues:**
_________________________________
_________________________________

---

### ✅ 3.1.3 Sprint Goal Setting

**Objective:** Define clear focus for the sprint that delivers value.

**Responsible:** Product Owner  
**Participants:** Entire Team  
**Time Estimate:** 30 minutes

**Instructions:**
1. Review product roadmap and priorities
2. Consider team capacity and velocity
3. Draft sprint goal statement
4. Ensure goal is achievable and valuable
5. Get team commitment

**Actions:**
- [ ] Review product priorities
- [ ] Calculate team capacity
- [ ] Check velocity trends
- [ ] Draft sprint goal
- [ ] Validate technical feasibility
- [ ] Confirm business value
- [ ] Get team consensus
- [ ] Document sprint goal

**Deliverables:**
- [ ] Sprint goal documented
- [ ] Team commitment confirmed
- [ ] Goal posted visibly

**Notes/Issues:**
_________________________________
_________________________________

---

### ✅ 3.1.4 Task Breakdown

**Objective:** Create actionable tasks that team members can execute.

**Responsible:** Development Team  
**Participants:** Scrum Master (facilitator)  
**Time Estimate:** 1-2 hours

**Instructions:**
1. Break each story into development tasks
2. Identify testing tasks
3. Include deployment/DevOps tasks
4. Estimate task hours (optional)
5. Assign initial owners

**Actions:**
- [ ] List development tasks per story
- [ ] Add testing tasks (unit, integration, E2E)
- [ ] Include code review tasks
- [ ] Add documentation tasks
- [ ] Include deployment tasks
- [ ] Estimate hours (if team practice)
- [ ] Volunteers claim initial tasks
- [ ] Create task board

**Deliverables:**
- [ ] Task breakdown complete
- [ ] Task board populated
- [ ] Initial assignments made

**Notes/Issues:**
_________________________________
_________________________________

---

## Section 3.2: Daily Development Flow

### ✅ 3.2.1 Daily Standup

**Objective:** Synchronize team efforts and identify impediments quickly.

**Responsible:** Each Team Member  
**Participants:** Entire Team  
**Time Estimate:** 15 minutes maximum

**Instructions:**
1. Start on time, same time each day
2. Each person shares: yesterday, today, blockers
3. Keep updates brief and relevant
4. Take detailed discussions offline
5. Update task board real-time

**Daily Actions:**
- [ ] Yesterday: What I completed
- [ ] Today: What I plan to complete
- [ ] Blockers: Any impediments
- [ ] Help needed: From specific team members
- [ ] Update task board status
- [ ] Note follow-up items

**Common Issues to Address:**
- [ ] Blocked tasks
- [ ] Sick/absent team members
- [ ] Technical challenges
- [ ] Scope clarifications needed
- [ ] Environment issues

**Notes/Issues:**
_________________________________
_________________________________

---

### ✅ 3.2.2 Continuous Integration Practice

**Objective:** Maintain code quality through frequent integration and automated testing.

**Responsible:** Developers  
**Participants:** DevOps (support)  
**Time Estimate:** Ongoing throughout sprint

**Instructions:**
1. Write tests before code (TDD)
2. Commit code frequently (daily minimum)
3. Ensure all tests pass locally first
4. Fix broken builds immediately
5. Monitor CI pipeline results

**Daily Development Checklist:**
- [ ] Pull latest code before starting
- [ ] Write failing test first
- [ ] Implement code to pass test
- [ ] Run all tests locally
- [ ] Commit with meaningful message
- [ ] Push to feature branch
- [ ] Verify CI build passes
- [ ] Address any failures immediately

**CI Health Metrics:**
- [ ] Build success rate: ______%
- [ ] Average build time: ______ min
- [ ] Test coverage: ______%
- [ ] Code quality score: ______

**Notes/Issues:**
_________________________________
_________________________________

---

### ✅ 3.2.3 Code Review Process

**Objective:** Ensure code quality through peer review and knowledge sharing.

**Responsible:** Developer (author)  
**Participants:** Reviewer(s)  
**Time Estimate:** 30-60 min per review

**Instructions:**
1. Create PR with clear description
2. Ensure CI checks pass
3. Request review from team member
4. Address feedback promptly
5. Merge only after approval

**Pull Request Checklist:**
- [ ] PR description explains changes
- [ ] Links to story/task included
- [ ] All tests passing
- [ ] Code coverage maintained/improved
- [ ] No security vulnerabilities
- [ ] Follows coding standards
- [ ] Documentation updated
- [ ] Reviewer assigned

**Review Checklist:**
- [ ] Functionality correct
- [ ] Tests adequate
- [ ] Code readable
- [ ] Performance acceptable
- [ ] Security considered
- [ ] No code duplication

**Notes/Issues:**
_________________________________
_________________________________

---

### ✅ 3.2.4 Continuous Deployment

**Objective:** Deploy changes safely and frequently to get rapid feedback.

**Responsible:** DevOps Engineer  
**Participants:** Developer (changes owner)  
**Time Estimate:** Automated (manual oversight: 15-30 min)

**Instructions:**
1. Merge approved PRs to main branch
2. Monitor automated deployment pipeline
3. Verify deployment success
4. Check monitoring dashboards
5. Validate feature flags (if used)

**Deployment Checklist:**
- [ ] PR approved and merged
- [ ] Deployment pipeline triggered
- [ ] Build stage passed
- [ ] Tests stage passed
- [ ] Security scans passed
- [ ] Deployment to staging complete
- [ ] Smoke tests passed
- [ ] Monitoring alerts configured
- [ ] Feature flags set correctly

**Post-Deployment Verification:**
- [ ] Application health check
- [ ] Error rates normal
- [ ] Performance metrics stable
- [ ] New features accessible

**Notes/Issues:**
_________________________________
_________________________________

---

## Section 3.3: Sprint Closure

### ✅ 3.3.1 Sprint Review Preparation

**Objective:** Prepare effective demonstration of completed work.

**Responsible:** Development Team  
**Participants:** Product Owner  
**Time Estimate:** 1-2 hours

**Instructions:**
1. Identify all completed stories
2. Prepare demo scenarios
3. Set up demo environment
4. Create presentation outline
5. Do dry run if needed

**Actions:**
- [ ] List completed stories
- [ ] Prepare demo data
- [ ] Test demo scenarios
- [ ] Create demo script/outline
- [ ] Assign demo presenters
- [ ] Test screen sharing
- [ ] Prepare metrics summary
- [ ] Send review invitation

**Deliverables:**
- [ ] Demo environment ready
- [ ] Demo scenarios tested
- [ ] Presentation materials
- [ ] Meeting invitation sent

**Notes/Issues:**
_________________________________
_________________________________

---

### ✅ 3.3.2 Sprint Review

**Objective:** Demonstrate working software and gather stakeholder feedback.

**Responsible:** Product Owner  
**Participants:** Stakeholders, Entire Team  
**Time Estimate:** 1-2 hours

**Instructions:**
1. Review sprint goal achievement
2. Demo completed functionality
3. Gather stakeholder feedback
4. Discuss upcoming priorities
5. Celebrate successes

**Review Agenda:**
- [ ] Sprint goal recap (5 min)
- [ ] Metrics overview (5 min)
- [ ] Demo completed stories (45 min)
- [ ] Gather feedback (20 min)
- [ ] Preview next sprint (10 min)
- [ ] Q&A session (15 min)

**Feedback to Capture:**
- [ ] Feature satisfaction
- [ ] Usability concerns
- [ ] New requirements
- [ ] Priority changes
- [ ] Bug reports

**Notes/Issues:**
_________________________________
_________________________________

---

### ✅ 3.3.3 Sprint Metrics Review

**Objective:** Measure sprint performance and identify trends.

**Responsible:** Scrum Master  
**Participants:** Team  
**Time Estimate:** 30 minutes

**Instructions:**
1. Calculate velocity
2. Review burndown chart
3. Analyze cycle time
4. Check quality metrics
5. Identify trends

**Metrics to Calculate:**
- [ ] Planned vs. Actual velocity: ____ / ____
- [ ] Sprint commitment met: _____%
- [ ] Stories completed: ____ / ____
- [ ] Defects found: ____
- [ ] Defects fixed: ____
- [ ] Test coverage: _____%
- [ ] Build success rate: _____%
- [ ] Average cycle time: ____ days

**Trend Analysis:**
- [ ] Velocity trend: ↑ ↓ →
- [ ] Quality trend: ↑ ↓ →
- [ ] Team satisfaction: ↑ ↓ →

**Notes/Issues:**
_________________________________
_________________________________

---

### ✅ 3.3.4 Sprint Retrospective

**Objective:** Improve team process through reflection and action planning.

**Responsible:** Scrum Master  
**Participants:** Entire Team (no observers)  
**Time Estimate:** 90 minutes

**Instructions:**
1. Create safe environment
2. Gather team feedback
3. Identify improvement areas
4. Create specific action items
5. Assign owners and deadlines

**Retrospective Format:**
- [ ] Set the stage (10 min)
- [ ] Gather data (20 min)
- [ ] Generate insights (20 min)
- [ ] Decide actions (20 min)
- [ ] Close retrospective (20 min)

**Discussion Topics:**
- [ ] What went well?
- [ ] What didn't go well?
- [ ] What puzzled us?
- [ ] Team health check
- [ ] Process improvements

**Action Items:**
1. Action: _________________ Owner: _______ Due: _______
2. Action: _________________ Owner: _______ Due: _______
3. Action: _________________ Owner: _______ Due: _______

**Notes/Issues:**
_________________________________
_________________________________

---

## Sprint Completion Checklist

### Sprint Goals
- [ ] Sprint goal achieved: Yes / No / Partial
- [ ] All committed stories completed
- [ ] No carried over work (or justified)

### Quality Metrics
- [ ] Code coverage maintained above: _____%
- [ ] All tests passing
- [ ] No critical bugs in production
- [ ] Technical debt addressed as planned

### Process Health
- [ ] All ceremonies conducted
- [ ] Daily standups effective
- [ ] Impediments resolved quickly
- [ ] Team morale positive

### Stakeholder Satisfaction
- [ ] Demo feedback positive
- [ ] No major concerns raised
- [ ] Priorities confirmed for next sprint

---

## Sprint Summary

**Velocity Achieved:** _____ points  
**Stories Completed:** _____ / _____  
**Team Satisfaction:** _____ / 10  

**Key Achievements:**
_________________________________
_________________________________

**Carried Over Items:**
_________________________________
_________________________________

**Retrospective Actions for Next Sprint:**
_________________________________
_________________________________

**Sprint Completion Date:** _______________  
**Scrum Master Signature:** ________________  
**Product Owner Signature:** ________________