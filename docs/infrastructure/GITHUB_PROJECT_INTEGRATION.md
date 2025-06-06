# Linking Commits to GitHub Projects

This guide explains how to automatically link commits, pull requests, and issues to your GitHub Project board.

## Overview

GitHub Projects (v2) can automatically track work through various linking methods:

```
Commits → Issues → Project Items
   ↓        ↓          ↓
  PRs → Auto-link → Automation
```

## Method 1: Issue-Based Linking (Recommended)

### Step 1: Reference Issues in Commits

Always reference an issue number in your commits:

```bash
# In commit message
git commit -m "feat: implement storage VFS (#15)"
git commit -m "fix: memory leak in P2P module, closes #23"
git commit -m "docs: update API documentation (refs #8)"
```

### Keywords that Auto-Close Issues:
- `fixes #123`
- `closes #123`
- `resolves #123`
- `fix #123`
- `close #123`
- `resolve #123`

### Step 2: Ensure Issues are in Project

Add all issues to your project:

```bash
# Using GitHub CLI
gh issue list --limit 100 | while read issue; do
  issue_number=$(echo $issue | awk '{print $1}')
  gh api graphql -f query='
    mutation($project: ID!, $item: ID!) {
      addProjectV2ItemById(input: {projectId: $project, contentId: $item}) {
        item { id }
      }
    }
  ' -f project="PVT_kwDOBqH4Zc4AK5Xj" -f item="$issue_number"
done
```

### Step 3: Configure Auto-Add Workflow

Create `.github/workflows/project-automation.yml`:

```yaml
name: Project Automation

on:
  issues:
    types: [opened, reopened]
  pull_request:
    types: [opened, reopened, ready_for_review]

jobs:
  add-to-project:
    name: Add to project
    runs-on: ubuntu-latest
    steps:
      - uses: actions/add-to-project@v0.5.0
        with:
          project-url: https://github.com/orgs/blackholenetwork/projects/2
          github-token: ${{ secrets.PROJECT_TOKEN }}
```

## Method 2: Pull Request Linking

### Automatic PR Creation with Issue Link

```bash
# Create PR that links to issue
gh pr create --title "Implement storage VFS" --body "Closes #15"

# Or in PR description
## Description
This PR implements the storage VFS module.

Closes #15
Related to #16, #17
```

### Branch Naming Convention

Use issue numbers in branch names:

```bash
git checkout -b 15-storage-vfs
git checkout -b fix/23-memory-leak
git checkout -b feature/8-api-docs
```

## Method 3: Commit-to-Project Automation

### Custom GitHub Action

Create `.github/workflows/link-commits.yml`:

```yaml
name: Link Commits to Project

on:
  push:
    branches: [main, develop]

jobs:
  link-commits:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Link Commits to Project
        uses: actions/github-script@v7
        with:
          github-token: ${{ secrets.PROJECT_TOKEN }}
          script: |
            const commits = context.payload.commits;
            const projectId = 'PVT_kwDOBqH4Zc4AK5Xj';
            
            for (const commit of commits) {
              // Extract issue numbers from commit message
              const issueMatches = commit.message.matchAll(/#(\d+)/g);
              
              for (const match of issueMatches) {
                const issueNumber = match[1];
                
                try {
                  // Get issue node ID
                  const issue = await github.rest.issues.get({
                    owner: context.repo.owner,
                    repo: context.repo.repo,
                    issue_number: issueNumber
                  });
                  
                  // Add to project if not already there
                  await github.graphql(`
                    mutation($project: ID!, $item: ID!) {
                      addProjectV2ItemById(input: {
                        projectId: $project,
                        contentId: $item
                      }) {
                        item { id }
                      }
                    }
                  `, {
                    project: projectId,
                    item: issue.data.node_id
                  });
                  
                  console.log(`Linked issue #${issueNumber} to project`);
                } catch (error) {
                  console.log(`Could not link issue #${issueNumber}: ${error.message}`);
                }
              }
            }
```

## Method 4: Conventional Commits Integration

### Setup Commitizen

```bash
npm install -g commitizen
npm install -g cz-conventional-changelog

# In your repo
echo '{ "path": "cz-conventional-changelog" }' > .czrc
```

### Commit with Automatic Formatting

```bash
git add .
git cz
# Follow prompts, add issue number when asked
```

### Parse Commits for Automation

```yaml
- name: Parse Conventional Commits
  run: |
    # Get commit message
    MSG=$(git log -1 --pretty=%B)
    
    # Extract issue number from footer
    ISSUE=$(echo "$MSG" | grep -E "(Closes|Fixes|Resolves) #[0-9]+" | grep -oE "#[0-9]+" | tr -d '#')
    
    if [ ! -z "$ISSUE" ]; then
      gh api graphql -f query='
        mutation($project: ID!, $issue: Int!) {
          addProjectV2ItemByNodeId(input: {
            projectId: $project,
            contentId: "Issue_$issue"
          }) {
            item { id }
          }
        }
      ' -f project="${{ env.PROJECT_ID }}" -f issue="$ISSUE"
    fi
```

## Method 5: Git Hooks for Local Enforcement

### Install prepare-commit-msg Hook

Create `.githooks/prepare-commit-msg`:

```bash
#!/bin/bash
# Automatically append issue number from branch name

BRANCH=$(git symbolic-ref --short HEAD)
ISSUE=$(echo "$BRANCH" | grep -oE '^[0-9]+' || echo "$BRANCH" | grep -oE '#[0-9]+' | tr -d '#')

if [ ! -z "$ISSUE" ] && ! grep -q "#$ISSUE" "$1"; then
  echo "" >> "$1"
  echo "Refs #$ISSUE" >> "$1"
fi
```

### Enable Git Hooks

```bash
git config core.hooksPath .githooks
chmod +x .githooks/prepare-commit-msg
```

## Method 6: Project Board Automation

### Configure Built-in Automations

1. Go to your project settings
2. Enable these workflows:
   - **Item added to project** → Set status to "Todo"
   - **Pull request merged** → Set status to "Done"
   - **Issue closed** → Set status to "Done"

### Custom Automation Rules

```yaml
name: Project Card Automation

on:
  issues:
    types: [assigned, unassigned, labeled, unlabeled]
  pull_request:
    types: [review_requested, review_request_removed]

jobs:
  update-project:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            const project_id = 'PVT_kwDOBqH4Zc4AK5Xj';
            
            // Move to "In Progress" when assigned
            if (context.payload.action === 'assigned') {
              // Update project item status
            }
            
            // Move to "Review" when PR review requested
            if (context.payload.action === 'review_requested') {
              // Update project item status
            }
```

## Best Practices

### 1. Commit Message Template

Create `.gitmessage`:

```
# <type>(<scope>): <subject>
#
# <body>
#
# Refs: #
# Closes: #
```

Configure Git to use it:
```bash
git config commit.template .gitmessage
```

### 2. Branch Protection Rules

Require issue references in PRs:

1. Go to Settings → Branches
2. Add rule for `main`
3. Enable "Require pull request reviews"
4. Add status check: "PR must reference an issue"

### 3. Issue Templates

Create `.github/ISSUE_TEMPLATE/feature.yml`:

```yaml
name: Feature Request
description: Suggest a new feature
title: "[Feature]: "
labels: ["enhancement"]
projects: ["blackholenetwork/2"]
body:
  - type: textarea
    id: description
    attributes:
      label: Feature Description
      description: Clear description of the feature
    validations:
      required: true
```

### 4. PR Template

Create `.github/pull_request_template.md`:

```markdown
## Description
Brief description of changes

## Related Issues
Closes #
Refs #

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] New tests added
- [ ] Documentation updated
```

## Viewing Commit History in Project

### GraphQL Query to Get Linked Commits

```graphql
query($projectId: ID!, $itemId: ID!) {
  node(id: $projectId) {
    ... on ProjectV2 {
      items(first: 100) {
        nodes {
          id
          content {
            ... on Issue {
              number
              title
              timelineItems(first: 100, itemTypes: [CROSS_REFERENCED_EVENT]) {
                nodes {
                  ... on CrossReferencedEvent {
                    source {
                      ... on PullRequest {
                        commits(first: 100) {
                          nodes {
                            commit {
                              message
                              committedDate
                              author {
                                name
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

## Automation Scripts

### Link All Historical Commits

```bash
#!/bin/bash
# link-historical-commits.sh

PROJECT_ID="PVT_kwDOBqH4Zc4AK5Xj"

# Get all commits with issue references
git log --pretty=format:"%H %s" | grep -E "#[0-9]+" | while read commit; do
  hash=$(echo $commit | awk '{print $1}')
  message=$(echo $commit | cut -d' ' -f2-)
  
  # Extract issue numbers
  issues=$(echo $message | grep -oE "#[0-9]+" | tr -d '#')
  
  for issue in $issues; do
    echo "Linking commit $hash to issue #$issue"
    
    gh api graphql -f query='
      mutation($project: ID!, $issue: Int!, $org: String!, $repo: String!) {
        addProjectV2ItemById(input: {
          projectId: $project,
          contentId: $issue
        }) {
          item { id }
        }
      }
    ' -f project="$PROJECT_ID" \
      -f issue="$issue" \
      -f org="blackholenetwork" \
      -f repo="blackhole"
  done
done
```

## Recommended Setup for Your Project

1. **Use Issue-Based Development**
   - Create issues for all work
   - Add issues to project board
   - Reference issues in commits

2. **Enable Automation**
   - Add the `project-automation.yml` workflow
   - Configure branch protection
   - Use PR templates

3. **Commit Convention**
   ```bash
   git commit -m "feat(storage): implement VFS module (#15)"
   git commit -m "fix(p2p): resolve connection timeout, closes #23"
   ```

4. **Review Process**
   - PRs automatically added to project
   - Status updates on merge
   - Issue auto-closes with PR

This setup ensures complete traceability from commits → PRs → issues → project items.