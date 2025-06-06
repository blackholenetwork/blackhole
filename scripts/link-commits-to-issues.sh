#!/bin/bash

# Link past commits to GitHub issues via commit messages
# This script finds issue references in commits and ensures those issues are in the project

PROJECT_NUMBER=2
ORG="blackholenetwork"

echo "🔗 Linking commits to issues in GitHub Project #${PROJECT_NUMBER}"
echo "================================================"

# Get the project ID
echo "Fetching project ID..."
PROJECT_ID=$(gh api graphql -f query='
  query($org: String!, $number: Int!) {
    organization(login: $org) {
      projectV2(number: $number) {
        id
      }
    }
  }' -f org="$ORG" -F number="$PROJECT_NUMBER" --jq '.data.organization.projectV2.id')

if [ -z "$PROJECT_ID" ]; then
  echo "❌ Error: Could not find project #${PROJECT_NUMBER}"
  exit 1
fi

echo "✅ Found project ID: $PROJECT_ID"
echo ""

# Get all commits that reference issues
echo "Analyzing commit history for issue references..."
echo ""

# Find all commits with issue references
git log --oneline --all | grep -E '(#[0-9]+|Refs)' | while IFS= read -r line; do
  commit_hash=$(echo "$line" | awk '{print $1}')
  commit_msg=$(echo "$line" | cut -d' ' -f2-)

  # Extract all issue numbers from commit message (supports both #123 and Refs #123 format)
  issue_numbers=$(echo "$commit_msg" | grep -oE '(#[0-9]+|Refs #[0-9]+)' | grep -oE '[0-9]+' | sort -u)

  if [ -z "$issue_numbers" ]; then
    continue
  fi

  for issue_num in $issue_numbers; do
    echo "📝 Commit: $commit_hash references issue #$issue_num"
    echo "   Message: $commit_msg"

    # Check if issue exists
    issue_state=$(gh issue view "$issue_num" --json state --jq '.state' 2>/dev/null)

    if [ -z "$issue_state" ]; then
      echo "   ⚠️  Issue #$issue_num not found in repository"
      echo ""
      continue
    fi

    echo "   ✓ Issue #$issue_num exists (state: $issue_state)"

    # Get issue node ID
    issue_node_id=$(gh issue view "$issue_num" --json id --jq '.id')

    # Check if issue is already in project
    is_in_project=$(gh api graphql -f query='
      query($id: ID!) {
        node(id: $id) {
          ... on Issue {
            projectItems(first: 100) {
              nodes {
                project {
                  id
                }
              }
            }
          }
        }
      }' -f id="$issue_node_id" --jq ".data.node.projectItems.nodes[] | select(.project.id == \"$PROJECT_ID\") | .project.id" 2>/dev/null)

    if [ ! -z "$is_in_project" ]; then
      echo "   ✓ Issue #$issue_num is already in the project"
    else
      echo "   → Adding issue #$issue_num to project..."

      # Add issue to project
      result=$(gh api graphql -f query='
        mutation($project: ID!, $content: ID!) {
          addProjectV2ItemById(input: {projectId: $project, contentId: $content}) {
            item {
              id
            }
          }
        }' -f project="$PROJECT_ID" -f content="$issue_node_id" 2>&1)

      if [ $? -eq 0 ]; then
        echo "   ✅ Successfully added issue #$issue_num to project"
      else
        echo "   ❌ Failed to add issue #$issue_num: $result"
      fi
    fi

    echo ""
  done
done

echo "================================================"
echo "✨ Commit linking complete!"
echo ""
echo "📊 Summary of actions:"
echo "- Analyzed all commits for issue references"
echo "- Ensured referenced issues are in the project"
echo ""
echo "💡 Tips for future commits:"
echo "1. Always reference issues: 'git commit -m \"feat: add feature (#123)\"'"
echo "2. Use closing keywords: 'fixes #123', 'closes #123', 'resolves #123'"
echo "3. Create issues before starting work"
