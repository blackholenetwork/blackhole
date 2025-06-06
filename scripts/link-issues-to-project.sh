#!/bin/bash

# Link issues referenced in commits to GitHub Project
# Checks both commit subject and body for issue references

PROJECT_NUMBER=2
ORG="blackholenetwork"

echo "🔗 Linking Issues from Commits to GitHub Project #${PROJECT_NUMBER}"
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

# Track processed issues
processed_issues=()

# Function to add issue to project
add_issue_to_project() {
  local issue_num=$1
  
  # Check if already processed
  for processed in "${processed_issues[@]}"; do
    if [ "$processed" = "$issue_num" ]; then
      return
    fi
  done
  
  processed_issues+=("$issue_num")
  
  echo "📝 Processing issue #$issue_num"
  
  # Check if issue exists
  issue_state=$(gh issue view "$issue_num" --json state --jq '.state' 2>/dev/null)
  
  if [ -z "$issue_state" ]; then
    echo "   ⚠️  Issue #$issue_num not found in repository"
    return
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
}

# Get all commits and check full message for issue references
echo "Analyzing commit history for issue references..."
echo ""

# Get recent commits with full messages
git log --pretty=format:"COMMIT_START%n%H%n%B%nCOMMIT_END" -50 | while IFS= read -r line; do
  if [[ "$line" == "COMMIT_START" ]]; then
    # Read commit hash
    read -r commit_hash
    
    # Read commit message until COMMIT_END
    commit_msg=""
    while IFS= read -r msg_line && [[ "$msg_line" != "COMMIT_END" ]]; do
      commit_msg="${commit_msg}${msg_line} "
    done
    
    # Extract issue numbers from full commit message
    issue_numbers=$(echo "$commit_msg" | grep -oE '(#[0-9]+|Refs #[0-9]+|refs #[0-9]+|Closes #[0-9]+|closes #[0-9]+|Fixes #[0-9]+|fixes #[0-9]+)' | grep -oE '[0-9]+' | sort -u)
    
    if [ ! -z "$issue_numbers" ]; then
      echo "Found references in commit ${commit_hash:0:7}"
      for issue_num in $issue_numbers; do
        add_issue_to_project "$issue_num"
      done
      echo ""
    fi
  fi
done

echo "================================================"
echo "✨ Issue linking complete!"
echo ""
echo "📊 Summary:"
echo "- Analyzed last 50 commits for issue references"
echo "- Processed ${#processed_issues[@]} unique issues"
echo "- Ensured all referenced issues are in the project"
echo ""
echo "💡 View your project at:"
echo "https://github.com/orgs/blackholenetwork/projects/2"