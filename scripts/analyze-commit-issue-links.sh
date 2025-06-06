#!/bin/bash

# Analyze and report on commit-to-issue relationships
# Shows which commits reference which issues and their project status

PROJECT_NUMBER=2
ORG="blackholenetwork"
REPO="blackhole"

echo "📊 Analyzing Commit-to-Issue Relationships"
echo "========================================="
echo ""

# Get the project ID
PROJECT_ID=$(gh api graphql -f query='
  query($org: String!, $number: Int!) {
    organization(login: $org) {
      projectV2(number: $number) {
        id
      }
    }
  }' -f org="$ORG" -f number="$PROJECT_NUMBER" --jq '.data.organization.projectV2.id')

# Create a temporary file to store results
REPORT_FILE=$(mktemp)

# Headers for CSV output
echo "Commit Hash,Date,Author,Message,Issue Numbers,Issues in Project" >"$REPORT_FILE"

# Analyze commits
echo "Scanning commit history..."
git log --pretty=format:"%H|%ad|%an|%s" --date=short | while IFS='|' read -r hash date author message; do
  # Find issue references
  issue_refs=$(echo "$message" | grep -oE '#[0-9]+' | grep -oE '[0-9]+' | sort -u | tr '\n' ' ')

  if [ ! -z "$issue_refs" ]; then
    issues_in_project=""

    for issue_num in $issue_refs; do
      # Check if issue exists and is in project
      issue_data=$(gh api graphql -f query='
        query($owner: String!, $repo: String!, $number: Int!) {
          repository(owner: $owner, name: $repo) {
            issue(number: $number) {
              id
              state
              projectItems(first: 10) {
                nodes {
                  project {
                    id
                  }
                }
              }
            }
          }
        }' -f owner="$ORG" -f repo="$REPO" -f number="$issue_num" 2>/dev/null)

      if [ $? -eq 0 ]; then
        is_in_project=$(echo "$issue_data" | jq -r ".data.repository.issue.projectItems.nodes[] | select(.project.id == \"$PROJECT_ID\") | .project.id" 2>/dev/null)

        if [ ! -z "$is_in_project" ]; then
          issues_in_project="${issues_in_project}#${issue_num} "
        fi
      fi
    done

    # Add to report
    echo "${hash:0:7},$date,$author,\"$message\",\"$issue_refs\",\"$issues_in_project\"" >>"$REPORT_FILE"
  fi
done

# Display summary
echo ""
echo "📋 Commit-Issue Link Summary"
echo "============================"
echo ""

# Count statistics
total_commits_with_issues=$(tail -n +2 "$REPORT_FILE" | wc -l)
echo "Total commits with issue references: $total_commits_with_issues"
echo ""

# Show recent commits with issues
echo "Recent commits referencing issues:"
echo "---------------------------------"
tail -n +2 "$REPORT_FILE" | tail -10 | while IFS=',' read -r hash date author message issues in_project; do
  printf "%-7s %-10s %-15s %s\n" "$hash" "$date" "${author:0:15}" "$issues"
done

echo ""
echo "To add missing issues to the project, run:"
echo "./scripts/link-commits-to-issues.sh"
echo ""
echo "Full report saved to: commit-issue-report.csv"

# Save report
cp "$REPORT_FILE" commit-issue-report.csv
rm "$REPORT_FILE"
