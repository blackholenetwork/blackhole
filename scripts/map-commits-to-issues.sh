#!/bin/bash

# Map existing commits to issues based on content matching
# This helps retroactively link commits to their relevant issues

PROJECT_NUMBER=2
ORG="blackholenetwork"

echo "🔍 Mapping Commits to Issues Based on Content"
echo "============================================="
echo ""

# Get all issues with their titles
echo "Fetching all issues..."
gh issue list --limit 100 --json number,title,state | jq -r '.[] | "\(.number)|\(.title)"' >/tmp/issues.txt

# Analyze commits and suggest issue links
echo ""
echo "Analyzing commits for potential issue matches..."
echo ""

git log --pretty=format:"%H|%ad|%s" --date=short | while IFS='|' read -r hash date message; do
  # Skip if already has issue reference
  if echo "$message" | grep -qE '#[0-9]+'; then
    continue
  fi

  # Look for potential matches
  matches=""

  # Check each issue
  while IFS='|' read -r issue_num issue_title; do
    # Extract keywords from issue title
    keywords=$(echo "$issue_title" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9 ]//g' | sed 's/  */ /g')

    # Check if commit message contains issue keywords
    message_lower=$(echo "$message" | tr '[:upper:]' '[:lower:]')

    # Special pattern matching
    case "$issue_title" in
    *"Orchestrator"*)
      if echo "$message_lower" | grep -qE 'orchestrat|lifecycle'; then
        matches="$matches $issue_num"
      fi
      ;;
    *"P2P Networking"*)
      if echo "$message_lower" | grep -qE 'p2p|network|libp2p|peer'; then
        matches="$matches $issue_num"
      fi
      ;;
    *"Security"*)
      if echo "$message_lower" | grep -qE 'security|auth|did|identity'; then
        matches="$matches $issue_num"
      fi
      ;;
    *"Resource Manager"*)
      if echo "$message_lower" | grep -qE 'resource|manager|allocation'; then
        matches="$matches $issue_num"
      fi
      ;;
    *"Monitoring"*)
      if echo "$message_lower" | grep -qE 'monitor|metric|analytic|health'; then
        matches="$matches $issue_num"
      fi
      ;;
    *"WebServer"*)
      if echo "$message_lower" | grep -qE 'web|server|http|api|dashboard'; then
        matches="$matches $issue_num"
      fi
      ;;
    *"Plugin"*)
      if echo "$message_lower" | grep -qE 'plugin|architecture|system'; then
        matches="$matches $issue_num"
      fi
      ;;
    esac
  done </tmp/issues.txt

  if [ ! -z "$matches" ]; then
    echo "📝 Commit: ${hash:0:7} - $message"
    echo "   Date: $date"
    echo "   Potential issues:$matches"
    echo ""
  fi
done

echo ""
echo "🔗 To link these commits, you can:"
echo "1. Create a new branch"
echo "2. Use interactive rebase to amend commit messages:"
echo "   git rebase -i HEAD~20"
echo "3. Add issue references to commit messages"
echo ""
echo "Or create new commits that reference the issues:"
echo "git commit --allow-empty -m \"chore: link previous work to issues\""
echo ""

# Clean up
rm -f /tmp/issues.txt
