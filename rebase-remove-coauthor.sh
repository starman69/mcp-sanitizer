#!/bin/bash

# This script creates a rebase sequence that removes Co-Authored-By lines

echo "Creating rebase sequence to remove Co-Authored-By lines..."

# Create a rebase todo list
git rebase -i HEAD~13 --exec 'git commit --amend -m "$(git log --format=%B -n1 HEAD | grep -v "Co-Authored-By: Claude" | grep -v "🤖 Generated with Claude Code")"'

echo "Rebase complete!"