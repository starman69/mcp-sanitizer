#!/bin/bash

# Script to remove Co-Authored-By lines from commits
# This will rewrite the last 13 commits on the current branch

echo "Removing Co-Authored-By lines from commits..."

# Use git filter-branch to remove the Co-Authored-By lines
git filter-branch -f --msg-filter '
    sed "/Co-Authored-By: Claude/d; /🤖 Generated with Claude Code/d"
' HEAD~13..HEAD

echo "Done! Co-Authored-By lines have been removed."
echo "Note: This rewrites history. You'll need to force push if you've already pushed."