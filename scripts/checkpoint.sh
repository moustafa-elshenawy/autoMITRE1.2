#!/bin/bash
# autoMITRE Checkpoint Script
# Automatically stage, commit, and push changes to the repository.

set -e

# Change to the root of the repository
cd "$(dirname "$0")/.."

# Check if there are changes
if [ -z "$(git status --porcelain)" ]; then
  echo "No changes to commit."
  exit 0
fi

# Set commit message
MESSAGE=$1
if [ -z "$MESSAGE" ]; then
  MESSAGE="Auto-checkpoint: Changes made on $(date '+%Y-%m-%d %H:%M:%S')"
fi

echo "--- Committing changes ---"
git add .
git commit -m "$MESSAGE"

echo "--- Pushing to origin ---"
git push origin main

echo "--- Checkpoint successful ---"
