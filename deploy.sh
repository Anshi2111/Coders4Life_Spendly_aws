#!/bin/bash

# Spendly Deployment Script
echo "🚀 Preparing Spendly for deployment..."

# Check if git is initialized
if [ ! -d ".git" ]; then
    echo "📝 Initializing Git repository..."
    git init
fi

# Add all files
echo "📦 Adding files to Git..."
git add .

# Commit changes
echo "💾 Committing changes..."
read -p "Enter commit message (or press Enter for default): " commit_msg
if [ -z "$commit_msg" ]; then
    commit_msg="Deploy: Spendly payment API app ready for production"
fi
git commit -m "$commit_msg"

# Check if remote exists
if ! git remote get-url origin > /dev/null 2>&1; then
    echo "🔗 Setting up GitHub remote..."
    read -p "Enter your GitHub repository URL: " repo_url
    git remote add origin "$repo_url"
fi

# Push to GitHub
echo "⬆️ Pushing to GitHub..."
git branch -M main
git push -u origin main

echo "✅ Deployment preparation complete!"
echo ""
echo "Next steps:"
echo "1. Go to https://dashboard.render.com"
echo "2. Click 'New' → 'Blueprint'"
echo "3. Connect your GitHub repository"
echo "4. Render will automatically deploy using render.yaml"
echo ""
echo "Your app will be available at:"
echo "- Frontend: https://spendly-frontend.onrender.com"
echo "- Backend API: https://spendly-api.onrender.com"
echo ""
echo "🎉 Happy deploying!"