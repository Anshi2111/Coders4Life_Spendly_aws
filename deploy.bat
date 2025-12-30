@echo off
echo 🚀 Preparing Spendly for deployment...

REM Check if git is initialized
if not exist ".git" (
    echo 📝 Initializing Git repository...
    git init
)

REM Add all files
echo 📦 Adding files to Git...
git add .

REM Commit changes
echo 💾 Committing changes...
set /p commit_msg="Enter commit message (or press Enter for default): "
if "%commit_msg%"=="" set commit_msg=Deploy: Spendly payment API app ready for production
git commit -m "%commit_msg%"

REM Check if remote exists
git remote get-url origin >nul 2>&1
if errorlevel 1 (
    echo 🔗 Setting up GitHub remote...
    set /p repo_url="Enter your GitHub repository URL: "
    git remote add origin "%repo_url%"
)

REM Push to GitHub
echo ⬆️ Pushing to GitHub...
git branch -M main
git push -u origin main

echo ✅ Deployment preparation complete!
echo.
echo Next steps:
echo 1. Go to https://dashboard.render.com
echo 2. Click 'New' → 'Blueprint'
echo 3. Connect your GitHub repository
echo 4. Render will automatically deploy using render.yaml
echo.
echo Your app will be available at:
echo - Frontend: https://spendly-frontend.onrender.com
echo - Backend API: https://spendly-api.onrender.com
echo.
echo 🎉 Happy deploying!
pause