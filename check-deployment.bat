@echo off
REM Pre-deployment verification script for Render (Windows)

echo.
echo 🔍 Checking DataSell deployment readiness...
echo.

setlocal enabledelayedexpansion
set "missing=0"

REM Check for required files
echo 📋 Checking required files...
for %%F in (server.js package.json render.yaml .gitignore .env.example) do (
  if exist %%F (
    echo   ✅ Found: %%F
  ) else (
    echo   ❌ Missing: %%F
    set /a missing=missing+1
  )
)

echo.
echo 📦 Checking package.json structure...
findstr /M "\"start\"" package.json > nul
if !errorlevel! equ 0 (
  echo   ✅ Start script defined
) else (
  echo   ❌ Start script not found
)

findstr /M "\"engines\"" package.json > nul
if !errorlevel! equ 0 (
  echo   ✅ Node.js version specified
) else (
  echo   ⚠️  Warning: Node.js version not specified
)

echo.
echo 🔐 Checking .gitignore...
findstr /M "^node_modules/" .gitignore > nul
if !errorlevel! equ 0 (
  echo   ✅ node_modules excluded
) else (
  echo   ❌ node_modules not excluded
)

findstr /M "^.env" .gitignore > nul
if !errorlevel! equ 0 (
  echo   ✅ .env files excluded
) else (
  echo   ❌ .env files not excluded
)

echo.
echo 🔧 Checking render.yaml...
findstr /M "startCommand: node server.js" render.yaml > nul
if !errorlevel! equ 0 (
  echo   ✅ Start command configured
) else (
  echo   ❌ Start command not configured
)

echo.
echo 🌐 Checking server.js configuration...
findstr /M "app.listen" server.js > nul
if !errorlevel! equ 0 (
  echo   ✅ Server listening configured
) else (
  echo   ❌ Server listening not found
)

findstr /M "trust proxy" server.js > nul
if !errorlevel! equ 0 (
  echo   ✅ Reverse proxy configured
) else (
  echo   ⚠️  Warning: Trust proxy not configured
)

echo.
echo 📝 Environment variables checklist:
echo   Make sure to set these in Render dashboard:
echo   - NODE_ENV = production
echo   - PORT = 3000
echo   - Firebase variables
echo   - ADMIN_EMAIL and ADMIN_PASSWORD
echo   - SESSION_SECRET
echo   - Payment gateway keys
echo   - DOMAIN = your-render-url

echo.
if !missing! equ 0 (
  echo ✅ All required files present!
  echo ✅ Ready for Render deployment!
  exit /b 0
) else (
  echo ❌ Missing files detected. Please fix before deploying.
  exit /b 1
)
