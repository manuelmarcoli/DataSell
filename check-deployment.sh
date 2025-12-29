#!/bin/bash
# Pre-deployment verification script for Render

echo "🔍 Checking DataSell deployment readiness..."
echo ""

# Check for required files
echo "📋 Checking required files..."
required_files=("server.js" "package.json" "render.yaml" ".gitignore" ".env.example")
missing_files=()

for file in "${required_files[@]}"; do
  if [ ! -f "$file" ]; then
    missing_files+=("$file")
    echo "  ❌ Missing: $file"
  else
    echo "  ✅ Found: $file"
  fi
done

echo ""
echo "📦 Checking package.json structure..."
if grep -q '"start"' package.json; then
  echo "  ✅ Start script defined"
else
  echo "  ❌ Start script not found in package.json"
fi

if grep -q '"engines"' package.json; then
  echo "  ✅ Node.js version specified"
else
  echo "  ⚠️  Warning: Node.js version not specified in engines"
fi

echo ""
echo "🔐 Checking .gitignore..."
if grep -q "^node_modules/" .gitignore; then
  echo "  ✅ node_modules excluded"
else
  echo "  ❌ node_modules not properly excluded"
fi

if grep -q "^\.env" .gitignore; then
  echo "  ✅ .env files excluded"
else
  echo "  ❌ .env files not properly excluded"
fi

echo ""
echo "🔧 Checking render.yaml..."
if grep -q "startCommand: node server.js" render.yaml; then
  echo "  ✅ Start command configured"
else
  echo "  ❌ Start command not properly configured"
fi

if grep -q "healthCheckPath:" render.yaml; then
  echo "  ✅ Health check configured"
else
  echo "  ⚠️  Warning: Health check not configured"
fi

echo ""
echo "🌐 Checking server.js configuration..."
if grep -q "app.listen" server.js; then
  echo "  ✅ Server listening configured"
else
  echo "  ❌ Server listening not found"
fi

if grep -q "trust proxy" server.js; then
  echo "  ✅ Reverse proxy configured (for Render)"
else
  echo "  ⚠️  Warning: Trust proxy not configured"
fi

echo ""
echo "📝 Environment variables checklist:"
echo "  Make sure to set these in Render dashboard:"
echo "  - NODE_ENV = production"
echo "  - PORT = 3000"
echo "  - Firebase variables (API_KEY, PROJECT_ID, etc.)"
echo "  - ADMIN_EMAIL and ADMIN_PASSWORD"
echo "  - SESSION_SECRET (use secure random string)"
echo "  - Payment gateway keys (Paystack, mNotify)"
echo "  - DOMAIN = your-render-url"

echo ""
if [ ${#missing_files[@]} -eq 0 ]; then
  echo "✅ All required files present!"
  echo "✅ Ready for Render deployment!"
  exit 0
else
  echo "❌ Missing files detected. Please fix before deploying."
  exit 1
fi
