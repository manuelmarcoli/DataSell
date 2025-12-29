#!/usr/bin/env bash
set -euo pipefail

# Simple build script to create a debug APK using Cordova.
# Requirements: Node.js, npm, Java JDK, Android SDK (ANDROID_HOME), and Cordova installed globally.
# Usage: bash build-apk.sh

# Project path (this folder)
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Working in: $ROOT_DIR"

if ! command -v cordova >/dev/null 2>&1; then
  echo "cordova CLI not found. Install with: npm install -g cordova"
  exit 1
fi

# If platforms folder doesn't exist, create a cordova project skeleton
if [ ! -d "$ROOT_DIR/platforms" ]; then
  echo "Initializing Cordova project (if not already initialized)..."
  # Create a temp cordova project structure if necessary
  if [ ! -f "$ROOT_DIR/config.xml" ]; then
    echo "config.xml missing in $ROOT_DIR. Please ensure it exists (we provided a template)."
    exit 1
  fi

  # Use cordova to create the project in-place (this will not overwrite existing files)
  # cordova requires a directory with package.json normally; instead we run cordova platform add.
  echo "Adding android platform..."
  cordova platform add android || true
fi

# Try to copy the project logo from the main repo into the wrapper so icons are available
SRC_LOGO="$ROOT_DIR/../public/images/web-logo2.png"
DEST_DIR="$ROOT_DIR/www/images"
mkdir -p "$DEST_DIR"
if [ -f "$SRC_LOGO" ]; then
  echo "Copying web-logo2.png to wrapper images..."
  cp "$SRC_LOGO" "$DEST_DIR/web-logo2.png"
  # Create fallback resized PNGs if imagemagick is available
  if command -v convert >/dev/null 2>&1; then
    echo "Resizing icon images using ImageMagick (convert)"
    convert "$DEST_DIR/web-logo2.png" -resize 36x36 "$DEST_DIR/web-logo2-36.png" || true
    convert "$DEST_DIR/web-logo2.png" -resize 48x48 "$DEST_DIR/web-logo2-48.png" || true
    convert "$DEST_DIR/web-logo2.png" -resize 72x72 "$DEST_DIR/web-logo2-72.png" || true
    convert "$DEST_DIR/web-logo2.png" -resize 96x96 "$DEST_DIR/web-logo2-96.png" || true
  else
    echo "ImageMagick not found — copied full-size logo. Please provide icon PNGs at: $DEST_DIR/web-logo2-36.png etc."
    # If ImageMagick not installed, copy the same file to the named sizes as a fallback
    cp "$DEST_DIR/web-logo2.png" "$DEST_DIR/web-logo2-36.png" || true
    cp "$DEST_DIR/web-logo2.png" "$DEST_DIR/web-logo2-48.png" || true
    cp "$DEST_DIR/web-logo2.png" "$DEST_DIR/web-logo2-72.png" || true
    cp "$DEST_DIR/web-logo2.png" "$DEST_DIR/web-logo2-96.png" || true
  fi
else
  echo "No source logo found at $SRC_LOGO — please copy your web-logo2.png into $DEST_DIR before building."
fi

# Copy the full public website into the wrapper for offline bundling
if [ -d "$ROOT_DIR/../public" ]; then
  echo "Copying public/ into wrapper as offline bundle..."
  rm -rf "$ROOT_DIR/www/app"
  mkdir -p "$ROOT_DIR/www/app"
  # Use rsync if available to preserve structure, otherwise fallback to cp
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --exclude='node_modules' --exclude='.git' "$ROOT_DIR/../public/" "$ROOT_DIR/www/app/"
  else
    cp -a "$ROOT_DIR/../public/." "$ROOT_DIR/www/app/"
  fi
else
  echo "No public/ directory found to bundle for offline mode."
fi

# Build debug APK
echo "Building debug APK... (this may take a while)"
# Use safer Gradle flags for low-memory CI/containers: avoid daemon and limit JVM heap
# Pass extra args through Cordova to Gradle. These flags reduce flaky daemon crashes in Codespaces.
CORDOVA_GRADLE_FLAGS=("--no-daemon" "-Dorg.gradle.jvmargs=-Xmx1200m -Dfile.encoding=UTF-8")

# Build with the extra Gradle flags
cordova build android --debug -- "${CORDOVA_GRADLE_FLAGS[@]}"
echo "Build finished. The debug APK will be in platforms/android/app/build/outputs/apk/debug/"

# Attempt to copy the generated debug APK into the repo `public/downloads/`
# and into the bundled wrapper offline app so `download.html` can link to it.
APK_SRC="$ROOT_DIR/platforms/android/app/build/outputs/apk/debug/app-debug.apk"
if [ -f "$APK_SRC" ]; then
  echo "Copying built APK to ../public/downloads/ and wrapper www/app/downloads/"
  mkdir -p "$ROOT_DIR/../public/downloads"
  mkdir -p "$ROOT_DIR/www/app/downloads"
  cp "$APK_SRC" "$ROOT_DIR/../public/downloads/datasell-debug.apk" || true
  cp "$APK_SRC" "$ROOT_DIR/www/app/downloads/datasell-debug.apk" || true
  echo "APK copied to public and wrapper downloads."
else
  echo "Warning: APK not found at $APK_SRC — build may have failed or the path differs."
fi
