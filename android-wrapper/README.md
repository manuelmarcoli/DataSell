# DataSell Android Wrapper (Cordova)

This folder contains a minimal Cordova app template to wrap your DataSell website into an Android APK. The app is configured to load a remote website (your deployed Render URL). This is a lightweight approach that uses a WebView inside a native shell.

IMPORTANT: Building an APK requires the Android build toolchain (Android SDK, Java JDK) and Cordova. This repository does not include the Android SDK — you must install it on your machine or build server.

---

Quick overview

- `config.xml` — Cordova config. Set the `<content src="https://REPLACE_WITH_YOUR_RENDER_URL/" />` to your deployed front-end URL (the URL you will host on Render).
- `www/index.html` — A fallback page that will redirect to the remote site if necessary.
- `build-apk.sh` — A helper script to run a Cordova debug build (assumes Cordova CLI is installed).
- `www/index.html` contains a splash animation that uses your site's `images/web-logo2.png` and shows a loading progress before redirecting to the site.

Icon notes:
- The build script will attempt to copy `public/images/web-logo2.png` into `android-wrapper/www/images/` and create resized icon fallbacks. If you want crisp icons, replace the generated files with properly sized PNGs: `web-logo2-36.png`, `web-logo2-48.png`, `web-logo2-72.png`, `web-logo2-96.png`.
- If ImageMagick is available (`convert`), the build script will create resized icons automatically.

Step-by-step: Build a debug APK (local)

1. Install prerequisites

- Java JDK 11+ (or as required by Android Gradle plugin)
- Android SDK + platform-tools + build-tools (install via `sdkmanager`)
- Node.js (16+ recommended) and npm
- Cordova CLI globally: `npm install -g cordova`

Set `ANDROID_HOME` or `ANDROID_SDK_ROOT` to your SDK path and add platform-tools to your PATH.

2. Configure the remote URL

Open `android-wrapper/config.xml` and replace the `content` URL:

```xml
<content src="index.html" />
```

or edit `www/index.html` and set `remote` variable.

Note: The wrapper now bundles the `public/` site into `www/app/` during the build so the app can run offline. The default `www/index.html` will try the remote site first; if it's unreachable it will load the bundled `app/index.html` (offline). The build script copies `public/` into `www/app/`.

3. Build the app

From the `android-wrapper` folder run:

```bash
# make script executable once
chmod +x build-apk.sh

# then
./build-apk.sh
```

Or manually:

```bash
cordova platform add android
cordova build android --debug
```

After a successful build the debug APK will be at:

`platforms/android/app/build/outputs/apk/debug/app-debug.apk`

4. Test on device

- Copy the APK to a device or install via `adb install -r path/to/app-debug.apk`.
- Open the app; it should load your deployed site.

Release build and signing

To produce a signed release APK:

1. Generate a keystore (if you don't have one):

```bash
keytool -genkeypair -v -keystore my-release-key.keystore -alias datasell-key -keyalg RSA -keysize 2048 -validity 10000
```

2. Build release APK

```bash
cordova build android --release
```

3. Sign the APK (example using apksigner included in Android SDK build-tools):

```bash
# align is optional depending on Gradle plugin
jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 -keystore my-release-key.keystore platforms/android/app/build/outputs/apk/release/app-release-unsigned.apk datasell-key

# or use apksigner
apksigner sign --ks my-release-key.keystore --out app-release-signed.apk platforms/android/app/build/outputs/apk/release/app-release-unsigned.apk
```

4. Verify:

```bash
apksigner verify app-release-signed.apk
```

Notes, security & features

- This wrapper loads your website inside a native WebView. Any cross-origin resources and API calls must be accessible from the device (CORS, server SSL certificate, etc.).
- For better UX and integration consider using Capacitor or a Trusted Web Activity (TWA) which provide improved performance and PWAs capabilities. Capacitor also provides a modern integration with native plugins.
- If your site requires authentication cookies, confirm your backend sets cookies with appropriate `SameSite=None; Secure` flags so they work in the WebView.

Need help?
- If you want, I can scaffold a Capacitor-based project instead (preferred for modern apps and PWAs) and provide Android Studio instructions.
- Or I can add basic splash icons and a simple native permission handler.

