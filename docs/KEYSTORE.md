# Keystore creation and encoding for GitHub Actions

This repository's Android release workflow expects the signing keystore to be provided via repository secrets. Follow these steps locally and then add the secrets to GitHub (Settings → Secrets → Actions).

1) Generate a signing keystore (if you don't already have one):

```bash
keytool -genkey -v -keystore my-release-key.jks -keyalg RSA -keysize 2048 -validity 10000 -alias my-key-alias
```

2) Create a base64-encoded single-line representation of the keystore. This is safe to paste into the `ANDROID_KEYSTORE_BASE64` secret.

```bash
# macOS / Linux
base64 -w0 my-release-key.jks > my-release-key.jks.b64
# Windows (PowerShell)
# [Convert]::ToBase64String([IO.File]::ReadAllBytes('my-release-key.jks')) | Out-File -Encoding ASCII my-release-key.jks.b64
```

3) Add the following repository secrets (GitHub → Settings → Secrets → Actions):

- `ANDROID_KEYSTORE_BASE64` — copy the contents of `my-release-key.jks.b64` (the single-line base64 string)
- `ANDROID_KEYSTORE_PASSWORD` — the keystore password you entered when creating the keystore
- `ANDROID_KEY_ALIAS` — the alias (e.g. `my-key-alias`)
- `ANDROID_KEY_PASSWORD` — the key password (often same as keystore password)

After these secrets are set, the `android-build.yml` workflow will sign the release APK and upload it as a GitHub Release asset.

Notes
- Keep your keystore and passwords private. Do not commit the binary keystore file into the repository.
- If you rotate the keystore, update the secret with the new base64 blob.
- If you prefer not to use base64, you can upload the keystore to a trusted secret manager and adapt the workflow accordingly.
