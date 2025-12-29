Deployment checklist for DataSell

1) Set Render environment variables

- In your Render service settings, add the following environment variable:

  - `BASE_URL` = `https://datasell.onrender.com`

- Ensure other required env vars are set (Firebase service account fields, `PAYSTACK_SECRET_KEY`, `HUBNET_API_KEY`, `SESSION_SECRET`, etc.). The server will exit at startup if required env vars are missing.

2) NODE_ENV

- For production, set `NODE_ENV=production` in Render to enable production cookie security and stricter domain checks.

3) APK download serving

- The app exposes a lightweight client config at `/config.js`. This sets `window.__BASE_URL` and `window.__APK_URL` so static pages can read the runtime `BASE_URL` without rebuilding the frontend.

4) Restart the service

- After updating env vars, restart your Render service from the Render dashboard or via the CLI.

5) Quick local test (optional)

- If you want to test locally (you said you'll run commands yourself), set a local `.env` with the same `BASE_URL` and run:

```bash
npm install
npm start
```

Then open `http://localhost:3000` and verify the site loads and the install/download flow points to `https://datasell.onrender.com/downloads/datasell-debug.apk` (or the `__APK_URL` provided by `/config.js`).

6) Notes

- The server already includes `datasell.onrender.com` in its CORS allow-list. If you use a different domain, update the `allowedDomains` array in `server.js` or set the `BASE_URL` accordingly.
- Consider precomputing the APK checksum during your build pipeline and embedding it into `public/download.html` to avoid client-side hashing for large APKs.

If you want, I can add a small Render `service.yaml` snippet or CI workflow to compute the checksum and copy the APK into `public/downloads` automatically.sk_live_1e391b5e1279118463aad86963eae9c172015c3c
PAYSTACK_PUBLIC_KEY=pk_live_1ab0cbfd78adf80ea97911b53ca1bbfaee891316