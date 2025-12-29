# Render Deployment Guide

## Overview
This guide provides step-by-step instructions to deploy DataSell to Render.com.

## Prerequisites
- Render.com account
- GitHub repository with the DataSell code
- Firebase project with Admin SDK credentials
- Paystack and mNotify API keys

## Step 1: Prepare Your Repository

### 1.1 Ensure all necessary files are present:
- ✅ `render.yaml` - Render configuration file
- ✅ `Procfile` - Alternative process definition
- ✅ `package.json` - With engines specification
- ✅ `.env.example` - Environment variables template
- ✅ `.gitignore` - Proper exclusions configured
- ✅ `server.js` - Main application file

### 1.2 Verify package.json
Ensure the following are present:
```json
{
  "engines": {
    "node": "18.x",
    "npm": "9.x"
  },
  "scripts": {
    "start": "node server.js"
  }
}
```

### 1.3 Commit and push to GitHub
```bash
git add .
git commit -m "Prepare for Render deployment"
git push origin main
```

## Step 2: Create Render Web Service

### 2.1 Log in to Render Dashboard
- Go to https://dashboard.render.com
- Sign in or create an account

### 2.2 Create New Web Service
1. Click "New +" → "Web Service"
2. Select "Deploy an existing repository" or "Build and deploy from GitHub"
3. Connect your GitHub account and select the DataSell repository
4. Choose the main branch

### 2.3 Configure Service Settings
- **Name**: `datasell` (or your preferred name)
- **Environment**: `Node`
- **Build Command**: `npm install`
- **Start Command**: `node server.js`
- **Plan**: Choose appropriate plan (free or paid)

## Step 3: Set Environment Variables

### 3.1 In Render Dashboard:
1. Go to your Web Service dashboard
2. Click "Environment"
3. Add the following environment variables:

```
NODE_ENV = production
PORT = 3000

# Firebase Configuration
FIREBASE_API_KEY = [your_firebase_api_key]
FIREBASE_AUTH_DOMAIN = [your_project.firebaseapp.com]
FIREBASE_DATABASE_URL = [https://your_project-default-rtdb.firebasedatabase.app]
FIREBASE_PROJECT_ID = [your_project_id]
FIREBASE_STORAGE_BUCKET = [your_project.appspot.com]
FIREBASE_MESSAGING_SENDER_ID = [your_sender_id]
FIREBASE_APP_ID = [your_app_id]
FIREBASE_CLIENT_EMAIL = [firebase-adminsdk-xxx@your_project.iam.gserviceaccount.com]
FIREBASE_PRIVATE_KEY_ID = [your_private_key_id]
FIREBASE_PRIVATE_KEY = [-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----]

# Admin Credentials
ADMIN_EMAIL = [your_admin_email@example.com]
ADMIN_PASSWORD = [your_secure_password]

# Session Configuration
SESSION_SECRET = [generate_secure_random_string]

# Payment Gateway
PAYSTACK_PUBLIC_KEY = [your_paystack_public_key]
PAYSTACK_SECRET_KEY = [your_paystack_secret_key]
PAYSTACK_BASE_URL = https://api.paystack.co

# SMS API
MNOTIFY_API_KEY = [your_mnotify_api_key]

# Data API
DATAMART_API_KEY = [your_datamart_api_key]

# Domain Configuration
BASE_URL = [https://your-render-app-name.onrender.com]
DOMAIN = [https://your-render-app-name.onrender.com]
```

### 3.2 Important Notes:
- For FIREBASE_PRIVATE_KEY, ensure newlines are properly escaped as `\n`
- Use strong, unique passwords for ADMIN_PASSWORD
- Keep API keys and secrets secure - never commit them to git
- All sensitive values should be set in Render dashboard environment variables

## Step 4: Deploy

### 4.1 Deploy from Render Dashboard:
1. In your Web Service dashboard, click "Manual Deploy"
2. Select the branch (usually `main`)
3. Click "Deploy"

### 4.2 Monitor Deployment:
- Watch the deployment logs in real-time
- Check for any build or startup errors
- The service will be live once the status shows "Live"

### 4.3 Access Your Application:
- Your app will be available at: `https://datasell-xxxxx.onrender.com`
- Replace `xxxxx` with your service's randomly assigned ID

## Step 5: Verify Deployment

### 5.1 Health Check
Test the health check endpoint:
```bash
curl https://datasell-xxxxx.onrender.com/api/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2024-12-13T10:30:00Z"
}
```

### 5.2 Test Key Endpoints:
- Login: `POST /api/login`
- User data: `GET /api/user`
- Admin dashboard: `GET /admin`

## Step 6: Post-Deployment Configuration

### 6.1 Firebase Rules (if needed)
Update your Firebase Realtime Database rules to allow the Render domain:
```json
{
  "rules": {
    ".read": "root.child('users').child(auth.uid).exists()",
    ".write": "root.child('users').child(auth.uid).exists()"
  }
}
```

### 6.2 CORS Configuration
The server includes CORS headers. Ensure your frontend domains are configured if needed.

### 6.3 SSL/HTTPS
Render automatically provides HTTPS for all services.

## Troubleshooting

### Build Fails
- Check logs for specific error messages
- Verify all environment variables are set correctly
- Ensure `package.json` has all required dependencies listed

### Application Crashes
- Check the logs in Render dashboard
- Verify Firebase credentials are correct
- Ensure PORT environment variable is set to 3000
- Check that the health check endpoint `/api/health` is accessible

### Environment Variables Not Working
- Make sure there are no extra spaces in variable names or values
- For multi-line values (like FIREBASE_PRIVATE_KEY), use proper escaping
- Restart the service after updating environment variables

### Database Connection Issues
- Verify FIREBASE_DATABASE_URL is correct
- Check Firebase project is active and accessible
- Ensure Firebase Admin SDK credentials are valid
- Test Firebase connection locally before deploying

## Monitoring and Maintenance

### 6.1 View Logs
- Click "Logs" in your Render dashboard
- Filter by date, level, and source

### 6.2 Restart Service
- Go to "Settings" → "Restart Service"
- Useful when environment variables are updated

### 6.3 Scale Application
- Upgrade plan for more resources
- Adjust auto-scaling settings if available

### 6.4 Update Application
- Push changes to GitHub
- Trigger manual deploy or enable auto-deploy
- Render will rebuild and restart the service

## Security Best Practices

1. **Never commit `.env` file to git** - Use `.env.example` instead
2. **Use strong admin passwords** - At least 16 characters with mixed case
3. **Rotate API keys regularly** - Update Paystack, mNotify, and Datamart keys
4. **Enable two-factor authentication** on Firebase and Paystack accounts
5. **Monitor logs regularly** for suspicious activity
6. **Use environment-specific values** - Different keys for dev and production
7. **Restrict Firebase rules** - Only allow authenticated users

## Performance Tips

1. **Database Indexing**: Add indices in Firebase for frequently queried fields
2. **Caching**: Implement request caching where appropriate
3. **Error Handling**: Ensure proper error responses to avoid timeouts
4. **Connection Pooling**: Express handles this automatically
5. **Cleanup Old Data**: Periodically archive or delete old transactions/logs

## Support and Resources

- Render Documentation: https://render.com/docs
- Firebase Documentation: https://firebase.google.com/docs
- Express.js Documentation: https://expressjs.com
- Node.js Documentation: https://nodejs.org/docs

## Rollback Procedure

If deployment has issues:
1. Go to "Deployment" tab in Render dashboard
2. Select the previous working deployment
3. Click "Redeploy"

---

**Last Updated**: December 13, 2025
**Version**: 1.0.0
