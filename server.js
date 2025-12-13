require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const admin = require('firebase-admin');
const axios = require('axios');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const cors = require('cors');
// rate limiting removed per request

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for Render deployment (needed for correct IP addresses and HTTPS)
// Render uses a reverse proxy, so we need to trust it
app.set('trust proxy', 1);

// mNotify SMS configuration
const MNOTIFY_API_KEY = process.env.MNOTIFY_API_KEY || '8QZ7zFXx1iFXvRYnDOmoyUabC';
const MNOTIFY_ENDPOINT = 'https://api.mnotify.com/api/sms/quick';

async function sendSmsToUser(userId, phoneFallback, message) {
  try {
    const userSnap = await admin.database().ref(`users/${userId}`).once('value');
    const user = userSnap.val() || {};
    const phone = (user.phone || user.phoneNumber || phoneFallback || '').toString();
    if (!phone || phone.length < 8) {
      console.log('SMS not sent: no valid phone for user', userId);
      return;
    }

    const url = `${MNOTIFY_ENDPOINT}?key=${MNOTIFY_API_KEY}`;
    const payload = {
      recipient: [phone],
      sender: 'DataSell',
      message,
      is_schedule: false,
      schedule_date: ''
    };

    const resp = await axios.post(url, payload, { headers: { 'Content-Type': 'application/json' } });
    console.log('📩 SMS sent to', phone, 'response:', resp.data);
  } catch (err) {
    console.error('❌ SMS send error for user', userId, err?.response?.data || err.message || err);
  }
}

// Enhanced environment validation
const requiredEnvVars = [
  'FIREBASE_PRIVATE_KEY',
  'FIREBASE_CLIENT_EMAIL', 
  'FIREBASE_DATABASE_URL',
  'PAYSTACK_SECRET_KEY',
  'DATAMART_API_KEY',
  'SESSION_SECRET',
  'BASE_URL',
  'FIREBASE_API_KEY',
  'FIREBASE_PROJECT_ID'
];

const missingVars = requiredEnvVars.filter(envVar => !process.env[envVar]);
if (missingVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingVars);
  process.exit(1);
}

// Enhanced Firebase Admin initialization with better error handling
try {
  const serviceAccount = {
    type: "service_account",
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: "https://accounts.google.com/o/oauth2/auth",
    token_uri: "https://oauth2.googleapis.com/token",
    auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
    client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL
  };

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL
  });
  console.log('✅ Firebase Admin initialized successfully');
} catch (error) {
  console.error('❌ Firebase initialization failed:', error.message);
  process.exit(1);
}

// Enhanced Package Cache System with error recovery
let packageCache = {
  mtn: [],
  at: [],
  lastUpdated: null,
  isInitialized: false
};

function initializePackageCache() {
  console.log('🔄 Initializing real-time package cache...');
  
  const mtnRef = admin.database().ref('packages/mtn');
  const atRef = admin.database().ref('packages/at');
  
  mtnRef.on('value', (snapshot) => {
    try {
      const packages = snapshot.val() || {};
      const packagesArray = Object.entries(packages).map(([key, pkg]) => ({
        id: key,
        ...pkg
      })).filter(pkg => pkg.active !== false);
      
      packageCache.mtn = packagesArray;
      packageCache.lastUpdated = Date.now();
      packageCache.isInitialized = true;
      console.log(`✅ MTN packages cache updated (${packagesArray.length} packages)`);
    } catch (error) {
      console.error('❌ Error updating MTN packages cache:', error);
    }
  }, (error) => {
    console.error('❌ MTN packages listener error:', error);
  });
  
  atRef.on('value', (snapshot) => {
    try {
      const packages = snapshot.val() || {};
      const packagesArray = Object.entries(packages).map(([key, pkg]) => ({
        id: key,
        ...pkg
      })).filter(pkg => pkg.active !== false);
      
      packageCache.at = packagesArray;
      packageCache.lastUpdated = Date.now();
      packageCache.isInitialized = true;
      console.log(`✅ AirtelTigo packages cache updated (${packagesArray.length} packages)`);
    } catch (error) {
      console.error('❌ Error updating AirtelTigo packages cache:', error);
    }
  }, (error) => {
    console.error('❌ AirtelTigo packages listener error:', error);
  });
}

initializePackageCache();

// Custom Firebase Session Store (persists sessions across restarts)
class FirebaseSessionStore extends session.Store {
  constructor() {
    super();
    this.sessionsRef = admin.database().ref('sessions');
  }

  get(sessionId, callback) {
    console.log('📖 Session store: GET', sessionId);
    this.sessionsRef.child(sessionId).once('value', (snapshot) => {
      const data = snapshot.val();
      if (data && data.expires > Date.now()) {
        // Session still valid
        console.log('✅ Session store: GET found valid session for', sessionId);
        callback(null, JSON.parse(data.session));
      } else if (data) {
        // Session expired, delete it
        console.log('⏰ Session store: GET found expired session for', sessionId, '- deleting');
        this.sessionsRef.child(sessionId).remove();
        callback(null, null);
      } else {
        console.log('❌ Session store: GET found NO session for', sessionId);
        callback(null, null);
      }
    }).catch((err) => {
      console.error('❌ Session store GET error:', err);
      callback(err);
    });
  }

  set(sessionId, sessionData, callback) {
    const expiresMs = sessionData.cookie.maxAge || 24 * 60 * 60 * 1000;
    console.log('💾 Session store: SET', sessionId, 'with user:', sessionData.user?.uid || 'no user');
    this.sessionsRef.child(sessionId).set({
      session: JSON.stringify(sessionData),
      expires: Date.now() + expiresMs,
      createdAt: Date.now()
    }, (err) => {
      if (err) {
        console.error('❌ Session store SET error:', err);
        callback(err);
      } else {
        console.log('✅ Session store: SET complete for', sessionId);
        callback(null);
      }
    });
  }

  destroy(sessionId, callback) {
    console.log('🗑️  Session store: DESTROY', sessionId);
    this.sessionsRef.child(sessionId).remove((err) => {
      if (err) {
        console.error('❌ Session store DESTROY error:', err);
        callback(err);
      } else {
        console.log('✅ Session store: DESTROY complete for', sessionId);
        callback(null);
      }
    });
  }

  touch(sessionId, sessionData, callback) {
    const expiresMs = sessionData.cookie.maxAge || 24 * 60 * 60 * 1000;
    console.log('🔄 Session store: TOUCH', sessionId);
    this.sessionsRef.child(sessionId).update({
      expires: Date.now() + expiresMs
    }, (err) => {
      if (err) {
        console.error('❌ Session store TOUCH error:', err);
        callback(err);
      } else {
        console.log('✅ Session store: TOUCH complete for', sessionId);
        callback(null);
      }
    });
  }
}

// Enhanced middleware setup
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Enhanced session configuration with Firebase persistence
app.use(session({
  store: new FirebaseSessionStore(),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  // Allow overriding secure flag via env `SESSION_COOKIE_SECURE` for local testing
  cookie: {
    secure: (typeof process.env.SESSION_COOKIE_SECURE !== 'undefined') ? (process.env.SESSION_COOKIE_SECURE === 'true') : (process.env.NODE_ENV === 'production'),
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  },
  name: 'datasell.sid'
}));

// Enhanced CORS configuration
const allowedDomains = [
  'datasell.store',
  'datasell.com', 
  'datasell.onrender.com',
  'datasell.io',
  'datasell.pro',
  'datasell.shop',
  'localhost:3000',
'datasell-5w0w.onrender.com'
];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedDomains.some(domain => origin.includes(domain))) {
      callback(null, true);
    } else {
      console.log('🚫 CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Enhanced domain restriction middleware
app.use((req, res, next) => {
  const host = req.get('host');
  const origin = req.get('origin');
  
  // Skip domain check for health endpoints, webhooks and lightweight config
  if (req.path === '/api/health' || req.path === '/api/ping' || req.path === '/api/hubnet-webhook' || req.path === '/api/datamart-webhook' || req.path === '/config.js') {
    return next();
  }
  
  // Development bypass: do not enforce domain restrictions when not in production
  if (process.env.NODE_ENV !== 'production') {
    // Log host/origin to help diagnose local dev issues
    console.log('Domain check bypass (dev). host:', host, 'origin:', origin, 'path:', req.path);
    return next();
  }

  const isAllowed = allowedDomains.some(domain => 
    host?.includes(domain) || origin?.includes(domain)
  );

  if (!isAllowed) {
    console.log('🚫 Blocked access from:', { host, origin, path: req.path });
    return res.status(403).json({ 
      success: false,
      error: 'Access forbidden - Domain not allowed'
    });
  }

  next();
});

// Rate limiting removed to allow seamless login/signup access.

// Enhanced authentication middleware
const requireAuth = (req, res, next) => {
  // Debug: log session state
  console.log('🔐 Session check for', req.path, ':', {
    hasSession: !!req.session,
    hasUser: !!req.session?.user,
    userId: req.session?.user?.uid || 'none',
    sessionId: req.sessionID || 'none'
  });

  if (req.session.user) {
    next();
  } else {
    // Prefer JSON for API routes to avoid HTML redirects being returned to fetch()
    if (req.path && req.path.startsWith('/api')) {
      console.warn('Unauthorized API request:', { path: req.path, cookies: req.headers.cookie, session: req.session && Object.keys(req.session).length ? '[session present]' : '[no session]' });
      return res.status(401).json({ success: false, error: 'Authentication required' });
    }

    // If the client accepts HTML, redirect to login page for browser navigations
    if (req.accepts && req.accepts('html')) {
      return res.redirect('/login');
    }

    // Fallback to JSON
    res.status(401).json({ success: false, error: 'Authentication required' });
  }
};

// Lightweight client config endpoint (serves runtime values to the browser)
app.get('/config.js', (req, res) => {
  const domainEnv = process.env.DOMAIN || null;
  const base = (domainEnv ? (domainEnv.match(/^https?:\/\//) ? domainEnv : `https://${domainEnv}`) : (process.env.BASE_URL || 'https://datasell.onrender.com')).replace(/\/$/, '');
  const apkUrl = base + '/downloads/datasell-debug.apk';
  const firebaseConfig = {
    apiKey: process.env.FIREBASE_API_KEY || null,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN || null,
    projectId: process.env.FIREBASE_PROJECT_ID || null,
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET || null,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID || null,
    appId: process.env.FIREBASE_APP_ID || null
  };
  res.set('Content-Type', 'application/javascript');
  const vapid = process.env.FIREBASE_VAPID_KEY || null;
  res.send(`window.__DOMAIN = ${JSON.stringify(domainEnv)}; window.__BASE_URL = ${JSON.stringify(base)}; window.__APK_URL = ${JSON.stringify(apkUrl)}; window.__FIREBASE_CONFIG = ${JSON.stringify(firebaseConfig)}; window.__FCM_VAPID_KEY = ${JSON.stringify(vapid)};`);
});

// Serve Firebase Messaging Service Worker dynamically with server-side config
app.get('/firebase-messaging-sw.js', (req, res) => {
  res.set('Content-Type', 'application/javascript');
  const fbConfig = {
    apiKey: process.env.FIREBASE_API_KEY || null,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN || null,
    projectId: process.env.FIREBASE_PROJECT_ID || null,
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET || null,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID || null,
    appId: process.env.FIREBASE_APP_ID || null
  };

  const sw = `importScripts('https://www.gstatic.com/firebasejs/9.22.1/firebase-app-compat.js');\nimportScripts('https://www.gstatic.com/firebasejs/9.22.1/firebase-messaging-compat.js');\n\nfirebase.initializeApp(${JSON.stringify(fbConfig)});\nconst messaging = firebase.messaging();\n\nmessaging.onBackgroundMessage(function(payload) {\n  try {\n    const title = (payload.notification && payload.notification.title) || 'Notification';\n    const options = {\n      body: (payload.notification && payload.notification.body) || '',\n      icon: (payload.notification && payload.notification.image) || '/images/app-icon.png',\n      data: payload.data || {}\n    };\n    self.registration.showNotification(title, options);\n  } catch (e) { console.error('SW background message error', e); }\n});\n\nself.addEventListener('notificationclick', function(event) {\n  event.notification.close();\n  const url = event.notification.data && event.notification.data.click_action ? event.notification.data.click_action : '/notifications';\n  event.waitUntil(clients.matchAll({ type: 'window' }).then(windowClients => {\n    for (let i = 0; i < windowClients.length; i++) {\n      const client = windowClients[i];\n      if (client.url === url && 'focus' in client) return client.focus();\n    }\n    if (clients.openWindow) return clients.openWindow(url);\n  }));\n});\n`;

  res.send(sw);
});

// Enhanced admin middleware
const requireAdmin = (req, res, next) => {
  if (req.session.user && req.session.user.isAdmin) {
    next();
  } else {
    // For browser navigation, redirect to admin login page for a smoother UX
    if (req.accepts && req.accepts('html')) {
      return res.redirect('/admin-login');
    }

    res.status(403).json({ 
      success: false, 
      error: 'Admin privileges required' 
    });
  }
};

// ====================
// ENHANCED PAGE ROUTES
// ====================

app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/purchase', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'purchase.html'));
});

app.get('/wallet', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'wallet.html'));
});

app.get('/orders', requireAuth, (req, res) => {
  // Serve the orders page (replaced with new content)
  res.sendFile(path.join(__dirname, 'public', 'orders.html'));
});

app.get('/notifications', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'notifications.html'));
});

app.get('/profile', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/admin-login', (req, res) => {
  if (req.session.user && req.session.user.isAdmin) return res.redirect('/admin');
  res.sendFile(path.join(__dirname, 'public', 'admin-login.html'));
});

app.get('/admin', (req, res) => {
  // Serve admin page to admins; otherwise redirect browser navigations to /admin-login
  if (!req.session?.user || !req.session.user.isAdmin) {
    return res.redirect('/admin-login');
  }

  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ====================
// ENHANCED AUTHENTICATION API ROUTES
// ====================

// Enhanced User Registration
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, firstName, lastName, phone, acceptedTerms } = req.body;
    
    // Validation
    if (!email || !password || !firstName || !lastName || !phone) {
      return res.status(400).json({ 
        success: false, 
        error: 'All fields are required' 
      });
    }

    // Terms acceptance validation
    if (!acceptedTerms) {
      return res.status(400).json({
        success: false,
        error: 'You must accept the Terms of Service and Privacy Policy to create an account'
      });
    }

    if (!/^\d{10}$/.test(phone)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Phone number must be 10 digits' 
      });
    }

    const userRecord = await admin.auth().createUser({
      email,
      password,
      displayName: `${firstName} ${lastName}`,
      phoneNumber: `+233${phone.substring(1)}` // Format for Ghana
    });

    // Create user in database
    await admin.database().ref('users/' + userRecord.uid).set({
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      email: email.toLowerCase().trim(),
      phone: phone.trim(),
      walletBalance: 0,
      createdAt: new Date().toISOString(),
      isAdmin: email === process.env.ADMIN_EMAIL,
      pricingGroup: 'regular',
      suspended: false,
      lastLogin: null
    });

    // Log registration
    await admin.database().ref('userLogs').push().set({
      userId: userRecord.uid,
      action: 'registration',
      timestamp: new Date().toISOString(),
      ip: req.ip
    });

    res.json({ 
      success: true, 
      userId: userRecord.uid,
      message: 'Account created successfully'
    });
  } catch (error) {
    console.error('Signup error:', error);
    
    if (error.code === 'auth/email-already-exists') {
      return res.status(400).json({ 
        success: false, 
        error: 'Email already exists' 
      });
    }
    
    res.status(400).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Enhanced User Login
app.post('/api/login', async (req, res) => {
  try {
    let { email, password, remember } = req.body;
    // Coerce remember to boolean for safety (clients may send 'true'/'false' strings)
    remember = (remember === true || remember === 'true');
    console.log('Login attempt for:', email, 'remember=', remember);

    // Enforce 'remember me' requirement: do not allow login unless user checked it
    if (!remember) {
      return res.status(400).json({
        success: false,
        error: 'You must check "Remember me" to sign in.'
      });
    }
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email and password are required' 
      });
    }

    // Enhanced Admin login
    if (email === process.env.ADMIN_EMAIL) {
      if (password === process.env.ADMIN_PASSWORD) {
        let userRecord;
        try {
          userRecord = await admin.auth().getUserByEmail(email);
        } catch (error) {
          // Create admin user if doesn't exist
          userRecord = await admin.auth().createUser({
            email,
            password: process.env.ADMIN_PASSWORD,
            displayName: 'Administrator'
          });

          await admin.database().ref('users/' + userRecord.uid).set({
            firstName: 'Admin',
            lastName: 'User',
            email,
            phone: '',
            walletBalance: 0,
            createdAt: new Date().toISOString(),
            isAdmin: true,
            pricingGroup: 'admin',
            suspended: false
          });
        }

        // Set user data directly (no regenerate - it breaks session ID sync)
        req.session.user = {
          uid: userRecord.uid,
          email: userRecord.email,
          displayName: userRecord.displayName,
          isAdmin: true
        };

        // Respect 'remember me' for admin sessions if provided
        try {
          const rememberMs = remember ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000; // 30 days || 24 hours
          req.session.cookie.maxAge = rememberMs;
        } catch (e) {
          // Ignore if session cookie cannot be modified
        }

        // Update last login - do this in background
        admin.database().ref('users/' + userRecord.uid).update({
          lastLogin: new Date().toISOString()
        }).catch(err => console.error('Failed to update lastLogin:', err));

        // Log session info for debugging
        console.log('✅ Admin login for', userRecord.uid, 'sessionID:', req.sessionID, 'cookieMaxAge:', req.session.cookie.maxAge);
        console.log('🍪 Session data set:', { uid: req.session.user.uid, sessionID: req.sessionID });
        
        // Return response - express-session middleware will automatically save and set Set-Cookie
        return res.json({ 
          success: true, 
          message: 'Admin login successful',
          user: req.session.user,
          sessionID: req.sessionID
        });
      } else {
        return res.status(401).json({ 
          success: false, 
          error: 'Invalid admin credentials' 
        });
      }
    }

    // Enhanced Regular user login
    const signInResponse = await axios.post(
      `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_API_KEY}`,
      {
        email,
        password,
        returnSecureToken: true
      },
      { timeout: 10000 }
    );

    const { localId, email: userEmail, displayName } = signInResponse.data;

    const userSnapshot = await admin.database().ref('users/' + localId).once('value');
    const userData = userSnapshot.val();

    if (!userData) {
      return res.status(404).json({ 
        success: false, 
        error: 'User data not found' 
      });
    }

    // Check if user is suspended
    if (userData.suspended) {
      return res.status(403).json({
        success: false,
        error: 'Account suspended. Please contact administrator.'
      });
    }

    // Set user data directly (no regenerate - it breaks session ID sync)
    req.session.user = {
      uid: localId,
      email: userEmail,
      displayName: displayName || `${userData.firstName} ${userData.lastName}`,
      isAdmin: userData.isAdmin || false
    };

    // Respect 'remember me' for regular user sessions
    try {
      const rememberMs = remember ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000; // 30 days || 24 hours
      req.session.cookie.maxAge = rememberMs;
    } catch (e) {
      // Ignore if session cookie cannot be modified
    }

    // Update last login - do this in background
    admin.database().ref('users/' + localId).update({
      lastLogin: new Date().toISOString()
    }).catch(err => console.error('Failed to update lastLogin:', err));

    // Log session info for debugging
    console.log('✅ User login for', localId, 'sessionID:', req.sessionID, 'cookieMaxAge:', req.session.cookie.maxAge);
    console.log('🍪 Session data set:', { uid: req.session.user.uid, sessionID: req.sessionID });
    
    // Return response - express-session middleware will automatically save and set Set-Cookie
    return res.json({ 
      success: true, 
      message: 'Login successful',
      user: req.session.user,
      sessionID: req.sessionID
    });
  } catch (error) {
    console.error('Login error:', error);
    
    if (error.response?.data?.error?.message) {
      const errorMessage = error.response.data.error.message;
      if (errorMessage.includes('INVALID_EMAIL') || errorMessage.includes('INVALID_PASSWORD')) {
        return res.status(401).json({ 
          success: false, 
          error: 'Invalid email or password' 
        });
      }
      // Do not expose or enforce Firebase's TOO_MANY_ATTEMPTS_TRY_LATER limit.
      // Map that specific error to a generic response so the client isn't
      // blocked or shown the rate-limit message.
      if (errorMessage.includes('TOO_MANY_ATTEMPTS_TRY_LATER')) {
        return res.status(401).json({ success: false, error: 'Invalid credentials' });
      }
      if (errorMessage) {
        return res.status(401).json({ success: false, error: errorMessage });
      }
    }
    
    res.status(401).json({ 
      success: false, 
      error: 'Invalid credentials' 
    });
  }
});

// Enhanced Get current user
app.get('/api/user', requireAuth, async (req, res) => {
  try {
    const uid = req.session.user.uid;
    const snap = await admin.database().ref('users/' + uid).once('value');
    const userData = snap.val() || {};

    // Merge session data with database fields we want the client to know
    const user = Object.assign({}, req.session.user, {
      phoneNumber: userData.phone || userData.phoneNumber || null,
      walletBalance: userData.walletBalance || 0,
      firstName: userData.firstName || null,
      lastName: userData.lastName || null
    });

    res.json({ success: true, user });
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ success: false, error: 'Failed to fetch user' });
  }
});

// Get user profile endpoint
app.get('/api/profile', requireAuth, async (req, res) => {
  try {
    const uid = req.session.user.uid;
    const snap = await admin.database().ref('users/' + uid).once('value');
    const userData = snap.val() || {};

    const profile = {
      uid,
      firstName: userData.firstName || '',
      lastName: userData.lastName || '',
      email: userData.email || '',
      phone: userData.phone || '',
      walletBalance: userData.walletBalance || 0,
      createdAt: userData.createdAt || null,
      lastLogin: userData.lastLogin || null,
      isAdmin: userData.isAdmin || false,
      pricingGroup: userData.pricingGroup || 'regular'
    };

    res.json({ success: true, profile });
  } catch (err) {
    console.error('Get profile error:', err);
    res.status(500).json({ success: false, error: 'Failed to fetch profile' });
  }
});

// Get user profile statistics
app.get('/api/profile/stats', requireAuth, async (req, res) => {
  try {
    const uid = req.session.user.uid;
    
    // Get total spent from orders
    const ordersSnap = await admin.database().ref('orders').orderByChild('userId').equalTo(uid).once('value');
    const orders = ordersSnap.val() || {};
    const totalOrders = Object.keys(orders).length;
    const totalSpent = Object.values(orders).reduce((sum, order) => sum + (order.amount || 0), 0);
    
    // Get wallet info
    const userSnap = await admin.database().ref('users/' + uid).once('value');
    const userData = userSnap.val() || {};
    const walletBalance = userData.walletBalance || 0;

    const stats = {
      totalOrders,
      totalSpent,
      walletBalance,
      memberSince: userData.createdAt || null
    };

    res.json({ success: true, stats });
  } catch (err) {
    console.error('Get profile stats error:', err);
    res.status(500).json({ success: false, error: 'Failed to fetch stats' });
  }
});

// Register FCM token for the logged-in user
app.post('/api/register-fcm-token', requireAuth, async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ success: false, error: 'Token is required' });
    const uid = req.session.user.uid;
    await admin.database().ref(`fcmTokens/${uid}/${token}`).set(true);
    res.json({ success: true });
  } catch (err) {
    console.error('Register FCM token error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get notifications for the logged-in user (latest 100)
app.get('/api/notifications', requireAuth, async (req, res) => {
  try {
    const snap = await admin.database().ref('notifications').orderByChild('createdAt').limitToLast(100).once('value');
    const data = snap.val() || {};
    const list = Object.entries(data).map(([id, n]) => ({ id, ...n }));
    list.sort((a, b) => b.createdAt - a.createdAt);
    res.json({ success: true, notifications: list });
  } catch (err) {
    console.error('Get notifications error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Admin: send notification (text + optional imageBase64)
app.post('/api/send-notification', requireAdmin, async (req, res) => {
  try {
    const { title, body, imageBase64 } = req.body;
    if (!title && !body) return res.status(400).json({ success: false, error: 'Title or body required' });

    let imageUrl = null;
    if (imageBase64) {
      const uploadsDir = path.join(__dirname, 'public', 'uploads');
      if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
      const matches = imageBase64.match(/^data:(image\/\w+);base64,(.+)$/);
      if (matches) {
        const ext = matches[1].split('/')[1];
        const buf = Buffer.from(matches[2], 'base64');
        const filename = `${Date.now()}-${Math.random().toString(36).slice(2,8)}.${ext}`;
        const filepath = path.join(uploadsDir, filename);
        fs.writeFileSync(filepath, buf);
        imageUrl = `/uploads/${filename}`;
      }
    }

    const newRef = admin.database().ref('notifications').push();
    const notif = {
      title: title || '',
      body: body || '',
      imageUrl: imageUrl || null,
      createdAt: Date.now(),
      sentBy: req.session.user?.email || 'admin'
    };

    await newRef.set(notif);

    // Collect all tokens and send push via FCM
    const tokensSnap = await admin.database().ref('fcmTokens').once('value');
    const tokensData = tokensSnap.val() || {};
    const tokens = [];
    Object.values(tokensData).forEach(userTokens => {
      Object.keys(userTokens || {}).forEach(t => tokens.push(t));
    });

    if (tokens.length > 0) {
      const host = req.get('host');
      const fullImageUrl = notif.imageUrl ? `${req.protocol}://${host}${notif.imageUrl}` : null;
      const notificationPayload = {
        title: notif.title,
        body: notif.body
      };
      // include image only when it's a non-empty string to avoid invalid-payload errors
      if (fullImageUrl && typeof fullImageUrl === 'string') {
        notificationPayload.image = String(fullImageUrl);
      }

      const payload = {
        notification: notificationPayload,
        data: {
          click_action: '/notifications',
          notificationId: newRef.key
        }
      };

      // send in batches (max 500 per sendToDevice)
      for (let i = 0; i < tokens.length; i += 500) {
        const chunk = tokens.slice(i, i + 500);
        try {
          await admin.messaging().sendToDevice(chunk, payload);
        } catch (sendErr) {
          console.error('FCM send error for chunk:', sendErr);
        }
      }
    }

    res.json({ success: true, notification: notif });
  } catch (err) {
    console.error('Send notification error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Enhanced Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ success: false, error: 'Logout failed' });
    }
    res.json({ success: true, message: 'Logged out successfully' });
  });
});

// ====================
// ENHANCED WALLET & PAYMENT ROUTES
// ====================

// Enhanced Get wallet balance
app.get('/api/wallet/balance', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.uid;
    const userSnapshot = await admin.database().ref('users/' + userId).once('value');
    const userData = userSnapshot.val();
    
    if (!userData) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }

    res.json({ 
      success: true, 
      balance: userData.walletBalance || 0 
    });
  } catch (error) {
    console.error('Wallet balance error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch wallet balance' 
    });
  }
});

// Enhanced Get wallet transactions
app.get('/api/wallet/transactions', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.uid;
    
    const transactionsSnapshot = await admin.database()
      .ref('transactions')
      .orderByChild('userId')
      .equalTo(userId)
      .once('value');
    
    const paymentsSnapshot = await admin.database()
      .ref('payments')
      .orderByChild('userId')
      .equalTo(userId)
      .once('value');

    const transactions = transactionsSnapshot.val() || {};
    const payments = paymentsSnapshot.val() || {};

    // Combine and format transactions
    let allTransactions = [];

    // Add data purchases (transactions)
    Object.entries(transactions).forEach(([id, transaction]) => {
      allTransactions.push({
        id,
        type: 'purchase',
        description: `${transaction.packageName} - ${transaction.network?.toUpperCase() || ''}`,
        amount: -transaction.amount,
        status: transaction.status || 'success',
        timestamp: transaction.timestamp,
        reference: transaction.reference
      });
    });

    // Add wallet funding (payments)
    Object.entries(payments).forEach(([id, payment]) => {
      allTransactions.push({
        id,
        type: 'funding',
        description: 'Wallet Funding',
        amount: payment.amount,
        status: payment.status || 'success',
        timestamp: payment.timestamp,
        reference: payment.reference
      });
    });

    // Sort by timestamp (newest first) and limit
    allTransactions.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    allTransactions = allTransactions.slice(0, 50);

    res.json({
      success: true,
      transactions: allTransactions
    });
  } catch (error) {
    console.error('Error loading wallet transactions:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to load transactions'
    });
  }
});

// Enhanced Get user orders
app.get('/api/orders', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.uid;
    
    console.log('📦 Fetching orders for user:', userId);
    
    // Try using orderByChild first (faster with index)
    try {
      const transactionsSnapshot = await admin.database()
        .ref('transactions')
        .orderByChild('userId')
        .equalTo(userId)
        .once('value');

      const transactions = transactionsSnapshot.val() || {};

      // Format transactions as orders
      const orders = Object.entries(transactions).map(([id, transaction]) => ({
        id,
        packageName: transaction.packageName || 'Data Package',
        network: transaction.network || 'unknown',
        phoneNumber: transaction.phoneNumber || '',
        amount: transaction.amount || 0,
        volume: transaction.volume || '0MB',
        status: transaction.status || 'processing',
        reference: transaction.reference || '',
        transactionId: transaction.transactionId || transaction.datamartTransactionId || transaction.hubnetTransactionId || '',
        timestamp: transaction.timestamp || new Date().toISOString(),
        reason: transaction.reason || ''
      }));

      // Sort by timestamp (newest first)
      orders.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

      console.log(`✅ Found ${orders.length} orders using orderByChild`);

      res.json({
        success: true,
        orders: orders
      });
    } catch (indexError) {
      // Fallback: read all transactions and filter client-side
      console.log('⚠️ OrderByChild failed, using fallback method:', indexError.message);
      
      const allTransactionsSnapshot = await admin.database()
        .ref('transactions')
        .once('value');

      const allTransactions = allTransactionsSnapshot.val() || {};

      // Filter transactions for current user
      const orders = Object.entries(allTransactions)
        .filter(([id, transaction]) => transaction.userId === userId)
        .map(([id, transaction]) => ({
          id,
          packageName: transaction.packageName || 'Data Package',
          network: transaction.network || 'unknown',
          phoneNumber: transaction.phoneNumber || '',
          amount: transaction.amount || 0,
          volume: transaction.volume || '0MB',
          status: transaction.status || 'processing',
          reference: transaction.reference || '',
          transactionId: transaction.transactionId || transaction.datamartTransactionId || transaction.hubnetTransactionId || '',
          timestamp: transaction.timestamp || new Date().toISOString(),
          reason: transaction.reason || ''
        }));

      // Sort by timestamp (newest first)
      orders.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

      console.log(`✅ Found ${orders.length} orders using fallback method`);

      res.json({
        success: true,
        orders: orders
      });
    }
  } catch (error) {
    console.error('❌ Error loading orders:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to load orders'
    });
  }
});

// Enhanced Paystack wallet funding
app.post('/api/initialize-payment', requireAuth, async (req, res) => {
  try {
    const { amount } = req.body;
    const userId = req.session.user.uid;
    const email = req.session.user.email;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid amount' 
      });
    }

    // Calculate Paystack amount (add 3% fee)
    const paystackAmount = Math.ceil(amount * 100 * 1.06);

    const paystackResponse = await axios.post(
      `${process.env.PAYSTACK_BASE_URL}/transaction/initialize`,
      {
        email,
        amount: paystackAmount,
        callback_url: `${process.env.BASE_URL}/wallet?success=true`,
        metadata: {
          userId: userId,
          purpose: 'wallet_funding',
          originalAmount: amount
        }
      },
      {
        headers: {
          'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
          'Content-Type': 'application/json'
        },
        timeout: 15000
      }
    );

    res.json(paystackResponse.data);
  } catch (error) {
    console.error('Paystack initialization error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.response?.data?.message || 'Payment initialization failed' 
    });
  }
});

// Enhanced Verify wallet payment
app.get('/api/verify-payment/:reference', requireAuth, async (req, res) => {
  try {
    const { reference } = req.params;
    const userId = req.session.user.uid;
    
    const paystackResponse = await axios.get(
      `${process.env.PAYSTACK_BASE_URL}/transaction/verify/${reference}`,
      {
        headers: {
          'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
        },
        timeout: 15000
      }
    );

    const result = paystackResponse.data;
    
    if (result.data.status === 'success') {
      // Get the ORIGINAL amount from metadata
      const originalAmount = result.data.metadata.originalAmount || (result.data.amount / 100);
      const amount = parseFloat(originalAmount);
      
      const userRef = admin.database().ref('users/' + userId);
      const userSnapshot = await userRef.once('value');
      const currentBalance = userSnapshot.val().walletBalance || 0;
      
      // Credit the ORIGINAL amount
      await userRef.update({ 
        walletBalance: currentBalance + amount 
      });

      const paymentRef = admin.database().ref('payments').push();
      await paymentRef.set({
        userId,
        amount: amount,
        paystackAmount: result.data.amount / 100,
        fee: (result.data.amount / 100) - amount,
        reference,
        status: 'success',
        paystackData: result.data,
        timestamp: new Date().toISOString()
      });

      // Send wallet funding SMS to user
      try {
        const userData = userSnapshot.val() || {};
        const username = userData.displayName || userData.username || userData.name || userData.email || 'Customer';
        const phoneFallback = userData.phone || userData.phoneNumber || '';
        const message = `hello ${username} your DataSell has been credited with ${amount} Thank you for choosing DataSell`;
        sendSmsToUser(userId, phoneFallback, message);
      } catch (smsErr) {
        console.error('Wallet funding SMS error:', smsErr);
      }

      res.json({ 
        success: true, 
        amount: amount,
        newBalance: currentBalance + amount
      });
    } else {
      res.json({ 
        success: false, 
        error: 'Payment failed or pending' 
      });
    }
  } catch (error) {
    console.error('Payment verification error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Payment verification failed' 
    });
  }
});

// Direct payment endpoints removed: application now supports wallet purchases and wallet funding only.

// ====================
// ENHANCED DATA PURCHASE ROUTES
// ====================

// Helper function to map internal network names to DataMart network identifiers
function mapNetworkToDataMart(network) {
  const networkMap = {
    'mtn': 'YELLO',
    'at': 'AT_PREMIUM',
    'airteltigo': 'AT_PREMIUM',
    'vodafone': 'TELECEL',
    'telecel': 'TELECEL'
  };
  return networkMap[network?.toLowerCase()] || network?.toUpperCase();
}

// Helper function to check if DataMart error is due to provider balance
function isProviderBalanceError(datamartData) {
  if (!datamartData) return false;
  
  const message = String(datamartData.message || datamartData.error || '').toLowerCase();
  const details = String(datamartData.details || '').toLowerCase();
  const fullResponse = JSON.stringify(datamartData || {}).toLowerCase();
  
  // Check for common DataMart balance error messages
  const balanceErrorKeywords = [
    'insufficient', 'balance', 'low balance', 'out of stock', 'unavailable', 
    'account balance', 'no stock', 'low', 'rejected', 'insufficient funds'
  ];
  
  // Check if any balance error keyword appears in message, details, or full response
  return balanceErrorKeywords.some(keyword => 
    message.includes(keyword) || 
    details.includes(keyword) ||
    fullResponse.includes(keyword)
  );
}

// Enhanced Get packages
app.get('/api/packages/:network', requireAuth, async (req, res) => {
  try {
    const { network } = req.params;
    
    if (!['mtn', 'at'].includes(network)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid network' 
      });
    }

    // Use cache if available, otherwise fetch from database
    if (!packageCache[network] || packageCache[network].length === 0) {
      const packagesSnapshot = await admin.database().ref('packages/' + network).once('value');
      const packages = packagesSnapshot.val() || {};
      const packagesArray = Object.values(packages).filter(pkg => pkg.active !== false);
      
      packagesArray.sort((a, b) => {
        const getVolume = (pkg) => {
          if (pkg.name) {
            const volumeMatch = pkg.name.match(/\d+/);
            return volumeMatch ? parseInt(volumeMatch[0]) : 0;
          }
          return 0;
        };
        return getVolume(a) - getVolume(b);
      });
      
      packageCache[network] = packagesArray;
    }
    
    res.json({ 
      success: true, 
      packages: packageCache[network] || []
    });
  } catch (error) {
    console.error('Packages fetch error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch packages' 
    });
  }
});

// Enhanced Purchase with wallet
app.post('/api/purchase-data', requireAuth, async (req, res) => {
  let transactionRef = null;
  
  try {
    const { network, volume, phoneNumber, amount, packageName } = req.body;
    const userId = req.session.user.uid;
    
    console.log('🔄 Purchase request received:', { network, volume, phoneNumber, amount, packageName });

    // Validation
    if (!network || !volume || !phoneNumber || !amount || !packageName) {
      return res.status(400).json({ 
        success: false, 
        error: 'All fields are required' 
      });
    }

    if (!/^\d{10}$/.test(phoneNumber)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Phone number must be 10 digits' 
      });
    }

    // Convert volume to GB for DataMart (they expect capacity in GB)
    let volumeValue = volume;
    let capacityGB = volumeValue;
    if (volumeValue && parseInt(volumeValue) >= 100) {
      // If volume is in MB, convert to GB
      capacityGB = (parseInt(volumeValue) / 1000).toString();
      console.log(`🔢 VOLUME CONVERTED: ${volume}MB → ${capacityGB}GB`);
    }

    const userRef = admin.database().ref('users/' + userId);
    const userSnapshot = await userRef.once('value');
    const userData = userSnapshot.val();
    
    if (!userData) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }

    if (userData.walletBalance < amount) {
      return res.status(400).json({ 
        success: false, 
        error: 'Insufficient wallet balance' 
      });
    }

    const reference = `DS-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    // Create order record first
    transactionRef = admin.database().ref('transactions').push();
    const transactionId = transactionRef.key; // Get the Firebase ID
    
    const initialOrderData = {
      userId,
      network,
      packageName,
      volume: volumeValue,
      phoneNumber,
      amount,
      status: 'processing',
      reference: reference,
      transactionId: null,
      datamartTransactionId: null,
      datamartResponse: null,
      datamartConfirmed: false,
      timestamp: new Date().toISOString(),
      paymentMethod: 'wallet'
    };
    
    await transactionRef.set(initialOrderData);
    console.log('✅ Order record created in Firebase:', {
      firebaseId: transactionId,
      reference: reference,
      userId: userId,
      network: network,
      packageName: packageName,
      amount: amount
    });

    // Notify user that payment/order is received and processing
    try {
      const notifyMsg = `Payment received. Your data package will be delivered within 1 to 30 minutes. If any troubles contact support on 0505573287.`;
      await sendSmsToUser(userId, phoneNumber, notifyMsg);
      console.log('📩 Order-created SMS sent for transaction', transactionId);
    } catch (smsErr) {
      console.error('❌ Failed to send order-created SMS for', transactionId, smsErr);
    }

    // Map network to DataMart format
    const datamartNetwork = mapNetworkToDataMart(network);
    
    // DataMart API call
    const datamartResponse = await axios.post(
      'https://api.datamartgh.shop/api/developer/purchase',
      {
        phoneNumber: phoneNumber,
        network: datamartNetwork,
        capacity: capacityGB,
        gateway: 'wallet'
      },
      {
        headers: {
          'X-API-Key': process.env.DATAMART_API_KEY,
          'Content-Type': 'application/json'
        },
        timeout: 30000
      }
    );

    const datamartData = datamartResponse.data;
    console.log('📡 DataMart response:', datamartData);
    console.log('📡 DataMart response full:', JSON.stringify(datamartData, null, 2));

    // Handle DataMart response structure
    if (datamartData.status === 'success' && datamartData.data) {
      // SUCCESS: Deduct balance and update order
      const newBalance = userData.walletBalance - amount;
      await userRef.update({ walletBalance: newBalance });

      const purchaseData = datamartData.data;
      await transactionRef.update({
        status: 'success',
        transactionId: purchaseData.purchaseId || purchaseData.transactionReference,
        datamartTransactionId: purchaseData.purchaseId || purchaseData.transactionReference,
        datamartResponse: purchaseData
      });

      console.log('✅ Purchase successful, order updated to success:', {
        reference: reference,
        transactionId: purchaseData.purchaseId || purchaseData.transactionReference,
        newBalance: newBalance
      });

      res.json({ 
        success: true, 
        data: purchaseData,
        newBalance: newBalance,
        reference: reference,
        message: 'Data purchase successful!'
      });
    } else {
      // FAILURE: Update order status but DON'T deduct balance
      await transactionRef.update({
        status: 'failed',
        datamartResponse: datamartData,
        reason: datamartData.message || 'Purchase failed'
      });

      console.log('❌ Purchase failed, order updated to failed');

      // Check if it's a provider balance issue
      const isOutOfStock = isProviderBalanceError(datamartData);
      console.log('🔍 Balance error check:', { isOutOfStock, datamartData });
      const errorMessage = isOutOfStock ? 'Out of Stock - Please try again later' : (datamartData.message || 'Purchase failed');

      res.status(400).json({ 
        success: false, 
        error: errorMessage,
        isOutOfStock: isOutOfStock
      });
    }

  } catch (error) {
    console.error('❌ Purchase error:', error);
    
    // Check if it's an Axios error with response data (e.g., 400 from DataMart)
    if (error.response && error.response.data) {
      const datamartErrorData = error.response.data;
      console.log('📡 DataMart error response:', datamartErrorData);
      
      if (transactionRef) {
        await transactionRef.update({
          status: 'failed',
          datamartResponse: datamartErrorData,
          reason: datamartErrorData.message || 'DataMart error'
        });
      }
      
      // Check if it's a provider balance issue
      const isOutOfStock = isProviderBalanceError(datamartErrorData);
      console.log('🔍 Balance error check (from catch):', { isOutOfStock, datamartErrorData });
      const errorMessage = isOutOfStock ? 'Out of Stock - Please try again later' : (datamartErrorData.message || 'Purchase failed');
      
      return res.status(400).json({ 
        success: false, 
        error: errorMessage,
        isOutOfStock: isOutOfStock
      });
    }
    
    // Handle other errors
    if (transactionRef) {
      await transactionRef.update({
        status: 'failed',
        datamartResponse: { error: error.message },
        reason: 'System error: ' + error.message
      });
    }
    
    let errorMessage = 'Purchase failed';
    if (error.code === 'ECONNABORTED') {
      errorMessage = 'Request timeout. Please check your connection and try again.';
    }
    
    res.status(500).json({ 
      success: false, 
      error: errorMessage 
    });
  }
});

// ====================
// ENHANCED ADMIN API ENDPOINTS
// ====================

// 1. DASHBOARD ANALYTICS
app.get('/api/admin/dashboard/stats', requireAdmin, async (req, res) => {
  try {
    const [usersSnapshot, transactionsSnapshot, paymentsSnapshot] = await Promise.all([
      admin.database().ref('users').once('value'),
      admin.database().ref('transactions').once('value'),
      admin.database().ref('payments').once('value')
    ]);

    const users = usersSnapshot.val() || {};
    const transactions = transactionsSnapshot.val() || {};
    const payments = paymentsSnapshot.val() || {};

    const usersArray = Object.values(users);
    const transactionsArray = Object.values(transactions);
    const paymentsArray = Object.values(payments);

    // Calculate time-based metrics
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const weekAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
    const monthAgo = new Date(today.getFullYear(), today.getMonth() - 1, today.getDate());

    const todayTransactions = transactionsArray.filter(t => 
      new Date(t.timestamp) >= today
    );
    const weekTransactions = transactionsArray.filter(t => 
      new Date(t.timestamp) >= weekAgo
    );
    const monthTransactions = transactionsArray.filter(t => 
      new Date(t.timestamp) >= monthAgo
    );

    // Calculate revenue
    const totalRevenue = paymentsArray.reduce((sum, payment) => sum + (payment.amount || 0), 0);
    const todayRevenue = todayTransactions.reduce((sum, t) => sum + (t.amount || 0), 0);
    const weekRevenue = weekTransactions.reduce((sum, t) => sum + (t.amount || 0), 0);
    const monthRevenue = monthTransactions.reduce((sum, t) => sum + (t.amount || 0), 0);

    // Calculate Paystack fees (3%)
    const totalPaystackFees = transactionsArray.reduce((sum, t) => sum + (t.paystackFee || 0), 0);
    const todayPaystackFees = todayTransactions.reduce((sum, t) => sum + (t.paystackFee || 0), 0);
    const weekPaystackFees = weekTransactions.reduce((sum, t) => sum + (t.paystackFee || 0), 0);
    const monthPaystackFees = monthTransactions.reduce((sum, t) => sum + (t.paystackFee || 0), 0);

    // Net revenue (after Paystack fees)
    const netRevenue = totalRevenue - totalPaystackFees;
    const todayNetRevenue = todayRevenue - todayPaystackFees;
    const weekNetRevenue = weekRevenue - weekPaystackFees;
    const monthNetRevenue = monthRevenue - monthPaystackFees;

    // Top packages
    const packageSales = {};
    transactionsArray.forEach(t => {
      if (t.packageName) {
        packageSales[t.packageName] = (packageSales[t.packageName] || 0) + 1;
      }
    });

    const topPackages = Object.entries(packageSales)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 5)
      .map(([name, count]) => ({ name, count }));

    // Network performance
    const networkStats = {
      mtn: transactionsArray.filter(t => t.network === 'mtn').length,
      at: transactionsArray.filter(t => t.network === 'at').length
    };

    const stats = {
      totalUsers: usersArray.length,
      totalTransactions: transactionsArray.length,
      totalRevenue,
      netRevenue: parseFloat(netRevenue.toFixed(2)),
      totalPaystackFees: parseFloat(totalPaystackFees.toFixed(2)),
      successfulTransactions: transactionsArray.filter(t => t.status === 'success').length,
      todayTransactions: todayTransactions.length,
      todayRevenue,
      todayNetRevenue: parseFloat(todayNetRevenue.toFixed(2)),
      todayPaystackFees: parseFloat(todayPaystackFees.toFixed(2)),
      weekRevenue,
      weekNetRevenue: parseFloat(weekNetRevenue.toFixed(2)),
      weekPaystackFees: parseFloat(weekPaystackFees.toFixed(2)),
      monthRevenue,
      monthNetRevenue: parseFloat(monthNetRevenue.toFixed(2)),
      monthPaystackFees: parseFloat(monthPaystackFees.toFixed(2)),
      newUsers: usersArray.filter(u => new Date(u.createdAt) >= monthAgo).length,
      topPackages,
      networkStats,
      successRate: transactionsArray.length > 0 ? 
        (transactionsArray.filter(t => t.status === 'success').length / transactionsArray.length * 100).toFixed(1) : 0
    };

    res.json({ success: true, stats });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 2. USER MANAGEMENT ENDPOINTS
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const usersSnapshot = await admin.database().ref('users').once('value');
    const transactionsSnapshot = await admin.database().ref('transactions').once('value');
    
    const users = usersSnapshot.val() || {};
    const transactions = transactionsSnapshot.val() || {};

    const usersArray = Object.entries(users).map(([uid, userData]) => {
      const userTransactions = Object.values(transactions).filter(t => t.userId === uid);
      const totalSpent = userTransactions.reduce((sum, t) => sum + (t.amount || 0), 0);
      
      return {
        uid,
        ...userData,
        totalSpent,
        transactionCount: userTransactions.length,
        lastActivity: userData.lastLogin || userData.createdAt,
        status: userData.suspended ? 'suspended' : 'active',
        pricingGroup: userData.pricingGroup || 'regular'
      };
    });

    res.json({ success: true, users: usersArray });
  } catch (error) {
    console.error('Admin users error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update user role (promote/demote)
app.post('/api/admin/users/:uid/update-role', requireAdmin, async (req, res) => {
  try {
    const { uid } = req.params;
    const { role } = req.body;

    console.log('🔄 Updating user role:', { uid, role });

    if (!['regular', 'vip', 'premium'].includes(role)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid role. Must be: regular, vip, or premium' 
      });
    }

    const userRef = admin.database().ref('users/' + uid);
    const userSnapshot = await userRef.once('value');
    
    if (!userSnapshot.exists()) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const userData = userSnapshot.val();
    const currentRole = userData.pricingGroup || 'regular';
    
    await userRef.update({ 
      pricingGroup: role,
      roleUpdatedAt: new Date().toISOString(),
      previousRole: currentRole
    });

    // Log admin action
    const logRef = admin.database().ref('adminLogs').push();
    await logRef.set({
      adminId: req.session.user.uid,
      action: 'update_user_role',
      targetUserId: uid,
      details: `Changed user role from ${currentRole} to ${role}`,
      timestamp: new Date().toISOString(),
      ip: req.ip
    });

    console.log('✅ User role updated successfully:', { uid, from: currentRole, to: role });

    res.json({ 
      success: true, 
      message: `User role updated from ${currentRole} to ${role} successfully`,
      previousRole: currentRole,
      newRole: role
    });
  } catch (error) {
    console.error('❌ Update user role error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Toggle user suspension
app.post('/api/admin/users/:uid/toggle-suspend', requireAdmin, async (req, res) => {
  try {
    const { uid } = req.params;
    const userRef = admin.database().ref('users/' + uid);
    const userSnapshot = await userRef.once('value');
    
    if (!userSnapshot.exists()) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const currentStatus = userSnapshot.val().suspended || false;
    await userRef.update({ suspended: !currentStatus });

    // Log admin action
    const logRef = admin.database().ref('adminLogs').push();
    await logRef.set({
      adminId: req.session.user.uid,
      action: 'toggle_user_suspension',
      targetUserId: uid,
      details: `User ${!currentStatus ? 'suspended' : 'activated'}`,
      timestamp: new Date().toISOString(),
      ip: req.ip
    });

    res.json({ 
      success: true, 
      message: `User ${!currentStatus ? 'suspended' : 'activated'} successfully`,
      suspended: !currentStatus
    });
  } catch (error) {
    console.error('Toggle suspend error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Add funds to user wallet
app.post('/api/admin/users/:uid/add-funds', requireAdmin, async (req, res) => {
  try {
    const { uid } = req.params;
    const { amount, note } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid amount' });
    }

    const userRef = admin.database().ref('users/' + uid);
    const userSnapshot = await userRef.once('value');
    
    if (!userSnapshot.exists()) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const currentBalance = userSnapshot.val().walletBalance || 0;
    const newBalance = currentBalance + parseFloat(amount);

    await userRef.update({ walletBalance: newBalance });

    // Record the manual fund addition
    const fundRef = admin.database().ref('manualFunds').push();
    await fundRef.set({
      userId: uid,
      adminId: req.session.user.uid,
      amount: parseFloat(amount),
      note: note || 'Manual fund addition by admin',
      previousBalance: currentBalance,
      newBalance: newBalance,
      timestamp: new Date().toISOString(),
      type: 'addition'
    });

    // Log admin action
    const logRef = admin.database().ref('adminLogs').push();
    await logRef.set({
      adminId: req.session.user.uid,
      action: 'add_funds',
      targetUserId: uid,
      details: `Added ₵${amount} to user wallet`,
      timestamp: new Date().toISOString(),
      ip: req.ip
    });

    res.json({ 
      success: true, 
      message: `₵${amount} added successfully`,
      newBalance: newBalance
    });
  } catch (error) {
    console.error('Add funds error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// NEW: Deduct funds from user wallet
app.post('/api/admin/users/:uid/deduct-funds', requireAdmin, async (req, res) => {
  try {
    const { uid } = req.params;
    const { amount, note } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid amount' });
    }

    const userRef = admin.database().ref('users/' + uid);
    const userSnapshot = await userRef.once('value');
    
    if (!userSnapshot.exists()) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const userData = userSnapshot.val();
    const currentBalance = userData.walletBalance || 0;

    if (currentBalance < amount) {
      return res.status(400).json({ 
        success: false, 
        error: 'Insufficient balance. User only has ₵' + currentBalance 
      });
    }

    const newBalance = currentBalance - parseFloat(amount);

    await userRef.update({ walletBalance: newBalance });

    // Record the manual fund deduction
    const fundRef = admin.database().ref('manualFunds').push();
    await fundRef.set({
      userId: uid,
      adminId: req.session.user.uid,
      amount: parseFloat(amount),
      note: note || 'Manual fund deduction by admin',
      previousBalance: currentBalance,
      newBalance: newBalance,
      timestamp: new Date().toISOString(),
      type: 'deduction'
    });

    // Log admin action
    const logRef = admin.database().ref('adminLogs').push();
    await logRef.set({
      adminId: req.session.user.uid,
      action: 'deduct_funds',
      targetUserId: uid,
      details: `Deducted ₵${amount} from user wallet`,
      timestamp: new Date().toISOString(),
      ip: req.ip
    });

    res.json({ 
      success: true, 
      message: `₵${amount} deducted successfully`,
      newBalance: newBalance
    });
  } catch (error) {
    console.error('Deduct funds error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 3. PACKAGE MANAGEMENT ENDPOINTS
app.get('/api/admin/packages', requireAdmin, async (req, res) => {
  try {
    // Use cache if available
    if (!packageCache.isInitialized) {
      const packagesSnapshot = await admin.database().ref('packages').once('value');
      const packages = packagesSnapshot.val() || {};
      
      packageCache.mtn = Object.entries(packages.mtn || {}).map(([key, pkg]) => ({
        id: key,
        ...pkg
      }));
      
      packageCache.at = Object.entries(packages.at || {}).map(([key, pkg]) => ({
        id: key,
        ...pkg
      }));
      packageCache.isInitialized = true;
    }
    
    res.json({ 
      success: true, 
      packages: {
        mtn: packageCache.mtn,
        at: packageCache.at
      }
    });
  } catch (error) {
    console.error('Admin packages error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update package price
app.post('/api/admin/packages/update-price', requireAdmin, async (req, res) => {
  try {
    const { network, packageId, newPrice } = req.body;
    
    console.log('🔄 Updating package:', { network, packageId, newPrice });

    if (!network || !packageId || !newPrice) {
      return res.status(400).json({ 
        success: false, 
        error: 'Network, packageId, and newPrice are required' 
      });
    }

    const packagesRef = admin.database().ref(`packages/${network}`);
    const packagesSnapshot = await packagesRef.once('value');
    const packages = packagesSnapshot.val() || {};
    
    let packageKey = packageId;
    
    // Remove network prefix if present
    if (packageId.startsWith('mtn-')) {
      packageKey = packageId.replace('mtn-', '');
    } else if (packageId.startsWith('at-')) {
      packageKey = packageId.replace('at-', '');
    }
    
    // Convert to match Firebase keys
    const keyMap = {
      '1gb': '1gb',
      '2gb': '2', '2': '2',
      '3gb': '3', '3': '3',
      '4gb': '4', '4': '4',
      '5gb': '5', '5': '5',
      '6gb': '6', '6': '6',
      '7gb': '7', '7': '7',
      '8gb': '8', '8': '8',
      '9gb': '9', '9': '9',
      '10gb': '10', '10': '10',
      '20gb': '20', '20': '20',
      '30gb': '30', '30': '30',
      '40gb': '40', '40': '40',
      '50gb': '50', '50': '50',
      '60gb': '60', '60': '60',
      '70gb': '70', '70': '70',
      '80gb': '80', '80': '80',
      '90gb': '90', '90': '90',
      '100gb': '100gb'
    };
    
    if (keyMap[packageKey]) {
      packageKey = keyMap[packageKey];
    }
    
    // Check if package exists
    if (!packages[packageKey]) {
      return res.status(404).json({ 
        success: false, 
        error: `Package not found. Available packages: ${Object.keys(packages).join(', ')}` 
      });
    }

    const oldPrice = packages[packageKey].price;
    const packageName = packages[packageKey].name;

    // Update the price
    await admin.database().ref(`packages/${network}/${packageKey}`).update({
      price: parseFloat(newPrice)
    });

    // Update cache
    if (packageCache[network]) {
      const packageIndex = packageCache[network].findIndex(pkg => pkg.id === packageKey);
      if (packageIndex !== -1) {
        packageCache[network][packageIndex].price = parseFloat(newPrice);
      }
    }

    // Log admin action
    const logRef = admin.database().ref('adminLogs').push();
    await logRef.set({
      adminId: req.session.user.uid,
      action: 'update_package_price',
      targetPackage: packageKey,
      details: `Updated ${network} package ${packageName} from ₵${oldPrice} to ₵${newPrice}`,
      timestamp: new Date().toISOString(),
      ip: req.ip
    });

    res.json({ 
      success: true, 
      message: `"${packageName}" price updated to ₵${newPrice}`,
      oldPrice: oldPrice,
      newPrice: parseFloat(newPrice),
      packageName: packageName
    });
  } catch (error) {
    console.error('Update package error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Toggle package active status
app.post('/api/admin/packages/toggle-active', requireAdmin, async (req, res) => {
  try {
    const { network, packageId } = req.body;
    
    if (!network || !packageId) {
      return res.status(400).json({ 
        success: false, 
        error: 'Network and packageId are required' 
      });
    }

    const packageRef = admin.database().ref(`packages/${network}/${packageId}`);
    const packageSnapshot = await packageRef.once('value');
    
    if (!packageSnapshot.exists()) {
      return res.status(404).json({ success: false, error: 'Package not found' });
    }

    const currentStatus = packageSnapshot.val().active !== false;
    await packageRef.update({ active: !currentStatus });

    // Update cache
    if (packageCache[network]) {
      const packageIndex = packageCache[network].findIndex(pkg => pkg.id === packageId);
      if (packageIndex !== -1) {
        packageCache[network][packageIndex].active = !currentStatus;
      }
    }

    // Log admin action
    const logRef = admin.database().ref('adminLogs').push();
    await logRef.set({
      adminId: req.session.user.uid,
      action: 'toggle_package_status',
      targetPackage: packageId,
      details: `Package ${!currentStatus ? 'activated' : 'deactivated'}`,
      timestamp: new Date().toISOString(),
      ip: req.ip
    });

    res.json({ 
      success: true, 
      message: `Package ${!currentStatus ? 'activated' : 'deactivated'}`,
      active: !currentStatus
    });
  } catch (error) {
    console.error('Toggle package error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create a new package
app.post('/api/admin/packages/create', requireAdmin, async (req, res) => {
  try {
    const { network, id, name, price, validity, active } = req.body;

    if (!network || !id || !name || price === undefined) {
      return res.status(400).json({ success: false, error: 'network, id, name and price are required' });
    }

    const packageRef = admin.database().ref(`packages/${network}/${id}`);
    const snap = await packageRef.once('value');
    if (snap.exists()) {
      return res.status(400).json({ success: false, error: 'Package with that id already exists' });
    }

    const payload = {
      name,
      price: parseFloat(price),
      validity: validity || null,
      active: active === false ? false : true,
      createdAt: new Date().toISOString()
    };

    await packageRef.set(payload);

    // Update cache if present
    if (packageCache[network]) {
      packageCache[network].push({ id, ...payload });
    }

    // Log admin action
    const logRef = admin.database().ref('adminLogs').push();
    await logRef.set({
      adminId: req.session.user.uid,
      action: 'create_package',
      targetPackage: id,
      details: `Created package ${id} (${name}) on ${network}`,
      timestamp: new Date().toISOString(),
      ip: req.ip
    });

    res.json({ success: true, message: 'Package created successfully', package: { id, ...payload } });
  } catch (error) {
    console.error('Create package error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 4. ORDER MANAGEMENT ENDPOINTS
app.get('/api/admin/transactions', requireAdmin, async (req, res) => {
  try {
    const { status, network, dateFrom, dateTo, search, limit } = req.query;
    
    const transactionsSnapshot = await admin.database().ref('transactions').once('value');
    const usersSnapshot = await admin.database().ref('users').once('value');
    
    let transactions = Object.entries(transactionsSnapshot.val() || {}).map(([id, transaction]) => ({
      id,
      ...transaction
    }));

    const users = usersSnapshot.val() || {};

    // Apply filters
    let filteredTransactions = transactions;

    if (status && status !== 'all') {
      filteredTransactions = filteredTransactions.filter(t => t.status === status);
    }
    
    if (network && network !== 'all') {
      filteredTransactions = filteredTransactions.filter(t => t.network === network);
    }
    
    if (dateFrom) {
      filteredTransactions = filteredTransactions.filter(t => 
        new Date(t.timestamp) >= new Date(dateFrom)
      );
    }
    
    if (dateTo) {
      const endDate = new Date(dateTo);
      endDate.setHours(23, 59, 59, 999);
      filteredTransactions = filteredTransactions.filter(t => 
        new Date(t.timestamp) <= endDate
      );
    }
    
    if (search) {
      const searchLower = search.toLowerCase();
      filteredTransactions = filteredTransactions.filter(t => 
        t.phoneNumber?.includes(search) ||
        t.reference?.includes(search) ||
        t.packageName?.toLowerCase().includes(searchLower) ||
        t.userId?.includes(search)
      );
    }

    // Apply limit if specified
    if (limit) {
      filteredTransactions = filteredTransactions.slice(0, parseInt(limit));
    }

    // Add user information to transactions
    const transactionsWithUsers = filteredTransactions.map(transaction => {
      const user = users[transaction.userId];
      return {
        ...transaction,
        userName: user ? `${user.firstName} ${user.lastName}` : 'Unknown User',
        userEmail: user?.email || 'N/A'
      };
    });

    // Sort by timestamp (newest first)
    transactionsWithUsers.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    res.json({ success: true, transactions: transactionsWithUsers });
  } catch (error) {
    console.error('Admin transactions error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get single transaction details
app.get('/api/admin/transactions/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const txRef = admin.database().ref(`transactions/${id}`);
    const txSnap = await txRef.once('value');

    if (!txSnap.exists()) {
      return res.status(404).json({ success: false, error: 'Transaction not found' });
    }

    const transaction = txSnap.val();

    // Attach user info if present
    const userRef = admin.database().ref(`users/${transaction.userId}`);
    const userSnap = await userRef.once('value');
    const user = userSnap.exists() ? userSnap.val() : null;

    res.json({ success: true, transaction: { id, ...transaction, user } });
  } catch (error) {
    console.error('Get transaction error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Process refund
app.post('/api/admin/transactions/:id/refund', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;
    
    if (!reason) {
      return res.status(400).json({ 
        success: false, 
        error: 'Refund reason is required' 
      });
    }

    const transactionRef = admin.database().ref('transactions/' + id);
    const transactionSnapshot = await transactionRef.once('value');
    
    if (!transactionSnapshot.exists()) {
      return res.status(404).json({ success: false, error: 'Transaction not found' });
    }

    const transaction = transactionSnapshot.val();
    
    // Refund to user wallet
    const userRef = admin.database().ref('users/' + transaction.userId);
    const userSnapshot = await userRef.once('value');
    const userData = userSnapshot.val();
    
    const newBalance = (userData.walletBalance || 0) + transaction.amount;
    await userRef.update({ walletBalance: newBalance });

    // Update transaction status
    await transactionRef.update({ 
      status: 'refunded',
      refundReason: reason,
      refundedAt: new Date().toISOString()
    });

    // Record refund
    const refundRef = admin.database().ref('refunds').push();
    await refundRef.set({
      transactionId: id,
      userId: transaction.userId,
      amount: transaction.amount,
      reason,
      processedBy: req.session.user.uid,
      processedAt: new Date().toISOString()
    });

    // Log admin action
    const logRef = admin.database().ref('adminLogs').push();
    await logRef.set({
      adminId: req.session.user.uid,
      action: 'process_refund',
      targetTransaction: id,
      details: `Refunded ₵${transaction.amount} for transaction ${id}`,
      timestamp: new Date().toISOString(),
      ip: req.ip
    });

    res.json({ 
      success: true, 
      message: `₵${transaction.amount} refunded to user wallet`,
      newBalance: newBalance
    });
  } catch (error) {
    console.error('Refund error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 5. PRICING CONTROL ENDPOINTS
app.get('/api/admin/pricing/groups', requireAdmin, async (req, res) => {
  try {
    const pricingSnapshot = await admin.database().ref('pricingGroups').once('value');
    const pricing = pricingSnapshot.val() || {
      regular: { discount: 0, name: 'Regular Users' },
      vip: { discount: 10, name: 'VIP Users' },
      premium: { discount: 15, name: 'Premium Users' }
    };

    res.json({ success: true, pricingGroups: pricing });
  } catch (error) {
    console.error('Pricing groups error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/admin/pricing/groups/update', requireAdmin, async (req, res) => {
  try {
    const { group, discount, name } = req.body;
    
    if (!group || discount === undefined) {
      return res.status(400).json({ 
        success: false, 
        error: 'Group and discount are required' 
      });
    }

    if (discount < 0 || discount > 50) {
      return res.status(400).json({ 
        success: false, 
        error: 'Discount must be between 0 and 50' 
      });
    }
    
    const groupNames = {
      regular: 'Regular Users',
      vip: 'VIP Users', 
      premium: 'Premium Users'
    };
    
    await admin.database().ref(`pricingGroups/${group}`).set({
      discount: parseFloat(discount),
      name: name || groupNames[group] || group
    });

    // Log admin action
    const logRef = admin.database().ref('adminLogs').push();
    await logRef.set({
      adminId: req.session.user.uid,
      action: 'update_pricing_group',
      targetGroup: group,
      details: `Updated ${group} pricing group discount to ${discount}%`,
      timestamp: new Date().toISOString(),
      ip: req.ip
    });

    res.json({ 
      success: true, 
      message: `Pricing group ${group} updated successfully` 
    });
  } catch (error) {
    console.error('Update pricing group error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 6. SYSTEM MONITORING ENDPOINTS
app.get('/api/admin/system/status', requireAdmin, async (req, res) => {
  try {
    // Check DataMart status (balance check not available in DataMart API)
    let datamartStatus = { status: 'unknown', note: 'Balance check not available' };
    try {
      // Test API connectivity by making a simple request to data-packages endpoint
      const datamartResponse = await axios.get(
        'https://api.datamartgh.shop/api/developer/data-packages?network=YELLO',
        {
          headers: {
            'X-API-Key': process.env.DATAMART_API_KEY,
            'Content-Type': 'application/json'
          },
          timeout: 10000
        }
      );
      datamartStatus = { status: 'online', note: 'API is accessible' };
    } catch (error) {
      datamartStatus = { status: 'offline', error: error.message };
    }

    // Check Paystack status
    let paystackStatus = { status: 'unknown' };
    try {
      await axios.get(
        `${process.env.PAYSTACK_BASE_URL}/bank`,
        {
          headers: {
            'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
          },
          timeout: 10000
        }
      );
      paystackStatus = { status: 'online' };
    } catch (error) {
      paystackStatus = { status: 'offline', error: error.message };
    }

    // Get system metrics
    const transactionsSnapshot = await admin.database().ref('transactions').once('value');
    const transactions = Object.values(transactionsSnapshot.val() || {});
    
    const recentTransactions = transactions.filter(t => 
      new Date(t.timestamp) > new Date(Date.now() - 24 * 60 * 60 * 1000)
    );

    const successRate = recentTransactions.length > 0 ? 
      (recentTransactions.filter(t => t.status === 'success').length / recentTransactions.length * 100).toFixed(1) : 100;

    const systemStatus = {
      datamart: datamartStatus,
      paystack: paystackStatus,
      firebase: { status: 'online' },
      server: { status: 'healthy' },
      successRate: parseFloat(successRate),
      recentTransactions: recentTransactions.length,
      packageCache: {
        mtnCount: packageCache.mtn.length,
        atCount: packageCache.at.length,
        lastUpdated: packageCache.lastUpdated ? new Date(packageCache.lastUpdated).toISOString() : null
      }
    };

    res.json({ success: true, systemStatus });
  } catch (error) {
    console.error('System status error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 7. SECURITY LOGS ENDPOINT
app.get('/api/admin/security/logs', requireAdmin, async (req, res) => {
  try {
    const logsSnapshot = await admin.database().ref('adminLogs').once('value');
    const logs = Object.entries(logsSnapshot.val() || {}).map(([id, log]) => ({
      id,
      ...log
    })).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    res.json({ success: true, logs });
  } catch (error) {
    console.error('Security logs error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ====================
// ENHANCED WEBHOOKS AND UTILITIES
// ====================

// Enhanced DataMart webhook (if supported by DataMart)
// Rate limiting removed for webhook endpoint.
app.post('/api/datamart-webhook', async (req, res) => {
  console.log('📩 DataMart Webhook received:', req.body);
  const { reference, transactionReference, purchaseId, status, message } = req.body;

  const transactionRef = reference || transactionReference || purchaseId;
  if (!transactionRef) {
    return res.status(400).json({ error: 'Missing reference' });
  }

  try {
    const snap = await admin.database()
      .ref('transactions')
      .orderByChild('reference')
      .equalTo(transactionRef)
      .once('value');

    if (!snap.val()) {
      // Try searching by transactionId or datamartTransactionId
      const allTxs = await admin.database().ref('transactions').once('value');
      const txEntries = Object.entries(allTxs.val() || {});
      const foundTx = txEntries.find(([id, tx]) => 
        tx.datamartTransactionId === transactionRef || 
        tx.transactionId === transactionRef
      );
      
      if (!foundTx) {
        console.log('❌ Webhook: No transaction found for reference:', transactionRef);
        return res.status(404).json({ error: 'Transaction not found' });
      }
      
      const [txId, tx] = foundTx;
      
      // Don't process if already confirmed
      if (tx.datamartConfirmed) {
        console.log('ℹ️ Webhook: Transaction already processed:', transactionRef);
        return res.json({ success: true, message: 'Already processed' });
      }

      let update = { 
        datamartConfirmed: true, 
        confirmedAt: new Date().toISOString(),
        datamartWebhookData: req.body
      };

      if (status === 'success' || status === 'completed' || message?.toLowerCase().includes('delivered')) {
        update.status = 'delivered';
        update.datamartStatus = 'delivered';
        update.reason = 'Package delivered via webhook';
        console.log('✅ Webhook: Marking as delivered:', transactionRef);
      } else {
        update.status = 'failed';
        update.datamartStatus = status || 'failed';
        update.reason = message || 'Delivery failed via webhook';
        console.log('❌ Webhook: Marking as failed:', transactionRef);

        // Auto-refund only if it was previously successful
        if (tx.status === 'success') {
          const user = (await admin.database().ref(`users/${tx.userId}`).once('value')).val();
          await admin.database().ref(`users/${tx.userId}`).update({
            walletBalance: (user.walletBalance || 0) + tx.amount
          });
          await admin.database().ref('refunds').push({
            transactionId: txId,
            userId: tx.userId,
            amount: tx.amount,
            reason: `Auto-refund: ${update.reason}`,
            timestamp: new Date().toISOString()
          });
          console.log('💰 Webhook: Auto-refund processed for:', transactionRef);
        }
      }

      await admin.database().ref(`transactions/${txId}`).update(update);
      console.log('✅ Webhook: Transaction updated successfully:', transactionRef);
      // If delivered and transaction was originally successful, send SMS notification
      if (update.status === 'delivered' && tx.status === 'success') {
        try {
          const network = (tx.network || '').toUpperCase();
          const packageName = tx.packageName || tx.package || '';
          const smsMessage = `Your ${network} data purchase (${packageName}) with reference ${transactionRef} has been delivered. Thank you for using DataSell.`;
          // send to stored phone and fallback to transaction phoneNumber
          await sendSmsToUser(tx.userId, tx.phoneNumber, smsMessage);
        } catch (smsErr) {
          console.error('SMS notification error for delivered transaction', transactionRef, smsErr);
        }
      }
      return res.json({ success: true });
    }

    // If transaction found by reference
    const [txId, tx] = Object.entries(snap.val())[0];
    
    // Don't process if already confirmed
    if (tx.datamartConfirmed) {
      console.log('ℹ️ Webhook: Transaction already processed:', transactionRef);
      return res.json({ success: true, message: 'Already processed' });
    }

    let update = { 
      datamartConfirmed: true, 
      confirmedAt: new Date().toISOString(),
      datamartWebhookData: req.body
    };

    if (status === 'success' || status === 'completed' || message?.toLowerCase().includes('delivered')) {
      update.status = 'delivered';
      update.datamartStatus = 'delivered';
      update.reason = 'Package delivered via webhook';
      console.log('✅ Webhook: Marking as delivered:', transactionRef);
    } else {
      update.status = 'failed';
      update.datamartStatus = status || 'failed';
      update.reason = message || 'Delivery failed via webhook';
      console.log('❌ Webhook: Marking as failed:', transactionRef);

      // Auto-refund only if it was previously successful
      if (tx.status === 'success') {
        const user = (await admin.database().ref(`users/${tx.userId}`).once('value')).val();
        await admin.database().ref(`users/${tx.userId}`).update({
          walletBalance: (user.walletBalance || 0) + tx.amount
        });
        await admin.database().ref('refunds').push({
          transactionId: txId,
          userId: tx.userId,
          amount: tx.amount,
          reason: `Auto-refund: ${update.reason}`,
          timestamp: new Date().toISOString()
        });
        console.log('💰 Webhook: Auto-refund processed for:', transactionRef);
      }
    }

    await admin.database().ref(`transactions/${txId}`).update(update);
    console.log('✅ Webhook: Transaction updated successfully:', transactionRef);
    // If delivered and transaction was originally successful, send SMS notification
    if (update.status === 'delivered' && tx.status === 'success') {
      try {
        const network = (tx.network || '').toUpperCase();
        const packageName = tx.packageName || tx.package || '';
        const smsMessage = `Your ${network} data purchase (${packageName}) with reference ${transactionRef} has been delivered. Thank you for using DataSell.`;
        // send to stored phone and fallback to transaction phoneNumber
        await sendSmsToUser(tx.userId, tx.phoneNumber, smsMessage);
      } catch (smsErr) {
        console.error('SMS notification error for delivered transaction', transactionRef, smsErr);
      }
    }
    res.json({ success: true });
  } catch (err) {
    console.error('❌ Webhook error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Enhanced Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    server: 'DataSell API',
    environment: process.env.NODE_ENV || 'development',
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    version: '2.0.0'
  });
});

// Enhanced Ping endpoint
app.get('/api/ping', (req, res) => {
  res.json({ 
    message: 'pong', 
    timestamp: Date.now(),
    server: 'DataSell API'
  });
});

// Enhanced Firebase config endpoint
app.get('/api/firebase-config', requireAuth, (req, res) => {
  const config = {
    apiKey: process.env.FIREBASE_API_KEY,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN,
    databaseURL: process.env.FIREBASE_DATABASE_URL,
    projectId: process.env.FIREBASE_PROJECT_ID,
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
    appId: process.env.FIREBASE_APP_ID
  };

  // Validate that all required config values are present
  const missingConfigs = Object.entries(config)
    .filter(([key, value]) => !value)
    .map(([key]) => key);

  if (missingConfigs.length > 0) {
    console.error('❌ Missing Firebase config values:', missingConfigs);
    return res.status(500).json({ 
      success: false, 
      error: 'Firebase configuration incomplete' 
    });
  }

  res.json(config);
});

// Enhanced Error handling middleware
app.use((error, req, res, next) => {
  console.error('🚨 Server error:', {
    message: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    ip: req.ip
  });
  
  res.status(500).json({ 
    success: false, 
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : error.message 
  });
});

// Enhanced 404 handler
app.use((req, res) => {
  console.log('🔍 404 Not Found:', { url: req.url, method: req.method });
  res.status(404).json({ 
    success: false, 
    error: 'Endpoint not found' 
  });
});

// Process error handlers for production stability
process.on('uncaughtException', (error) => {
  console.error('🚨 Uncaught Exception:', error);
  // Don't exit immediately in production, log and continue
  if (process.env.NODE_ENV === 'production') {
    console.error('Uncaught exception logged, continuing...');
  } else {
    process.exit(1);
  }
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('🚨 Unhandled Rejection at:', promise, 'reason:', reason);
  // Log but don't crash in production
  if (process.env.NODE_ENV !== 'production') {
    process.exit(1);
  }
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
  console.log('🔄 SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🔄 SIGINT received, shutting down gracefully');
  process.exit(0);
});

// Start server with enhanced logging
// Bind to 0.0.0.0 to accept connections from all network interfaces (required for Render)
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
🚀 DataSell Server v2.0.0
📍 Port: ${PORT}
🌐 Environment: ${process.env.NODE_ENV || 'development'}
🔗 Base URL: ${process.env.BASE_URL}
🔥 Firebase: ${process.env.FIREBASE_PROJECT_ID}
📡 DataMart: ${process.env.DATAMART_API_KEY ? 'Integrated' : 'Missing'}
💳 Paystack: ${process.env.PAYSTACK_SECRET_KEY ? 'Live Mode' : 'Missing'}
👑 Admin Panel: /admin
💾 Package Cache: ${packageCache.isInitialized ? 'Active' : 'Initializing'}
  `);
});
