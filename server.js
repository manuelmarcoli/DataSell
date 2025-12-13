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
console.log('Loaded environment variables:', process.env);
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
  res.send(`window.__DOMAIN = ${JSON.stringify(domainEnv)}; window.__BASE_URL = ${JSON.stringify(base)}; window.__FIREBASE_CONFIG = ${JSON.stringify(firebaseConfig)}; window.__FCM_VAPID_KEY = ${JSON.stringify(vapid)};`);
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
      
      // Provide clearer error messages
      let errorMessage;
      if (isOutOfStock) {
        // Check if it's specifically a provider wallet balance issue
        if (datamartErrorData.message?.toLowerCase().includes('insufficient wallet balance') || 
            datamartErrorData.message?.toLowerCase().includes('insufficient balance')) {
          errorMessage = 'Service temporarily unavailable - Provider balance issue. Please try again later or contact support.';
        } else {
          errorMessage = 'Out of Stock - Please try again later';
        }
      } else {
        errorMessage = datamartErrorData.message || 'Purchase failed';
      }
      
      return res.status(400).json({ 
        success: false, 
        error: errorMessage,
        isOutOfStock: isOutOfStock,
        details: process.env.NODE_ENV !== 'production' ? datamartErrorData : undefined
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
// REFUND WALLET ON FAILED PURCHASE
// ====================

async function refundWallet(userId, amount) {
  try {
    const userRef = admin.database().ref(`users/${userId}`);
    const userSnap = await userRef.once('value');
    const user = userSnap.val();

    if (!user) {
      console.error(`User ${userId} not found. Refund failed.`);
      return;
    }

    const updatedBalance = (user.walletBalance || 0) + amount;
    await userRef.update({ walletBalance: updatedBalance });

    console.log(`Refunded ₵${amount} to user ${userId}. New balance: ₵${updatedBalance}`);
  } catch (error) {
    console.error(`Failed to refund ₵${amount} to user ${userId}:`, error);
  }
}

// Example route for purchase
app.post('/api/purchase', async (req, res) => {
  const { userId, amount, purchaseDetails } = req.body;

  try {
    // Deduct wallet balance
    const userRef = admin.database().ref(`users/${userId}`);
    const userSnap = await userRef.once('value');
    const user = userSnap.val();

    if (!user || user.walletBalance < amount) {
      return res.status(400).json({ success: false, error: 'Insufficient wallet balance' });
    }

    const newBalance = user.walletBalance - amount;
    await userRef.update({ walletBalance: newBalance });

    console.log(`Deducted ₵${amount} from user ${userId}. New balance: ₵${newBalance}`);

    // Simulate purchase process
    const purchaseSuccess = Math.random() > 0.2; // 80% success rate for simulation

    if (purchaseSuccess) {
      // Handle successful purchase
      console.log(`Purchase successful for user ${userId}`);
      return res.json({ success: true, message: 'Purchase completed successfully' });
    } else {
      // Refund on failure
      console.log(`Purchase failed for user ${userId}. Refunding ₵${amount}...`);
      await refundWallet(userId, amount);
      return res.status(500).json({ success: false, error: 'Purchase failed. Amount refunded to wallet.' });
    }
  } catch (error) {
    console.error('Error during purchase:', error);
    return res.status(500).json({ success: false, error: 'An error occurred during the purchase process.' });
  }
});
