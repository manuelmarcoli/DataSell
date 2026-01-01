const express = require('express');
const admin = require('firebase-admin');
const session = require('express-session');
require('dotenv').config();
const path = require('path');

const app = express();

// Initialize Firebase Admin
try {
    const serviceAccount = {
        'type': 'service_account',
        'project_id': process.env.FIREBASE_PROJECT_ID,
        'private_key_id': process.env.FIREBASE_PRIVATE_KEY_ID,
        'private_key': process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
        'client_email': process.env.FIREBASE_CLIENT_EMAIL,
        'client_id': process.env.FIREBASE_CLIENT_ID,
        'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
        'token_uri': 'https://oauth2.googleapis.com/token',
        'auth_provider_x509_cert_url': 'https://www.googleapis.com/oauth2/v1/certs',
        'client_x509_cert_url': process.env.FIREBASE_CLIENT_CERT_URL
    };

    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        databaseURL: process.env.FIREBASE_DATABASE_URL
    });

    console.log('✅ Firebase Admin initialized');
} catch (error) {
    console.error('❌ Firebase initialization failed:', error.message);
    process.exit(1);
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// Middleware to check authentication
const requireAuth = (req, res, next) => {
    // For testing, allow if session exists or if there's a demo uid
    if (req.session.user || req.query.uid) {
        if (req.query.uid && !req.session.user) {
            req.session.user = { uid: req.query.uid };
        }
        next();
    } else {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
};

// Profile stats endpoint
app.get('/api/profile/stats', requireAuth, async (req, res) => {
    try {
        const uid = req.session.user?.uid;
        
        if (!uid) {
            return res.status(400).json({ success: false, error: 'User ID not found' });
        }

        console.log(`\n📊 Fetching stats for user: ${uid}`);

        // Set timeout for the request
        const timeout = setTimeout(() => {
            console.warn('⏱️ Request timeout - taking too long to fetch from Firebase');
            res.status(504).json({ success: false, error: 'Request timeout' });
        }, 10000);

        // Query transactions table with value event
        const transactionsRef = admin.database().ref('transactions');
        const transactionsSnap = await transactionsRef.orderByChild('userId').equalTo(uid).once('value', null, function(error) {
            if (error) {
                clearTimeout(timeout);
                console.error('Firebase error:', error);
                res.status(500).json({ success: false, error: 'Database error' });
            }
        });

        clearTimeout(timeout);

        const transactions = transactionsSnap.val() || {};
        console.log(`📦 Found ${Object.keys(transactions).length} transactions`);

        // Count total orders
        const totalOrders = Object.keys(transactions).length;

        // Count successful orders
        const successfulOrders = Object.values(transactions)
            .filter(tx => tx.status === 'success' || tx.status === 'completed')
            .length;

        // Calculate total spent
        const totalSpent = Object.values(transactions)
            .reduce((sum, tx) => sum + (parseFloat(tx.amount) || 0), 0);

        // Get wallet balance from users table
        const userData = (await admin.database().ref('users/' + uid).once('value')).val() || {};
        const walletBalance = userData.walletBalance || 0;

        // Get member since date
        const memberSince = userData.createdAt || new Date().toISOString();

        console.log(`✅ Stats calculated: ${totalOrders} orders, ${successfulOrders} successful, GH₵${totalSpent.toFixed(2)} spent`);

        return res.json({
            success: true,
            totalOrders,
            successfulOrders,
            totalSpent: parseFloat(totalSpent.toFixed(2)),
            walletBalance,
            memberSince
        });

    } catch (error) {
        console.error('❌ Error fetching stats:', error.message);
        return res.status(500).json({
            success: false,
            error: 'Failed to fetch profile stats',
            details: error.message
        });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'Profile API' });
});

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

const PORT = 3001; // Use port 3001 to avoid conflict with main server on 3000

app.listen(PORT, () => {
    console.log(`\n🚀 Profile API Server running on http://localhost:${PORT}`);
    console.log(`   Profile stats endpoint: http://localhost:${PORT}/api/profile/stats?uid=<USER_UID>`);
});
