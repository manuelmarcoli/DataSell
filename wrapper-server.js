#!/usr/bin/env node
/**
 * Wrapper Server - Provides the /api/profile/stats endpoint and serves static files
 */

require('dotenv').config();

const express = require('express');
const admin = require('firebase-admin');
const path = require('path');
const session = require('express-session');

const app = express();
const mainPort = process.env.PORT || 3000;

// Initialize Firebase
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

// Auth middleware  
const requireAuth = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        // For testing, allow /api/profile/stats without auth if uid is provided in query
        if (req.path === '/api/profile/stats' && req.query.uid) {
            req.session.user = { uid: req.query.uid };
            next();
        } else {
            return res.status(401).json({ success: false, error: 'Unauthorized' });
        }
    }
};

// THE PROFILE STATS ENDPOINT
app.get('/api/profile/stats', requireAuth, async (req, res) => {
    try {
        const uid = req.session.user?.uid || req.query.uid;
        
        if (!uid) {
            return res.status(400).json({ success: false, error: 'User ID not found' });
        }

        console.log(`📊 GET /api/profile/stats - User: ${uid}`);

        // Query transactions table
        const transactionsSnap = await admin.database()
            .ref('transactions')
            .orderByChild('userId')
            .equalTo(uid)
            .once('value');

        const transactions = transactionsSnap.val() || {};

        // Count total orders
        const totalOrders = Object.keys(transactions).length;

        // Count successful orders
        const successfulOrders = Object.values(transactions)
            .filter(tx => tx.status === 'success' || tx.status === 'completed' || tx.status === true)
            .length;

        // Calculate total spent
        const totalSpent = Object.values(transactions)
            .reduce((sum, tx) => sum + (parseFloat(tx.amount) || 0), 0);

        // Get wallet balance and member date
        const userData = (await admin.database().ref('users/' + uid).once('value')).val() || {};
        const walletBalance = userData.walletBalance || 0;
        const memberSince = userData.createdAt || new Date().toISOString();

        console.log(`   ✓ Found: ${totalOrders} orders, ${successfulOrders} successful, GH₵${totalSpent.toFixed(2)} spent`);

        const stats = {
            totalOrders,
            successfulOrders,
            totalSpent,
            walletBalance,
            memberSince
        };

        return res.json({ success: true, stats });

    } catch (error) {
        console.error(`❌ Profile stats error:`, error.message);
        return res.status(500).json({
            success: false,
            error: 'Failed to fetch profile stats'
        });
    }
});

// Serve public static files
app.use(express.static(path.join(__dirname, 'public')));

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
app.listen(mainPort, () => {
    console.log(`\n🚀 DataSell Server running on http://localhost:${mainPort}`);
    console.log(`   ✓ Profile Stats API: http://localhost:${mainPort}/api/profile/stats`);
    console.log(`   ✓ Application: http://localhost:${mainPort}\n`);
});

// Error handling
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error.message);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection:', reason);
});
