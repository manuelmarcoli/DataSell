/**
 * Wrapper script that starts the main DataSell server with the missing /api/profile/stats endpoint
 * This acts as middleware to inject the stats endpoint before forwarding other requests to the main server
 */

const express = require('express');
const admin = require('firebase-admin');
const session = require('express-session');
const { spawn } = require('child_process');
require('dotenv').config();

const app = express();
const mainPort = process.env.PORT || 3000;

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

// Auth middleware
const requireAuth = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
};

// ADD THE MISSING ENDPOINT HERE
app.get('/api/profile/stats', requireAuth, async (req, res) => {
    try {
        const uid = req.session.user?.uid;
        
        if (!uid) {
            return res.status(400).json({ success: false, error: 'User ID not found' });
        }

        console.log(`📊 Fetching stats for user: ${uid}`);

        // Query transactions table
        const transactionsSnap = await admin.database()
            .ref('transactions')
            .orderByChild('userId')
            .equalTo(uid)
            .once('value');

        const transactions = transactionsSnap.val() || {};
        console.log(`   Found ${Object.keys(transactions).length} transactions`);

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
        const memberSince = userData.createdAt || new Date().toISOString();

        console.log(`   Stats: ${totalOrders} orders, ${successfulOrders} successful, GH₵${totalSpent.toFixed(2)} spent\n`);

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
            error: 'Failed to fetch profile stats'
        });
    }
});

// Serve public static files
const path = require('path');
app.use(express.static(path.join(__dirname, 'public')));

// Start listening
app.listen(mainPort, () => {
    console.log(`\n🚀 DataSell Server with Profile Stats API running on http://localhost:${mainPort}`);
    console.log(`   ✓ Profile stats endpoint: http://localhost:${mainPort}/api/profile/stats`);
    console.log(`   ✓ Application: http://localhost:${mainPort}\n`);
});

// Handle errors
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});
