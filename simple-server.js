#!/usr/bin/env node
/**
 * Simple Profile Stats Server
 * Serves the /api/profile/stats endpoint with proper error handling
 */

require('dotenv').config();

const express = require('express');
const admin = require('firebase-admin');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

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

    console.log('✅ Firebase Admin initialized\n');
} catch (error) {
    console.error('❌ Firebase initialization failed:', error.message);
    process.exit(1);
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session middleware
app.use(require('express-session')({
    secret: process.env.SESSION_SECRET || 'development-secret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// Authentication middleware
const requireAuth = (req, res, next) => {
    if (req.session?.user) {
        next();
    } else {
        return res.status(401).json({ success: false, error: 'Authentication required' });
    }
};

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { email, password, remember } = req.body;

        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Email and password are required' 
            });
        }

        // Admin login
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

                // Set user session
                req.session.user = {
                    uid: userRecord.uid,
                    email: userRecord.email,
                    displayName: userRecord.displayName,
                    isAdmin: true
                };

                // Update last login
                admin.database().ref('users/' + userRecord.uid).update({
                    lastLogin: new Date().toISOString()
                }).catch(err => console.error('Failed to update lastLogin:', err));

                console.log('✅ Admin login successful for:', email);
                
                return res.json({ 
                    success: true, 
                    message: 'Login successful',
                    user: req.session.user
                });
            } else {
                return res.status(401).json({ 
                    success: false, 
                    error: 'Invalid credentials' 
                });
            }
        }

        // Regular user login (via Firebase REST API)
        const axios = require('axios');
        try {
            const signInResponse = await axios.post(
                `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_API_KEY}`,
                {
                    email,
                    password,
                    returnSecureToken: true
                }
            );

            const { localId, idToken, displayName } = signInResponse.data;

            // Get or create user record
            let userData = (await admin.database().ref('users/' + localId).once('value')).val();
            if (!userData) {
                userData = {
                    email,
                    firstName: displayName?.split(' ')[0] || 'User',
                    lastName: displayName?.split(' ')[1] || '',
                    phone: '',
                    walletBalance: 0,
                    createdAt: new Date().toISOString(),
                    isAdmin: false,
                    pricingGroup: 'regular',
                    suspended: false
                };
                await admin.database().ref('users/' + localId).set(userData);
            }

            // Set user session
            req.session.user = {
                uid: localId,
                email,
                displayName: displayName || email,
                isAdmin: userData.isAdmin || false
            };

            // Update last login
            admin.database().ref('users/' + localId).update({
                lastLogin: new Date().toISOString()
            }).catch(err => console.error('Failed to update lastLogin:', err));

            console.log('✅ User login successful for:', email);

            return res.json({ 
                success: true, 
                message: 'Login successful',
                user: req.session.user
            });
        } catch (error) {
            console.error('Login error:', error.response?.data || error.message);
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid email or password' 
            });
        }
    } catch (error) {
        console.error('❌ Login endpoint error:', error.message);
        return res.status(500).json({ success: false, error: 'Login failed' });
    }
});

// Get current user endpoint
app.get('/api/user', requireAuth, async (req, res) => {
    try {
        const uid = req.session.user.uid;
        const snap = await admin.database().ref('users/' + uid).once('value');
        const userData = snap.val() || {};

        const user = Object.assign({}, req.session.user, {
            phoneNumber: userData.phone || userData.phoneNumber || null,
            walletBalance: userData.walletBalance || 0,
            firstName: userData.firstName || null,
            lastName: userData.lastName || null
        });

        res.json({ success: true, user });
    } catch (error) {
        console.error('❌ Get user error:', error.message);
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
    } catch (error) {
        console.error('❌ Get profile error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to fetch profile' });
    }
});

// Update user profile endpoint
app.put('/api/profile', requireAuth, async (req, res) => {
    try {
        const uid = req.session.user.uid;
        const { firstName, lastName, phone } = req.body;

        console.log('📝 Profile update request for user:', uid);
        console.log('📝 Request body:', { firstName, lastName, phone });

        // Validate input
        if (!firstName || !firstName.trim() || !lastName || !lastName.trim()) {
            console.warn('❌ Validation failed: Missing firstName or lastName');
            return res.status(400).json({ 
                success: false, 
                message: 'First name and last name are required' 
            });
        }

        // Update user profile in database
        const updates = {
            firstName: firstName.trim(),
            lastName: lastName.trim()
        };

        if (phone && phone.trim()) {
            updates.phone = phone.trim();
        }

        console.log('📝 Updating database with:', updates);
        await admin.database().ref('users/' + uid).update(updates);

        console.log(`✅ Profile updated for user: ${uid}`);

        // Return updated profile
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

        res.json({ success: true, message: 'Profile updated successfully', profile });
    } catch (error) {
        console.error('❌ Update profile error:', error.message);
        console.error('❌ Stack trace:', error.stack);
        res.status(500).json({ success: false, message: 'Failed to update profile: ' + error.message });
    }
});

// Profile stats endpoint
app.get('/api/profile/stats', requireAuth, async (req, res) => {
    try {
        const uid = req.session.user.uid;

        console.log(`📊 Fetching profile stats for user: ${uid}`);
        console.log(`   Session user:`, req.session.user);

        // Fetch transactions with explicit value event
        const transactionsRef = admin.database().ref('transactions');
        console.log(`   Querying transactions by userId: ${uid}`);
        
        const transactionsSnap = await transactionsRef
            .orderByChild('userId')
            .equalTo(uid)
            .once('value');

        const transactions = transactionsSnap.val() || {};
        console.log(`   Found ${Object.keys(transactions).length} transactions`);

        // Count totals
        const totalOrders = Object.keys(transactions).length;
        const successfulOrders = Object.values(transactions).filter(tx => 
            tx.status === 'success' || tx.status === 'completed' || tx.status === true
        ).length;
        const totalSpent = Object.values(transactions).reduce((sum, tx) => 
            sum + (parseFloat(tx.amount) || 0), 0
        );

        // Fetch user data
        const userSnap = await admin.database().ref('users/' + uid).once('value');
        const userData = userSnap.val() || {};
        const walletBalance = userData.walletBalance || 0;
        const memberSince = userData.createdAt || null;

        console.log(`   ✓ Stats: ${totalOrders} orders, ${successfulOrders} successful, ₵${totalSpent.toFixed(2)} spent`);

        const stats = {
            totalOrders,
            successfulOrders,
            totalSpent,
            walletBalance,
            memberSince
        };

        console.log(`   📤 Sending response:`, stats);
        return res.json({ success: true, stats });

    } catch (error) {
        console.error(`❌ Error fetching stats:`, error.message);
        console.error(`   Stack:`, error.stack);
        return res.status(500).json({ success: false, message: 'Failed to fetch stats', error: error.message });
    }
});

// Wallet balance endpoint
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
        console.error('❌ Wallet balance error:', error.message);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch wallet balance' 
        });
    }
});

// Wallet transactions endpoint
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
        console.error('❌ Error loading wallet transactions:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to load transactions'
        });
    }
});

// User orders endpoint
app.get('/api/orders', requireAuth, async (req, res) => {
    try {
        const userId = req.session.user.uid;
        
        console.log('📦 Fetching orders for user:', userId);
        
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
            transactionId: transaction.transactionId || transaction.hubnetTransactionId || '',
            timestamp: transaction.timestamp || new Date().toISOString(),
            reason: transaction.reason || ''
        }));

        // Sort by timestamp (newest first)
        orders.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        console.log(`✅ Found ${orders.length} orders`);

        res.json({
            success: true,
            orders: orders
        });
    } catch (error) {
        console.error('❌ Error loading orders:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to load orders'
        });
    }
});

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

// Fallback: serve HTML files without extension
app.use((req, res, next) => {
    // Skip API routes
    if (req.path.startsWith('/api/')) {
        return next();
    }
    
    // Skip if path has a file extension (already handled by static middleware)
    if (req.path.includes('.')) {
        return next();
    }
    
    // Try to serve as HTML file
    const fileName = req.path.substring(1) || 'index';
    const filePath = path.join(__dirname, 'public', fileName + '.html');
    
    console.log(`📄 Attempting to serve: ${filePath}`);
    
    res.sendFile(filePath, (err) => {
        if (err) {
            console.log(`⚠️  File not found: ${filePath}`);
            res.status(404).send('Page not found');
        }
    });
});

// 404 handler - anything that reaches here is not found
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

// Start server
const server = app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`   ✓ API: GET /api/profile/stats?uid=USER_ID`);
    console.log(`   ✓ Static: http://localhost:${PORT}`);
});

// Timeout handling
server.timeout = 10000;

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down gracefully...');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
    // Force exit after 5 seconds
    setTimeout(() => process.exit(1), 5000);
});

// Error handling
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason) => {
    console.error('❌ Unhandled Rejection:', reason);
    process.exit(1);
});
