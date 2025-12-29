/**
 * Admin Access Restoration Script
 * 
 * This script restores admin access for a user by email.
 * Run: node restore-admin.js <email>
 */

require('dotenv').config();
const admin = require('firebase-admin');

// Initialize Firebase Admin
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
  console.log('✅ Firebase Admin initialized');
} catch (error) {
  console.error('❌ Firebase initialization failed:', error.message);
  process.exit(1);
}

async function restoreAdminAccess(email) {
  try {
    console.log(`\n🔍 Looking up user: ${email}`);
    
    // Get user by email
    const userRecord = await admin.auth().getUserByEmail(email);
    console.log(`✅ Found user: ${userRecord.uid}`);
    
    // Check current admin status
    const userSnapshot = await admin.database().ref('users/' + userRecord.uid).once('value');
    const userData = userSnapshot.val();
    
    if (!userData) {
      console.log('⚠️ User exists in Auth but not in Database. Creating user record...');
      await admin.database().ref('users/' + userRecord.uid).set({
        firstName: userRecord.displayName?.split(' ')[0] || 'User',
        lastName: userRecord.displayName?.split(' ').slice(1).join(' ') || '',
        email: email.toLowerCase().trim(),
        phone: userRecord.phoneNumber || '',
        walletBalance: userData?.walletBalance || 0,
        createdAt: userData?.createdAt || new Date().toISOString(),
        isAdmin: true,
        pricingGroup: 'admin',
        suspended: false,
        adminRestoredAt: new Date().toISOString()
      });
      console.log('✅ User record created with admin access');
    } else {
      // Update existing user
      await admin.database().ref('users/' + userRecord.uid).update({
        isAdmin: true,
        adminRestoredAt: new Date().toISOString(),
        suspended: false
      });
      console.log('✅ Admin access restored');
    }
    
    console.log(`\n🎉 Success! Admin access has been restored for: ${email}`);
    console.log(`   User ID: ${userRecord.uid}`);
    console.log(`\nYou can now log in at: /admin-login`);
    
    process.exit(0);
  } catch (error) {
    if (error.code === 'auth/user-not-found') {
      console.error(`❌ User not found with email: ${email}`);
      console.error('   Make sure the email is correct and the user has signed up.');
    } else {
      console.error('❌ Error:', error.message);
    }
    process.exit(1);
  }
}

// Get email from command line argument
const email = process.argv[2] || 'fotsiemmanuel397@gmail.com';

if (!email) {
  console.error('❌ Please provide an email address');
  console.error('Usage: node restore-admin.js <email>');
  process.exit(1);
}

console.log('🔧 Admin Access Restoration Tool');
console.log('================================\n');

restoreAdminAccess(email);

