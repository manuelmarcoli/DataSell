/**
 * Simple Admin Access Restoration Script
 * Uses Firebase REST API - only needs FIREBASE_DATABASE_URL
 */

require('dotenv').config();
const axios = require('axios');

const FIREBASE_DATABASE_URL = process.env.FIREBASE_DATABASE_URL;

if (!FIREBASE_DATABASE_URL) {
  console.error('❌ FIREBASE_DATABASE_URL is required in .env file');
  console.error('   Please add: FIREBASE_DATABASE_URL=https://your-project.firebaseio.com');
  process.exit(1);
}

async function findUserByEmail(email) {
  try {
    // Get all users from Firebase
    const usersUrl = `${FIREBASE_DATABASE_URL}/users.json`;
    const response = await axios.get(usersUrl);
    const users = response.data || {};
    
    // Find user by email
    for (const [uid, userData] of Object.entries(users)) {
      if (userData.email && userData.email.toLowerCase() === email.toLowerCase()) {
        return { uid, userData };
      }
    }
    
    return null;
  } catch (error) {
    console.error('❌ Error fetching users:', error.message);
    throw error;
  }
}

async function restoreAdminAccess(email) {
  try {
    console.log(`\n🔍 Looking up user: ${email}`);
    
    const user = await findUserByEmail(email);
    
    if (!user) {
      console.error(`❌ User not found with email: ${email}`);
      console.error('   Make sure the user has signed up and the email is correct.');
      process.exit(1);
    }
    
    console.log(`✅ Found user: ${user.uid}`);
    console.log(`   Current admin status: ${user.userData.isAdmin ? 'Admin' : 'Not Admin'}`);
    
    // Update user to restore admin access
    const updateUrl = `${FIREBASE_DATABASE_URL}/users/${user.uid}.json`;
    const updateData = {
      isAdmin: true,
      adminRestoredAt: new Date().toISOString(),
      suspended: false
    };
    
    await axios.patch(updateUrl, updateData);
    
    console.log('✅ Admin access restored successfully!');
    console.log(`\n🎉 Success! Admin access has been restored for: ${email}`);
    console.log(`   User ID: ${user.uid}`);
    console.log(`\nYou can now log in at: /admin-login`);
    console.log(`   Email: ${email}`);
    console.log(`   Password: Your account password`);
    
    process.exit(0);
  } catch (error) {
    console.error('❌ Error:', error.message);
    if (error.response) {
      console.error('   Response:', error.response.data);
    }
    process.exit(1);
  }
}

// Get email from command line argument
const email = process.argv[2] || 'fotsiemmanuel397@gmail.com';

console.log('🔧 Admin Access Restoration Tool (Simple)');
console.log('==========================================\n');

restoreAdminAccess(email);

