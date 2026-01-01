require('dotenv').config();
const admin = require('firebase-admin');

const serviceAccount = {
  type: 'service_account',
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: 'https://accounts.google.com/o/oauth2/auth',
  token_uri: 'https://oauth2.googleapis.com/token',
  auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
  client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL
});

const db = admin.database();

async function checkUsers() {
  try {
    console.log('Fetching user data from Firebase...\n');
    
    // Check users from Realtime Database
    const usersRef = db.ref('users');
    const snapshot = await usersRef.once('value');
    const usersData = snapshot.val();
    
    if (!usersData) {
      console.log('No users found in the database.');
      process.exit(0);
    }
    
    const userCount = Object.keys(usersData).length;
    console.log(`Total number of users: ${userCount}\n`);
    
    // Display user details
    console.log('User Details:');
    console.log('─'.repeat(60));
    
    let index = 1;
    for (const [userId, userData] of Object.entries(usersData)) {
      console.log(`\n${index}. User ID: ${userId}`);
      console.log(`   Email: ${userData.email || 'N/A'}`);
      console.log(`   Phone: ${userData.phone || 'N/A'}`);
      console.log(`   Name: ${userData.name || 'N/A'}`);
      console.log(`   Created: ${userData.createdAt || 'N/A'}`);
      index++;
    }
    
    console.log('\n' + '─'.repeat(60));
    console.log(`\nSummary: Total Users = ${userCount}`);
    
    process.exit(0);
  } catch (error) {
    console.error('Error fetching users:', error.message);
    process.exit(1);
  }
}

checkUsers();
