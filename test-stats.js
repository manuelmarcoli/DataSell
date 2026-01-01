const admin = require('firebase-admin');
require('dotenv').config();

// Initialize Firebase Admin
const serviceAccount = {
    type: 'service_account',
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY,
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: 'https://accounts.google.com/o/oauth2/auth',
    token_uri: 'https://oauth2.googleapis.com/token',
    auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
    client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL,
};

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL,
});

async function testStats() {
    try {
        const uid = 'fotsiemmanuel397@gmail.com'; // Test with admin email
        
        console.log(`\n🔍 Testing stats query for: ${uid}\n`);
        
        // Test 1: Check if user exists
        console.log('📌 Checking users table...');
        const usersRef = admin.database().ref('users');
        const usersSnap = await usersRef.once('value');
        const users = usersSnap.val() || {};
        console.log(`   Found ${Object.keys(users).length} users total`);
        
        // Find the user by email
        let foundUid = null;
        for (const [key, user] of Object.entries(users)) {
            if (user.email === uid) {
                foundUid = key;
                console.log(`   ✓ Found user by email: ${foundUid}`);
                console.log(`   - walletBalance: ${user.walletBalance}`);
                console.log(`   - createdAt: ${user.createdAt}`);
                break;
            }
        }
        
        if (!foundUid) {
            console.log(`   ✗ User not found with email: ${uid}`);
            return;
        }
        
        // Test 2: Check transactions table
        console.log('\n📌 Checking transactions table...');
        const transactionsRef = admin.database().ref('transactions');
        const transSnap = await transactionsRef.once('value');
        const transactions = transSnap.val() || {};
        console.log(`   Found ${Object.keys(transactions).length} transactions total`);
        
        // Find transactions for this user
        const userTransactions = {};
        for (const [key, tx] of Object.entries(transactions)) {
            if (tx.userId === foundUid || tx.userId === uid) {
                userTransactions[key] = tx;
            }
        }
        
        console.log(`   ✓ Found ${Object.keys(userTransactions).length} transactions for user`);
        if (Object.keys(userTransactions).length > 0) {
            console.log('   Sample transactions:');
            Object.entries(userTransactions).slice(0, 3).forEach(([key, tx]) => {
                console.log(`     - ${key}: ${tx.amount} (${tx.status})`);
            });
        }
        
        // Test 3: Test the query
        console.log('\n📌 Testing query with userId...');
        const querySnap = await transactionsRef
            .orderByChild('userId')
            .equalTo(foundUid)
            .once('value');
        const queryResult = querySnap.val() || {};
        console.log(`   Query returned: ${Object.keys(queryResult).length} transactions`);
        
        if (Object.keys(queryResult).length > 0) {
            console.log('   ✓ Query working correctly!');
        } else {
            console.log('   ⚠ Query returned 0 results - checking transaction structure...');
            Object.entries(transactions).slice(0, 5).forEach(([key, tx]) => {
                console.log(`   - Transaction ${key}:`);
                console.log(`     userId: ${tx.userId}`);
                console.log(`     userId type: ${typeof tx.userId}`);
            });
        }
        
        // Calculate stats
        const totalOrders = Object.keys(userTransactions).length;
        const successfulOrders = Object.values(userTransactions).filter(tx => 
            tx.status === 'success' || tx.status === 'completed' || tx.status === true
        ).length;
        const totalSpent = Object.values(userTransactions).reduce((sum, tx) => 
            sum + (parseFloat(tx.amount) || 0), 0
        );
        
        console.log('\n📊 CALCULATED STATS:');
        console.log(`   Total Orders: ${totalOrders}`);
        console.log(`   Successful Orders: ${successfulOrders}`);
        console.log(`   Total Spent: ₵${totalSpent.toFixed(2)}`);
        
    } catch (error) {
        console.error('❌ Error:', error.message);
        console.error(error);
    } finally {
        process.exit();
    }
}

testStats();
