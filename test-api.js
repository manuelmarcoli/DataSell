const http = require('http');
const https = require('https');

// Test login first
function makeRequest(method, path, data = null, useSession = false) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'localhost',
            port: 3000,
            path: path,
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        const req = http.request(options, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(body);
                    resolve({
                        status: res.statusCode,
                        headers: res.headers,
                        data: parsed
                    });
                } catch (e) {
                    resolve({
                        status: res.statusCode,
                        headers: res.headers,
                        body: body
                    });
                }
            });
        });

        req.on('error', reject);
        if (data) req.write(JSON.stringify(data));
        req.end();
    });
}

async function test() {
    try {
        console.log('📝 Testing API endpoints...\n');

        // Test 1: Login
        console.log('1️⃣ Testing Login...');
        const loginRes = await makeRequest('POST', '/api/login', {
            email: 'fotsiemmanuel397@gmail.com',
            password: 'Bulletman1234567890@'
        });
        console.log(`   Status: ${loginRes.status}`);
        console.log(`   Response:`, JSON.stringify(loginRes.data, null, 2));

        if (loginRes.status === 200) {
            console.log('\n✅ Login successful!\n');

            // Test 2: Get profile stats
            console.log('2️⃣ Testing /api/profile/stats...');
            const statsRes = await makeRequest('GET', '/api/profile/stats');
            console.log(`   Status: ${statsRes.status}`);
            console.log(`   Response:`, JSON.stringify(statsRes.data, null, 2));

            if (statsRes.data.success && statsRes.data.stats) {
                console.log('\n✅ Stats endpoint working!');
                console.log(`   Total Orders: ${statsRes.data.stats.totalOrders}`);
                console.log(`   Successful Orders: ${statsRes.data.stats.successfulOrders}`);
                console.log(`   Total Spent: ${statsRes.data.stats.totalSpent}`);
                console.log(`   Wallet Balance: ${statsRes.data.stats.walletBalance}`);
            }
        }
    } catch (error) {
        console.error('❌ Error:', error.message);
    }
    
    process.exit(0);
}

test();
