const http = require('http');

// Test email update endpoint
async function testEmailUpdate() {
  try {
    // Step 1: Login as admin
    console.log('Step 1: Logging in as admin...');
    const loginResponse = await new Promise((resolve, reject) => {
      const options = {
        hostname: 'localhost',
        port: 3000,
        path: '/api/login',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      };

      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          const cookies = res.headers['set-cookie'];
          resolve({ status: res.statusCode, data: JSON.parse(data), cookies });
        });
      });

      req.on('error', reject);
      req.write(JSON.stringify({
        email: 'fotsiemmanuel397@gmail.com',
        password: 'Bulletman1234567890@',
        remember: true
      }));
      req.end();
    });

    console.log('Login response:', JSON.stringify(loginResponse.data, null, 2));
    
    if (!loginResponse.cookies) {
      console.error('No session cookie received!');
      return;
    }

    const sessionCookie = loginResponse.cookies[0].split(';')[0];
    console.log('Session cookie:', sessionCookie);

    // Step 2: Update email
    console.log('\nStep 2: Updating user email...');
    const updateResponse = await new Promise((resolve, reject) => {
      const options = {
        hostname: 'localhost',
        port: 3000,
        path: '/api/admin/update-user-email',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': sessionCookie
        }
      };

      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        });
      });

      req.on('error', reject);
      req.write(JSON.stringify({
        uid: 'xl5NRnoRNpM1vxwN4yWedHaUOAT2',
        newEmail: 'manuelmarcoli0@gmail.com'
      }));
      req.end();
    });

    console.log('Update response:', JSON.stringify(updateResponse.data, null, 2));
    
    if (updateResponse.data.success) {
      console.log('\n✅ Email successfully updated!');
      console.log(`Old email: ${updateResponse.data.oldEmail}`);
      console.log(`New email: ${updateResponse.data.newEmail}`);
    } else {
      console.error('\n❌ Error updating email:', updateResponse.data.error);
    }

  } catch (error) {
    console.error('Error:', error.message);
  }
}

testEmailUpdate();
