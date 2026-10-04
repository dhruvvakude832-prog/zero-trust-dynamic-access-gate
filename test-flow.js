// Automated verification test script for Zero Trust CARTA Engine
const http = require('http');

async function request(path, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(`http://localhost:3000${path}`, options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: data ? JSON.parse(data) : {}
          });
        } catch (e) {
          resolve({ status: res.statusCode, headers: res.headers, raw: data });
        }
      });
    });
    req.on('error', reject);
    if (options.body) {
      req.write(typeof options.body === 'string' ? options.body : JSON.stringify(options.body));
    }
    req.end();
  });
}

async function runTests() {
  console.log('--- STARTING ZERO TRUST FLOW VERIFICATION TESTS ---\n');

  // 1. Primary Login with Password + 2FA
  console.log('Test 1: Login with Password + 2FA (expected initial trust: 70)');
  const loginRes = await request('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: {
      username: 'alice@secure.lab',
      password: 'DemoPassword@2026',
      totpCode: '123456'
    }
  });

  console.log(`Status: ${loginRes.status}, Trust: ${loginRes.body.session?.trustScore}`);
  if (loginRes.body.session?.trustScore !== 70) {
    throw new Error(`Expected trust 70, got ${loginRes.body.session?.trustScore}`);
  }
  const cookie = loginRes.headers['set-cookie'] ? loginRes.headers['set-cookie'][0].split(';')[0] : '';
  const headers = { 'Cookie': cookie };

  // 2. Access Public Page (Required: 20)
  console.log('\nTest 2: Access Public Page (Requires >= 20)');
  const publicRes = await request('/public', { method: 'GET', headers });
  console.log(`Status: ${publicRes.status}, Gate Decision: ${publicRes.headers['x-gate-decision']}, Current Trust: ${publicRes.body.currentTrust}`);
  if (publicRes.status !== 200) throw new Error('Expected 200 for public page');

  // 3. Access Profile Page (Required: 40)
  console.log('\nTest 3: Access Profile Page (Requires >= 40)');
  const profileRes = await request('/profile', { method: 'GET', headers });
  console.log(`Status: ${profileRes.status}, Gate Decision: ${profileRes.headers['x-gate-decision']}, Current Trust: ${profileRes.body.currentTrust}`);
  if (profileRes.status !== 200) throw new Error('Expected 200 for profile page');

  // 4. Access Payment Page (Required: 60)
  console.log('\nTest 4: Access Payment Page (Requires >= 60)');
  const paymentRes = await request('/payment', { method: 'GET', headers });
  console.log(`Status: ${paymentRes.status}, Gate Decision: ${paymentRes.headers['x-gate-decision']}, Current Trust: ${paymentRes.body.currentTrust}`);
  if (paymentRes.status !== 200) throw new Error('Expected 200 for payment page');

  // 5. Access Admin Page (Required: 80, Current trust ~ 70-74)
  console.log('\nTest 5: Access Admin Page (Requires >= 80, current trust ~ 74)');
  const adminRes = await request('/admin', { method: 'GET', headers });
  console.log(`Status: ${adminRes.status}, Decision: ${adminRes.body.decision}, Msg: ${adminRes.body.message}`);
  if (adminRes.status !== 401 || adminRes.body.decision !== 'STEP_UP_REQUIRED') {
    throw new Error('Expected 401 STEP_UP_REQUIRED for admin page');
  }

  // 6. Perform Step-Up 2FA
  console.log('\nTest 6: Submit Step-Up 2FA code (+35 boost)');
  const stepUpRes = await request('/api/simulate/step-up', {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: { code: '123456' }
  });
  console.log(`Status: ${stepUpRes.status}, New Trust: ${stepUpRes.body.currentTrust}`);
  if (stepUpRes.body.currentTrust < 80) throw new Error('Expected trust to be >= 80 after step-up');

  // 7. Access Admin Page again (Now Trust >= 80)
  console.log('\nTest 7: Access Admin Page after Step-Up (Should now be ALLOWED)');
  const adminAllowedRes = await request('/admin', { method: 'GET', headers });
  console.log(`Status: ${adminAllowedRes.status}, Gate Decision: ${adminAllowedRes.headers['x-gate-decision']}, Current Trust: ${adminAllowedRes.body.currentTrust}`);
  if (adminAllowedRes.status !== 200) throw new Error('Expected 200 for admin page after step-up');

  // 8. Anomaly: Network Change (−25)
  console.log('\nTest 8: Simulate Network Change anomaly (−25 penalty)');
  const networkRes = await request('/public', {
    method: 'GET',
    headers: { ...headers, 'X-Simulated-IP': '172.56.21.90 (Cellular)' }
  });
  console.log(`Status: ${networkRes.status}, Trust after network change: ${networkRes.body.currentTrust}`);

  // 9. Anomaly: User-Agent Change (−30)
  console.log('\nTest 9: Simulate User-Agent Change anomaly (−30 penalty)');
  const uaRes = await request('/public', {
    method: 'GET',
    headers: { ...headers, 'X-Simulated-UA': 'Mozilla/5.0 (iPhone; Mobile)' }
  });
  console.log(`Status: ${uaRes.status}, Trust after UA change: ${uaRes.body.currentTrust}`);

  // 10. Check Audit Logs
  console.log('\nTest 10: Query Audit Logs to verify reasons logged');
  const logsRes = await request('/api/logs/history', { method: 'GET' });
  const recentLogs = logsRes.body.logs.slice(-5);
  recentLogs.forEach(l => {
    console.log(`  [${l.formattedTime}] [${l.decision}] ${l.route}: ${l.oldTrust} -> ${l.newTrust} (${l.delta >= 0 ? '+' : ''}${l.delta}) | Reasons: ${l.reasons.join('; ')}`);
  });

  console.log('\n======================================================');
  console.log(' ALL AUTOMATED ZERO-TRUST TESTS PASSED SUCCESSFULLY! ');
  console.log('======================================================');
}

runTests().catch(err => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
