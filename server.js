const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
const os = require('os');

const trustEngine = require('./src/trust-engine');
const { gateMiddleware } = require('./src/gate');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cookieParser());
app.use(cors());

// Serve static frontend dashboard assets
app.use(express.static(path.join(__dirname, 'public')));

// Helper: Inspect active host network adapters
function getActiveNetworkInterfaces() {
  const interfaces = os.networkInterfaces();
  const list = [];
  for (const [name, nets] of Object.entries(interfaces)) {
    for (const net of nets) {
      if (net.family === 'IPv4' && !net.internal) {
        list.push({
          name,
          ip: net.address,
          label: `${net.address} (Physical ${name})`
        });
      }
    }
  }
  return list;
}

// Network detection endpoint
app.get('/api/network/detect', (req, res) => {
  const networks = getActiveNetworkInterfaces();
  return res.json({
    activeNetworks: networks,
    primary: networks.length > 0 ? networks[0].label : '192.168.1.45 (Home Wi-Fi)'
  });
});

// =============================================================================
// AUTHENTICATION ROUTES
// =============================================================================

// Login with Password and 2FA Code -> Initial Trust: 70
app.post('/api/auth/login', (req, res) => {
  const { username, password, totpCode, role } = req.body;

  // Basic credential validation
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required.' });
  }

  // 2FA code required for initial authentication (default demo code: 123456)
  if (!totpCode || (totpCode !== '123456' && totpCode !== '000000')) {
    return res.status(401).json({
      success: false,
      message: 'Invalid 2FA code. Please provide a valid 6-digit code (Use demo code: 123456).'
    });
  }

  const clientIp = req.headers['x-simulated-ip'] || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '192.168.1.45 (Home Wi-Fi)';
  const userAgent = req.headers['x-simulated-ua'] || req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0';

  const session = trustEngine.createSession({
    username,
    clientIp,
    userAgent,
    role
  });

  // Set session cookie
  res.cookie('sessionId', session.sessionId, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  });

  return res.json({
    success: true,
    message: `Login successful with Password + 2FA as [${session.role}].`,
    session: {
      sessionId: session.sessionId,
      username: session.username,
      role: session.role,
      trustScore: session.trustScore,
      ip: session.ip,
      userAgent: session.userAgent
    }
  });
});

// Check current session status
app.get('/api/auth/status', (req, res) => {
  const sessionId = req.cookies.sessionId || req.headers['x-session-id'];
  if (!sessionId) {
    return res.json({ active: false });
  }

  const session = trustEngine.getSession(sessionId);
  if (!session || session.status === 'TERMINATED') {
    return res.json({ active: false, terminated: true });
  }

  return res.json({
    active: true,
    session: {
      sessionId: session.sessionId,
      username: session.username,
      role: session.role,
      trustScore: session.trustScore,
      ip: session.ip,
      userAgent: session.userAgent,
      lastActive: session.lastActive,
      status: session.status
    }
  });
});

// Logout / Revoke Session
app.post('/api/auth/logout', (req, res) => {
  const sessionId = req.cookies.sessionId || req.headers['x-session-id'];
  if (sessionId) {
    trustEngine.terminateSession(sessionId, 'User manually logged out');
  }
  res.clearCookie('sessionId');
  return res.json({ success: true, message: 'Logged out successfully.' });
});

// =============================================================================
// SIMULATION & STEP-UP 2FA ENDPOINTS
// =============================================================================

// Step-Up 2FA Verification (Trust is a bit low -> User submits fresh 2FA code)
app.post('/api/simulate/step-up', (req, res) => {
  const sessionId = req.cookies.sessionId || req.headers['x-session-id'];
  const { code } = req.body;

  if (!sessionId) {
    return res.status(401).json({ success: false, message: 'No active session.' });
  }

  const result = trustEngine.verifyStepUp2FA(sessionId, code);
  return res.status(result.success ? 200 : 400).json(result);
});

// Time Travel Simulation: Fast-forward time (e.g. 15m, 30m, 60m) to observe decay
app.post('/api/simulate/time-jump', (req, res) => {
  const sessionId = req.cookies.sessionId || req.headers['x-session-id'];
  const { seconds } = req.body;

  if (!sessionId) {
    return res.status(401).json({ success: false, message: 'No active session.' });
  }

  const result = trustEngine.simulateTimeJump(sessionId, Number(seconds) || 1800);
  return res.json(result);
});

// Reset session back to pristine initial state (Trust 70)
app.post('/api/simulate/reset', (req, res) => {
  const sessionId = req.cookies.sessionId || req.headers['x-session-id'];
  if (!sessionId) {
    return res.status(401).json({ success: false, message: 'No active session.' });
  }

  const session = trustEngine.getSession(sessionId);
  if (session) {
    const oldTrust = session.trustScore;
    session.trustScore = 70;
    session.status = 'ACTIVE';
    session.ip = '192.168.1.45 (Home Wi-Fi)';
    session.userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0';
    session.lastActive = Date.now();
    session.recentTimestamps = [Date.now()];

    trustEngine.logEvent({
      sessionId,
      username: session.username,
      route: 'SESSION_RESET',
      oldTrust,
      newTrust: 70,
      delta: 70 - oldTrust,
      reasons: ['Session reset to baseline initial trust (70)'],
      decision: 'ALLOW'
    });

    return res.json({ success: true, session });
  }
  return res.status(404).json({ success: false, message: 'Session not found.' });
});

// =============================================================================
// REAL-TIME AUDIT LOGGING (SSE & HISTORICAL)
// =============================================================================

// SSE Live Stream for the dashboard
app.get('/api/logs/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  trustEngine.addSseClient(res);

  req.on('close', () => {
    trustEngine.removeSseClient(res);
  });
});

// Historical audit log query
app.get('/api/logs/history', (req, res) => {
  return res.json({ logs: trustEngine.auditLogs });
});

// =============================================================================
// DEDICATED NGINX AUTH_REQUEST ENDPOINT
// =============================================================================
// When using external Nginx, Nginx queries this endpoint internally
app.get('/api/gate/verify', (req, res) => {
  const sessionId = req.cookies.sessionId || req.headers['x-session-id'];
  const targetRoute = req.headers['x-original-uri'] || '/public';
  const clientIp = req.headers['x-original-ip'] || req.socket.remoteAddress;
  const userAgent = req.headers['x-original-ua'] || req.headers['user-agent'];

  const evaluation = trustEngine.evaluateRequest({
    sessionId,
    targetRoute,
    clientIp,
    userAgent
  });

  res.setHeader('X-Trust-Score', evaluation.currentTrust);
  res.setHeader('X-Gate-Decision', evaluation.decision);
  res.setHeader('X-Required-Trust', evaluation.requiredTrust);

  if (evaluation.decision === 'ALLOW') {
    return res.status(200).send('ALLOW');
  } else if (evaluation.decision === 'STEP_UP_REQUIRED') {
    return res.status(401).send('STEP_UP_REQUIRED');
  } else {
    return res.status(403).send('BLOCK_TERMINATE');
  }
});

// =============================================================================
// PROTECTED APPLICATION ROUTES (ROUTED THROUGH THE GATE)
// =============================================================================
// Every click on these pages passes through the Gate Middleware
app.use(gateMiddleware);

// 1. PUBLIC PAGE (Requirement: Trust >= 20)
app.get('/public', (req, res) => {
  res.json({
    page: 'Public Announcements',
    requiredTrust: 20,
    currentTrust: req.trustEvaluation.currentTrust,
    currentRole: req.trustSession.role,
    message: 'Welcome to the Public CCN Resource Portal.',
    content: {
      title: 'CCN Zero-Trust Network Architecture Hub',
      description: 'Continuous Adaptive Risk and Trust Assessment (CARTA) active on all network links.',
      announcements: [
        'Border firewall upgraded to stateful packet inspection v4.2',
        'Campus VPN migration scheduled for next maintenance window',
        'All student and staff sessions are monitored via dynamic trust scoring'
      ]
    }
  });
});

// 2. PROFILE PAGE (Requirement: Trust >= 40)
app.get('/profile', (req, res) => {
  res.json({
    page: 'User Profile & Identity Details',
    requiredTrust: 40,
    currentTrust: req.trustEvaluation.currentTrust,
    currentRole: req.trustSession.role,
    message: 'Identity and credentials verified for standard access tier.',
    content: {
      username: req.trustSession.username,
      role: req.trustSession.role,
      networkSubnet: req.trustSession.ip,
      deviceFingerprint: req.trustSession.userAgent,
      sessionCreated: new Date(req.trustSession.createdAt).toLocaleString(),
      permissions: ['READ_PUBLIC', 'VIEW_PROFILE', 'SUBMIT_FEEDBACK']
    }
  });
});

// 3. PAYMENT PAGE (Requirement: Trust >= 60)
app.get('/payment', (req, res) => {
  res.json({
    page: 'High-Trust Financial & Payment Portal',
    requiredTrust: 60,
    currentTrust: req.trustEvaluation.currentTrust,
    currentRole: req.trustSession.role,
    message: 'Financial gateway unlocked. Strict trust verified.',
    content: {
      accountBalance: '$4,850.00 USD',
      pendingTransactions: [
        { id: 'TXN-9021', merchant: 'CCN Cloud Lab Server Rental', amount: '$49.00', status: 'Approved' },
        { id: 'TXN-9022', merchant: 'Hardware Security Module License', amount: '$120.00', status: 'Completed' }
      ],
      authorizedActions: ['DISBURSE_FUNDS', 'TRANSFER_BALANCE', 'GENERATE_INVOICE']
    }
  });
});

// 4. ADMIN PAGE (Requirement: Role == 'ADMIN' AND Trust >= 80)
app.get('/admin', (req, res) => {
  // 1. Role-Based Access Control (RBAC) Check
  if (req.trustSession.role !== 'ADMIN') {
    return res.status(403).json({
      decision: 'ROLE_FORBIDDEN',
      status: 403,
      page: 'Admin Security Operations Center (SOC)',
      requiredRole: 'ADMIN',
      currentRole: req.trustSession.role,
      currentTrust: req.trustEvaluation.currentTrust,
      requiredTrust: 80,
      message: 'Access Denied: Common User role is not authorized for Admin SOC, regardless of trust score. Administrator role (ADMIN) is strictly required.'
    });
  }

  // 2. Continuous Dynamic Trust (CARTA) Check
  // Note: If trust was < 80, gateMiddleware already issued 401 STEP_UP_REQUIRED
  res.json({
    page: 'Admin Security Operations Center (SOC)',
    requiredTrust: 80,
    requiredRole: 'ADMIN',
    currentRole: 'ADMIN',
    currentTrust: req.trustEvaluation.currentTrust,
    message: 'Root Administrative Privileges Active. Maximum trust level & Admin role verified.',
    content: {
      firewallStatus: 'ONLINE (Enforcing ZTNA Policy)',
      networkGateways: [
        { name: 'Gateway-US-East', ip: '10.0.1.1', load: '34%', status: 'HEALTHY' },
        { name: 'Gateway-EU-Central', ip: '10.0.2.1', load: '61%', status: 'HEALTHY' }
      ],
      threatDetection: 'Zero active critical alerts. RBAC + ZTNA Policy enforced.',
      criticalOperations: ['FLUSH_SESSION_KEYS', 'RECONFIGURE_ROUTER_TABLES', 'ISOLATE_SUBNET']
    }
  });
});

// Start Server
app.listen(PORT, () => {
  console.log('================================================================');
  console.log(' CCN ZERO TRUST / CARTA DEMO PLATFORM RUNNING');
  console.log(` Web Dashboard: http://localhost:${PORT}`);
  console.log(' The Gate: Enforcing continuous dynamic trust on all requests');
  console.log(' Page Levels: Public(20), Profile(40), Payment(60), Admin(80)');
  console.log('================================================================');
});
