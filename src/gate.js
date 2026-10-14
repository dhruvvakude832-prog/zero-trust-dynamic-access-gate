// The Gate (Reverse Proxy & Policy Enforcement Point)
// Implements the Nginx auth_request pattern

const trustEngine = require('./trust-engine');

function gateMiddleware(req, res, next) {
  // Public static assets & login endpoints bypass the gate
  const publicBypass = [
    '/',
    '/index.html',
    '/login.html',
    '/api/auth/login',
    '/api/auth/status',
    '/api/network/detect',
    '/api/logs/stream',
    '/api/logs/history',
    '/api/simulate/time-jump',
    '/api/simulate/step-up',
    '/api/simulate/reset',
    '/api/gate/verify' // direct endpoint for external real Nginx
  ];

  if (publicBypass.includes(req.path) || req.path.startsWith('/assets') || req.path.startsWith('/static')) {
    return next();
  }

  // Extract Session ID from cookie or Authorization header
  const sessionId = req.cookies.sessionId || req.headers['x-session-id'];
  
  if (!sessionId) {
    return res.status(401).json({
      decision: 'BLOCK_TERMINATE',
      status: 401,
      message: 'No active session token found. Please log in.'
    });
  }

  // Detect incoming IP and User-Agent (or simulated anomaly overrides)
  const clientIp = req.headers['x-simulated-ip'] || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '192.168.1.45 (Home Wi-Fi)';
  const userAgent = req.headers['x-simulated-ua'] || req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0';

  // Support simulated anomaly headers from the demo dashboard
  const simulatedAnomalies = {
    ip: req.headers['x-simulated-ip'],
    userAgent: req.headers['x-simulated-ua'],
    burst: req.headers['x-simulated-burst'] === 'true'
  };

  // The Gate queries the Trust Engine: "Is this session trusted enough for this page?"
  const evaluation = trustEngine.evaluateRequest({
    sessionId,
    targetRoute: req.path,
    clientIp,
    userAgent,
    simulatedAnomalies
  });

  // Attach evaluation result to response headers
  res.setHeader('X-Trust-Score', evaluation.currentTrust);
  res.setHeader('X-Required-Trust', evaluation.requiredTrust);
  res.setHeader('X-Gate-Decision', evaluation.decision);
  res.setHeader('X-User-Role', evaluation.role || 'USER');

  if (evaluation.decision === 'ALLOW') {
    // Pass through to protected resource
    req.trustSession = trustEngine.getSession(sessionId);
    req.trustEvaluation = evaluation;
    return next();
  } else if (evaluation.decision === 'STEP_UP_REQUIRED') {
    // Trust is a bit low: challenge user for a fresh 2FA code
    return res.status(401).json({
      decision: 'STEP_UP_REQUIRED',
      status: 401,
      currentTrust: evaluation.currentTrust,
      requiredTrust: evaluation.requiredTrust,
      targetRoute: req.path,
      reasons: evaluation.reasons,
      message: `Access challenged. Required trust: ${evaluation.requiredTrust}, current trust: ${evaluation.currentTrust}. Fresh 2FA code required.`
    });
  } else {
    // Trust is very low or severe anomaly: Block and terminate session
    res.clearCookie('sessionId');
    return res.status(403).json({
      decision: 'BLOCK_TERMINATE',
      status: 403,
      currentTrust: evaluation.currentTrust,
      requiredTrust: evaluation.requiredTrust,
      targetRoute: req.path,
      reasons: evaluation.reasons,
      message: 'Access blocked and session terminated due to low trust score (< 20) or security violation.'
    });
  }
}

module.exports = { gateMiddleware };
