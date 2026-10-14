// Continuous Adaptive Risk and Trust Assessment (CARTA) Engine
// Zero Trust Dynamic Session Trust Evaluation

class TrustEngine {
  constructor() {
    // In-memory session store
    // sessionId -> session object
    this.sessions = new Map();

    // In-memory audit log buffer (circular buffer)
    this.auditLogs = [];
    this.maxLogs = 300;

    // SSE subscribers for live streaming
    this.sseClients = new Set();

    // Trust configuration parameters
    this.config = {
      initialTrust: 70,       // Initial trust score upon successful login with 2FA
      minTrust: 0,
      maxTrust: 100,
      
      // Page thresholds
      thresholds: {
        '/public': 20,
        '/profile': 40,
        '/payment': 60,
        '/admin': 80
      },

      // Decay parameters: Half-life = 3600 seconds (1 hour)
      // λ = ln(2) / 3600 ≈ 0.00019254 per second
      decayHalfLifeSeconds: 3600,

      // Penalties (Odd events)
      penalties: {
        networkChange: 25,     // Suddenly appears from different IP/subnet
        fingerprintChange: 30, // User-Agent / browser details change
        velocityBurst: 20      // Rate burst (> 5 reqs in 2s)
      },

      // Positive reinforcement
      recovery: {
        normalRequest: 2,      // Steady, normal interaction
        stepUp2FA: 35          // Correct step-up 2FA code entered
      },

      // Burst velocity window
      burstWindowMs: 2000,
      burstThresholdCount: 5
    };
  }

  // Create a new session after primary Login + 2FA
  createSession({ username, clientIp, userAgent, role }) {
    const sessionId = 'sess_' + Math.random().toString(36).substring(2, 10) + Date.now().toString(36);
    const now = Date.now();

    const userRole = role || (username && username.toLowerCase().includes('admin') ? 'ADMIN' : 'USER');

    const session = {
      sessionId,
      username: username || (userRole === 'ADMIN' ? 'admin@secure.lab' : 'alice@secure.lab'),
      role: userRole,
      trustScore: this.config.initialTrust,
      createdAt: now,
      lastActive: now,
      lastRecoveryAt: 0,
      ip: clientIp || '192.168.1.45 (Home Wi-Fi)',
      userAgent: userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0',
      recentTimestamps: [now],
      status: 'ACTIVE',
      // Current expected 2FA code (simulated TOTP, defaults to '123456' for easy testing)
      currentTotpCode: '123456'
    };

    this.sessions.set(sessionId, session);

    this.logEvent({
      sessionId,
      username: session.username,
      role: session.role,
      route: '/login',
      oldTrust: 0,
      newTrust: this.config.initialTrust,
      delta: +this.config.initialTrust,
      reasons: [`Initial login with Password + 2FA verified as [${session.role}], initial trust 70/100`],
      decision: 'ALLOW'
    });

    return session;
  }

  getSession(sessionId) {
    return this.sessions.get(sessionId);
  }

  terminateSession(sessionId, reason = 'Terminated by Trust Engine') {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.status = 'TERMINATED';
      session.trustScore = 0;
      this.logEvent({
        sessionId,
        username: session.username,
        route: 'SESSION_REVOKE',
        oldTrust: session.trustScore,
        newTrust: 0,
        delta: -session.trustScore,
        reasons: [reason],
        decision: 'BLOCK_TERMINATE'
      });
    }
  }

  // Subscribe SSE client
  addSseClient(res) {
    this.sseClients.add(res);
    // Send recent 20 logs immediately
    const recent = this.auditLogs.slice(-25);
    res.write(`data: ${JSON.stringify({ type: 'INIT_LOGS', logs: recent })}\n\n`);
  }

  removeSseClient(res) {
    this.sseClients.delete(res);
  }

  // Broadcast event to all SSE clients
  broadcastLog(logEntry) {
    const payload = `data: ${JSON.stringify({ type: 'NEW_LOG', log: logEntry })}\n\n`;
    for (const client of this.sseClients) {
      try {
        client.write(payload);
      } catch (err) {
        this.sseClients.delete(client);
      }
    }
  }

  // Log an event in the audit trail
  logEvent({ sessionId, username, role, route, oldTrust, newTrust, delta, reasons, decision }) {
    const entry = {
      id: Date.now() + '-' + Math.floor(Math.random() * 1000),
      timestamp: new Date().toISOString(),
      formattedTime: new Date().toLocaleTimeString('en-US', { hour12: false }),
      sessionId,
      username,
      role: role || 'USER',
      route,
      oldTrust: Math.round(oldTrust),
      newTrust: Math.round(newTrust),
      delta,
      reasons: reasons || [],
      decision
    };

    this.auditLogs.push(entry);
    if (this.auditLogs.length > this.maxLogs) {
      this.auditLogs.shift();
    }

    this.broadcastLog(entry);
    return entry;
  }

  // Calculate exponential time decay based on elapsed seconds
  calculateTimeDecay(initialScore, elapsedSeconds) {
    if (elapsedSeconds <= 0) return initialScore;
    // λ = ln(2) / decayHalfLifeSeconds
    const lambda = Math.LN2 / this.config.decayHalfLifeSeconds;
    const decayed = initialScore * Math.exp(-lambda * elapsedSeconds);
    return Math.max(this.config.minTrust, decayed);
  }

  // Fast forward time for simulation/demo
  simulateTimeJump(sessionId, jumpSeconds) {
    const session = this.sessions.get(sessionId);
    if (!session || session.status === 'TERMINATED') {
      return { error: 'Session not found or terminated' };
    }

    const oldTrust = session.trustScore;
    const decayedTrust = this.calculateTimeDecay(oldTrust, jumpSeconds);
    const drop = Math.round(oldTrust - decayedTrust);

    session.trustScore = Math.max(this.config.minTrust, Math.round(decayedTrust));
    session.lastActive = Date.now();

    const mins = Math.round(jumpSeconds / 60);
    const reason = `Time elapsed (~${mins} mins idle, half-life decay), −${drop}`;

    this.logEvent({
      sessionId,
      username: session.username,
      route: 'TIME_FAST_FORWARD',
      oldTrust,
      newTrust: session.trustScore,
      delta: -drop,
      reasons: [reason],
      decision: session.trustScore < 20 ? 'BLOCK_TERMINATE' : 'ALLOW'
    });

    if (session.trustScore < 20) {
      session.status = 'TERMINATED';
    }

    return {
      oldTrust,
      newTrust: session.trustScore,
      drop,
      reason
    };
  }

  // Handle Step-Up 2FA verification
  verifyStepUp2FA(sessionId, code) {
    const session = this.sessions.get(sessionId);
    if (!session || session.status === 'TERMINATED') {
      return { success: false, message: 'Invalid or terminated session' };
    }

    // Default valid codes are '123456' or session.currentTotpCode
    const isValid = code === '123456' || code === session.currentTotpCode;
    const oldTrust = session.trustScore;

    if (isValid) {
      const boost = this.config.recovery.stepUp2FA;
      session.trustScore = Math.min(this.config.maxTrust, Math.max(85, session.trustScore + boost));
      session.lastActive = Date.now();

      this.logEvent({
        sessionId,
        username: session.username,
        route: 'STEP_UP_2FA',
        oldTrust,
        newTrust: session.trustScore,
        delta: +(session.trustScore - oldTrust),
        reasons: [`Step-up 2FA code verified successfully, +${session.trustScore - oldTrust}`],
        decision: 'ALLOW'
      });

      return {
        success: true,
        message: 'Step-up 2FA successful! Trust restored.',
        currentTrust: session.trustScore
      };
    } else {
      // Penalty for wrong 2FA code: -15
      session.trustScore = Math.max(this.config.minTrust, session.trustScore - 15);
      this.logEvent({
        sessionId,
        username: session.username,
        route: 'STEP_UP_2FA',
        oldTrust,
        newTrust: session.trustScore,
        delta: -15,
        reasons: ['Incorrect step-up 2FA code entered, −15'],
        decision: session.trustScore < 20 ? 'BLOCK_TERMINATE' : 'STEP_UP_REQUIRED'
      });

      if (session.trustScore < 20) {
        session.status = 'TERMINATED';
      }

      return {
        success: false,
        message: 'Invalid 2FA code. Trust reduced.',
        currentTrust: session.trustScore
      };
    }
  }

  // Main evaluation logic called by the Gate on EVERY request
  evaluateRequest({ sessionId, targetRoute, clientIp, userAgent, simulatedAnomalies = {} }) {
    const session = this.sessions.get(sessionId);

    // 1. Check session existence and active state
    if (!session || session.status === 'TERMINATED') {
      const log = this.logEvent({
        sessionId: sessionId || 'unknown',
        username: session ? session.username : 'unauthenticated',
        route: targetRoute,
        oldTrust: 0,
        newTrust: 0,
        delta: 0,
        reasons: ['Session does not exist or has been terminated'],
        decision: 'BLOCK_TERMINATE'
      });

      return {
        decision: 'BLOCK_TERMINATE',
        status: 403,
        reason: 'Session terminated or invalid',
        currentTrust: 0,
        requiredTrust: this.config.thresholds[targetRoute] || 20,
        log
      };
    }

    const now = Date.now();
    const oldTrust = session.trustScore;
    let currentTrust = session.trustScore;
    const reasons = [];

    // Allow simulated overrides from the client demo panel
    const effectiveIp = simulatedAnomalies.ip || clientIp || session.ip;
    const effectiveUa = simulatedAnomalies.userAgent || userAgent || session.userAgent;

    // 2. TIME DECAY EVALUATION
    const elapsedSeconds = (now - session.lastActive) / 1000;
    if (elapsedSeconds > 10) { // check decay if more than 10s passed
      const decayed = this.calculateTimeDecay(currentTrust, elapsedSeconds);
      const decayDelta = Math.round(decayed - currentTrust);
      if (decayDelta < 0) {
        currentTrust = decayed;
        reasons.push(`Time decay (${Math.round(elapsedSeconds)}s inactive), ${decayDelta}`);
      }
    }

    // 3. ANOMALY DETECTION: IP / Network Change
    if (effectiveIp && effectiveIp !== session.ip) {
      const penalty = this.config.penalties.networkChange;
      currentTrust = Math.max(this.config.minTrust, currentTrust - penalty);
      reasons.push(`New network detected (${session.ip} → ${effectiveIp}), −${penalty}`);
      // Update session IP to new network
      session.ip = effectiveIp;
    }

    // 4. ANOMALY DETECTION: Browser / User-Agent Change
    if (effectiveUa && effectiveUa !== session.userAgent) {
      const penalty = this.config.penalties.fingerprintChange;
      currentTrust = Math.max(this.config.minTrust, currentTrust - penalty);
      reasons.push(`Browser details changed, −${penalty}`);
      // Update session UA
      session.userAgent = effectiveUa;
    }

    // 5. ANOMALY DETECTION: Request Velocity Burst
    // Track timestamps within burstWindowMs (default 2s)
    session.recentTimestamps.push(now);
    session.recentTimestamps = session.recentTimestamps.filter(t => (now - t) <= this.config.burstWindowMs);
    
    // Check if request count exceeds burst threshold or forced simulated burst
    if (session.recentTimestamps.length > this.config.burstThresholdCount || simulatedAnomalies.burst) {
      const penalty = this.config.penalties.velocityBurst;
      currentTrust = Math.max(this.config.minTrust, currentTrust - penalty);
      reasons.push(`Rapid request burst (${session.recentTimestamps.length} reqs in ${this.config.burstWindowMs / 1000}s), −${penalty}`);
      // Reset timestamps to avoid repeated continuous penalty for same burst
      session.recentTimestamps = [now];
    }

    // 6. POSITIVE REINFORCEMENT (Normal steady activity)
    // Anti-Farming: Page-specific and global passive ceilings prevent "trust grinding"
    if (reasons.length === 0) {
      // Ceilings per page:
      // /public cannot farm beyond 40
      // /profile cannot farm beyond 60
      // Passive browsing can never exceed 60 without explicit Step-Up 2FA
      const routeCeiling = targetRoute === '/public' ? 40 : 60;
      const cooldownMs = 3000; // 3 seconds between positive awards
      const timeSinceLast = now - (session.lastRecoveryAt || 0);

      if (timeSinceLast < cooldownMs) {
        reasons.push('Normal activity verified (anti-farming cooldown active)');
      } else if (currentTrust >= routeCeiling) {
        reasons.push(`Normal activity verified (passive recovery capped at ${routeCeiling} without Step-Up 2FA)`);
      } else {
        const recovery = this.config.recovery.normalRequest;
        const newScore = Math.min(routeCeiling, currentTrust + recovery);
        const actualGain = newScore - currentTrust;
        if (actualGain > 0) {
          currentTrust = newScore;
          session.lastRecoveryAt = now;
          reasons.push(`Normal activity verified, +${actualGain} (capped at ${routeCeiling})`);
        } else {
          reasons.push(`Normal activity verified (at tier ceiling ${routeCeiling})`);
        }
      }
    }

    // Update session state
    session.trustScore = Math.round(currentTrust);
    session.lastActive = now;

    // 7. POLICY DECISION MATRIX
    const requiredLevel = this.config.thresholds[targetRoute] !== undefined 
      ? this.config.thresholds[targetRoute] 
      : 20;

    let decision = 'ALLOW';
    let httpStatus = 200;

    // Condition 1: Trust is very low (< 20) -> Block and terminate session
    if (session.trustScore < 20) {
      decision = 'BLOCK_TERMINATE';
      httpStatus = 403;
      session.status = 'TERMINATED';
      reasons.push('CRITICAL: Trust score dropped below minimum safety threshold (20). Session terminated.');
    }
    // Condition 2: Trust is high enough -> Allow
    else if (session.trustScore >= requiredLevel) {
      decision = 'ALLOW';
      httpStatus = 200;
    }
    // Condition 3: Trust is a bit low for this specific page -> Ask for fresh 2FA code (Step-Up)
    else {
      decision = 'STEP_UP_REQUIRED';
      httpStatus = 401;
      reasons.push(`Trust score (${session.trustScore}) is below required level (${requiredLevel}) for ${targetRoute}. Step-up 2FA required.`);
    }

    const netDelta = session.trustScore - oldTrust;
    const log = this.logEvent({
      sessionId,
      username: session.username,
      role: session.role,
      route: targetRoute,
      oldTrust,
      newTrust: session.trustScore,
      delta: netDelta,
      reasons,
      decision
    });

    return {
      decision,
      status: httpStatus,
      currentTrust: session.trustScore,
      requiredTrust: requiredLevel,
      role: session.role,
      reasons,
      log
    };
  }
}

module.exports = new TrustEngine();
