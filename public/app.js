// CCN Project: Client-Side Dashboard & Simulation Controller
// Communicates with The Gate and Trust Engine

(function () {
  // Application State
  const state = {
    session: null,
    currentTrust: 0,
    currentIp: '192.168.1.45 (Home Wi-Fi)',
    currentUa: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0',
    activePage: '/public',
    pendingStepUpPage: null,
    logFilter: 'ALL',
    logs: [],
    sseSource: null
  };

  // DOM Elements
  const authView = document.getElementById('authView');
  const dashboardView = document.getElementById('dashboardView');
  const loginForm = document.getElementById('loginForm');
  const navSessionStatus = document.getElementById('navSessionStatus');
  const navClientIp = document.getElementById('navClientIp');
  const navUsername = document.getElementById('navUsername');
  const btnLogout = document.getElementById('btnLogout');

  // Gauge & HUD Elements
  const hudTrustScore = document.getElementById('hudTrustScore');
  const hudTrustState = document.getElementById('hudTrustState');
  const gaugeProgressCircle = document.getElementById('gaugeProgressCircle');
  const hudCurrentIp = document.getElementById('hudCurrentIp');
  const hudCurrentUa = document.getElementById('hudCurrentUa');
  const hudSessionStatus = document.getElementById('hudSessionStatus');

  // Matrix Tiles
  const matrixTiles = {
    '/public': { tile: document.getElementById('tilePublic'), state: document.getElementById('statePublic'), req: 20 },
    '/profile': { tile: document.getElementById('tileProfile'), state: document.getElementById('stateProfile'), req: 40 },
    '/payment': { tile: document.getElementById('tilePayment'), state: document.getElementById('statePayment'), req: 60 },
    '/admin': { tile: document.getElementById('tileAdmin'), state: document.getElementById('stateAdmin'), req: 80 }
  };

  // Navigation Tabs & Content
  const navTabs = document.querySelectorAll('.nav-tab');
  const pageContentBody = document.getElementById('pageContentBody');
  const pageLoading = document.getElementById('pageLoading');

  // Step-Up Modal Elements
  const stepUpModal = document.getElementById('stepUpModal');
  const btnCloseStepUp = document.getElementById('btnCloseStepUp');
  const btnCancelStepUp = document.getElementById('btnCancelStepUp');
  const stepUpForm = document.getElementById('stepUpForm');
  const inputStepUpCode = document.getElementById('inputStepUpCode');
  const modalCurrentTrust = document.getElementById('modalCurrentTrust');
  const modalRequiredTrust = document.getElementById('modalRequiredTrust');
  const modalReasonText = document.getElementById('modalReasonText');

  // Simulator Elements
  const btnSimNetworkChange = document.getElementById('btnSimNetworkChange');
  const btnSimUaChange = document.getElementById('btnSimUaChange');
  const btnSimBurst = document.getElementById('btnSimBurst');
  const btnSimNormal = document.getElementById('btnSimNormal');
  const btnSimStepUp = document.getElementById('btnSimStepUp');
  const btnSimReset = document.getElementById('btnSimReset');
  const timeJumpButtons = document.querySelectorAll('.btn-sim-time');

  // Audit Log Elements
  const auditLogTbody = document.getElementById('auditLogTbody');
  const filterButtons = document.querySelectorAll('.btn-filter');
  const btnClearLogs = document.getElementById('btnClearLogs');

  // =========================================================================
  // INITIALIZATION & SESSION CHECK
  // =========================================================================
  async function init() {
    setupEventListeners();
    await checkSessionStatus();
    connectSseStream();
  }

  async function checkSessionStatus() {
    try {
      const res = await fetch('/api/auth/status');
      const data = await res.json();

      if (data.active && data.session) {
        setSessionActive(data.session);
        await navigateToPage(state.activePage);
      } else {
        setSessionInactive();
      }
    } catch (err) {
      console.warn('Session status check error:', err);
      setSessionInactive();
    }
  }

  function setSessionActive(session) {
    state.session = session;
    state.currentTrust = session.trustScore;
    state.currentIp = session.ip;
    state.currentUa = session.userAgent;

    authView.style.display = 'none';
    dashboardView.style.display = 'flex';
    navSessionStatus.style.display = 'flex';

    navUsername.textContent = session.username;
    navClientIp.textContent = session.ip.split(' ')[0];
    hudCurrentIp.textContent = session.ip;
    hudCurrentUa.textContent = session.userAgent.includes('Mobile') ? 'Mobile Device' : 'Desktop Browser';
    hudSessionStatus.textContent = session.status;
    hudSessionStatus.className = 'badge-status';

    updateTrustDisplay(session.trustScore);
  }

  function setSessionInactive() {
    state.session = null;
    state.currentTrust = 0;
    authView.style.display = 'flex';
    dashboardView.style.display = 'none';
    navSessionStatus.style.display = 'none';
  }

  // =========================================================================
  // REAL-TIME AUDIT LOG SSE STREAM
  // =========================================================================
  function connectSseStream() {
    if (state.sseSource) {
      state.sseSource.close();
    }

    state.sseSource = new EventSource('/api/logs/stream');

    state.sseSource.onmessage = function (event) {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === 'INIT_LOGS') {
          state.logs = payload.logs || [];
          renderLogs();
        } else if (payload.type === 'NEW_LOG') {
          state.logs.unshift(payload.log);
          if (state.logs.length > 200) state.logs.pop();
          renderLogs();

          // Sync trust score from authoritative engine log
          if (state.session && payload.log.sessionId === state.session.sessionId) {
            updateTrustDisplay(payload.log.newTrust);
          }
        }
      } catch (err) {
        console.error('SSE parse error:', err);
      }
    };

    state.sseSource.onerror = function () {
      console.warn('SSE disconnected, retrying in 3s...');
      setTimeout(connectSseStream, 3000);
    };
  }

  // =========================================================================
  // DYNAMIC TRUST GAUGE & MATRIX DISPLAY
  // =========================================================================
  function updateTrustDisplay(score) {
    state.currentTrust = score;
    hudTrustScore.textContent = Math.round(score);

    // Circumference = 2 * PI * 70 ≈ 440
    const circumference = 440;
    const offset = circumference - (circumference * Math.max(0, Math.min(100, score)) / 100);
    gaugeProgressCircle.style.strokeDashoffset = offset;

    // Color & Status thresholds
    let color = '#10b981'; // green
    let label = 'HIGH TRUST (ALLOWED)';

    if (score >= 80) {
      color = '#10b981';
      label = 'MAXIMUM TRUST (ADMIN UNLOCKED)';
    } else if (score >= 60) {
      color = '#34d399';
      label = 'HIGH TRUST (PAYMENT ALLOWED)';
    } else if (score >= 40) {
      color = '#f59e0b';
      label = 'MODERATE TRUST (PROFILE ONLY)';
    } else if (score >= 20) {
      color = '#f97316';
      label = 'LOW TRUST (PUBLIC ONLY)';
    } else {
      color = '#ef4444';
      label = 'CRITICAL (SESSION TERMINATED)';
    }

    gaugeProgressCircle.style.stroke = color;
    hudTrustScore.style.color = color;
    hudTrustState.textContent = label;
    hudTrustState.style.color = color;

    if (score < 20) {
      hudSessionStatus.textContent = 'TERMINATED';
      hudSessionStatus.className = 'badge-status text-danger';
    }

    updateAccessMatrix(score);
  }

  function updateAccessMatrix(score) {
    for (const [route, item] of Object.entries(matrixTiles)) {
      item.tile.classList.remove('unlocked', 'step-up', 'locked');

      if (score >= item.req) {
        item.tile.classList.add('unlocked');
        item.state.textContent = 'ALLOWED';
      } else if (score >= 20) {
        item.tile.classList.add('step-up');
        item.state.textContent = 'STEP-UP (2FA)';
      } else {
        item.tile.classList.add('locked');
        item.state.textContent = 'BLOCKED';
      }
    }
  }

  // =========================================================================
  // GATE REQUESTS & PAGE NAVIGATION
  // =========================================================================
  async function navigateToPage(route, simulatedHeaders = {}) {
    state.activePage = route;

    // Update active tab button style
    navTabs.forEach(tab => {
      tab.classList.toggle('active', tab.getAttribute('data-page') === route);
    });

    pageLoading.style.display = 'block';
    pageContentBody.innerHTML = '';

    try {
      const headers = {
        'Accept': 'application/json',
        'X-Simulated-IP': simulatedHeaders.ip || state.currentIp,
        'X-Simulated-UA': simulatedHeaders.userAgent || state.currentUa,
        ...(simulatedHeaders.burst ? { 'X-Simulated-Burst': 'true' } : {})
      };

      const res = await fetch(route, { headers });
      const data = await res.json();

      pageLoading.style.display = 'none';

      // Case 1: ALLOW (200 OK)
      if (res.status === 200) {
        renderAllowedPage(data);
      }
      // Case 2: STEP_UP_REQUIRED (401 Challenge)
      else if (res.status === 401 && data.decision === 'STEP_UP_REQUIRED') {
        renderChallengedPage(data);
        showStepUpModal(data, route);
      }
      // Case 3: BLOCK_TERMINATE (403 Forbidden)
      else if (res.status === 403 || data.decision === 'BLOCK_TERMINATE') {
        renderBlockedPage(data);
      }
    } catch (err) {
      pageLoading.style.display = 'none';
      pageContentBody.innerHTML = `<div class="card p-3 text-danger">Network Error: ${err.message}</div>`;
    }
  }

  function renderAllowedPage(data) {
    pageContentBody.innerHTML = `
      <div class="page-view-content">
        <div class="page-view-header">
          <h2>${data.page}</h2>
          <div class="page-badge-row">
            <span class="badge-trust pass">Gate Decision: ALLOW (200 OK)</span>
            <span class="badge-trust pass">Required: ≥${data.requiredTrust}</span>
            <span class="badge-trust pass">Current Trust: ${data.currentTrust}/100</span>
          </div>
        </div>
        <p class="text-muted" style="margin-bottom: 1rem;">${data.message}</p>
        <div class="page-data-card">
          <h4 style="margin-bottom: 0.5rem; color: #93c5fd;">Resource Payload:</h4>
          <pre class="font-mono" style="font-size: 0.85rem; color: #e2e8f0; overflow-x: auto; background: rgba(0,0,0,0.4); padding: 1rem; border-radius: 8px;">${JSON.stringify(data.content, null, 2)}</pre>
        </div>
      </div>
    `;
  }

  function renderChallengedPage(data) {
    pageContentBody.innerHTML = `
      <div class="page-view-content">
        <div class="page-view-header">
          <h2 class="text-warning">⚠️ Step-Up Verification Required</h2>
          <div class="page-badge-row">
            <span class="badge-trust" style="background: rgba(245,158,11,0.2); color: #fbbf24; border: 1px solid #f59e0b;">Gate Decision: CHALLENGE (401)</span>
            <span class="badge-trust" style="background: rgba(245,158,11,0.2); color: #fbbf24;">Required Trust: ≥${data.requiredTrust}</span>
            <span class="badge-trust" style="background: rgba(245,158,11,0.2); color: #fbbf24;">Current: ${data.currentTrust}</span>
          </div>
        </div>
        <p style="margin: 1rem 0; color: #fbbf24;">${data.message}</p>
        <div class="page-data-card" style="border-color: rgba(245,158,11,0.3); background: rgba(245,158,11,0.05);">
          <p>The gate checked the trust engine. Your trust score is a bit low for this specific sensitive page.</p>
          <p style="margin-top: 8px;">Please verify with a fresh 2FA code in the modal to elevate your trust back to allowed level.</p>
          <button class="btn btn-primary" style="margin-top: 1rem;" onclick="document.getElementById('stepUpModal').style.display='flex'">Open 2FA Verification Dialog</button>
        </div>
      </div>
    `;
  }

  function renderBlockedPage(data) {
    pageContentBody.innerHTML = `
      <div class="page-view-content">
        <div class="page-view-header">
          <h2 class="text-danger">🛑 Access Blocked & Session Terminated</h2>
          <div class="page-badge-row">
            <span class="badge-trust" style="background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid #ef4444;">Gate Decision: BLOCK (403 Forbidden)</span>
            <span class="badge-trust" style="background: rgba(239,68,68,0.2); color: #f87171;">Session State: TERMINATED</span>
          </div>
        </div>
        <p style="margin: 1rem 0; color: #f87171;">${data.message || 'Session trust has decayed or dropped below 20.'}</p>
        <div class="page-data-card" style="border-color: rgba(239,68,68,0.3); background: rgba(239,68,68,0.05);">
          <p><strong>Zero Trust Policy:</strong> Trust score dropped below the critical minimum safety barrier (20) or a severe anomaly occurred.</p>
          <p style="margin-top: 8px;">Your session token has been revoked by the Gate. To regain access, please sign in with fresh primary credentials.</p>
          <button class="btn btn-outline-danger" style="margin-top: 1rem;" onclick="location.reload()">Return to Login</button>
        </div>
      </div>
    `;
  }

  // =========================================================================
  // STEP-UP 2FA MODAL
  // =========================================================================
  function showStepUpModal(challengeData, targetRoute) {
    state.pendingStepUpPage = targetRoute;
    modalCurrentTrust.textContent = challengeData.currentTrust;
    modalRequiredTrust.textContent = challengeData.requiredTrust;
    modalReasonText.textContent = `Accessing ${targetRoute} requires a trust level of at least ${challengeData.requiredTrust}. Your session currently has ${challengeData.currentTrust}. Submit a fresh 2FA code to boost trust.`;
    inputStepUpCode.value = '123456';
    stepUpModal.style.display = 'flex';
  }

  function hideStepUpModal() {
    stepUpModal.style.display = 'none';
  }

  // =========================================================================
  // AUDIT LOG RENDERING & FILTERING
  // =========================================================================
  function renderLogs() {
    const filtered = state.logs.filter(log => {
      if (state.logFilter === 'ALL') return true;
      return log.decision === state.logFilter;
    });

    if (filtered.length === 0) {
      auditLogTbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-sub); padding: 2rem;">No audit logs matching filter.</td></tr>`;
      return;
    }

    auditLogTbody.innerHTML = filtered.map(log => {
      const deltaClass = log.delta > 0 ? 'positive' : log.delta < 0 ? 'negative' : 'neutral';
      const deltaSign = log.delta > 0 ? `+${log.delta}` : `${log.delta}`;
      const reasonsHtml = log.reasons.map(r => `• ${escapeHtml(r)}`).join('<br>');

      return `
        <tr>
          <td class="font-mono text-muted">${log.formattedTime}</td>
          <td><strong class="font-mono" style="color: #93c5fd;">${escapeHtml(log.route)}</strong></td>
          <td><span class="delta-pill ${deltaClass}">${deltaSign}</span></td>
          <td class="font-mono">${log.oldTrust} → <strong>${log.newTrust}</strong></td>
          <td><span class="badge-decision ${log.decision}">${log.decision}</span></td>
          <td style="color: var(--text-muted); font-size: 0.78rem;">${reasonsHtml}</td>
        </tr>
      `;
    }).join('');
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"']/g, function (m) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m];
    });
  }

  // =========================================================================
  // EVENT LISTENERS & SIMULATOR TRIGGERS
  // =========================================================================
  function setupEventListeners() {
    // 1. Primary Login Form
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('inputUsername').value;
      const password = document.getElementById('inputPassword').value;
      const totpCode = document.getElementById('inputTotp').value;
      const initialIp = document.getElementById('inputInitialNetwork').value;

      state.currentIp = initialIp;

      try {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Simulated-IP': initialIp
          },
          body: JSON.stringify({ username, password, totpCode })
        });

        const data = await res.json();
        if (data.success) {
          setSessionActive(data.session);
          await navigateToPage('/public');
        } else {
          alert('Authentication Error: ' + data.message);
        }
      } catch (err) {
        alert('Login failed: ' + err.message);
      }
    });

    // 2. Sign Out
    btnLogout.addEventListener('click', async () => {
      await fetch('/api/auth/logout', { method: 'POST' });
      setSessionInactive();
    });

    // 3. Navigation Tabs
    navTabs.forEach(tab => {
      tab.addEventListener('click', () => {
        const page = tab.getAttribute('data-page');
        navigateToPage(page);
      });
    });

    // 4. Step-Up 2FA Modal Form Submission
    stepUpForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const code = inputStepUpCode.value.trim();

      try {
        const res = await fetch('/api/simulate/step-up', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code })
        });
        const data = await res.json();

        if (data.success) {
          hideStepUpModal();
          updateTrustDisplay(data.currentTrust);
          // Re-navigate to the page user originally wanted
          if (state.pendingStepUpPage) {
            await navigateToPage(state.pendingStepUpPage);
          }
        } else {
          alert('Step-Up Failed: ' + data.message);
          updateTrustDisplay(data.currentTrust);
        }
      } catch (err) {
        alert('Step-up request failed: ' + err.message);
      }
    });

    btnCloseStepUp.addEventListener('click', hideStepUpModal);
    btnCancelStepUp.addEventListener('click', hideStepUpModal);

    // 5. SIMULATOR: Network / IP Change (−25)
    btnSimNetworkChange.addEventListener('click', async () => {
      const networks = [
        '172.56.21.90 (Cellular Network)',
        '10.240.12.5 (Public Coffee Shop Wi-Fi)',
        '198.51.100.77 (Unknown Foreign Subnet)',
        '192.168.1.45 (Home Wi-Fi)'
      ];
      // Pick next different network
      const nextIp = networks.find(ip => ip !== state.currentIp) || networks[0];
      state.currentIp = nextIp;
      hudCurrentIp.textContent = nextIp;
      navClientIp.textContent = nextIp.split(' ')[0];

      // Send request through gate to apply penalty
      await navigateToPage(state.activePage, { ip: nextIp });
    });

    // 6. SIMULATOR: User-Agent / Browser Change (−30)
    btnSimUaChange.addEventListener('click', async () => {
      const uas = [
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148',
        'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'python-requests/2.31.0 (Automated Tool)',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0'
      ];
      const nextUa = uas.find(u => u !== state.currentUa) || uas[0];
      state.currentUa = nextUa;
      hudCurrentUa.textContent = nextUa.includes('iPhone') ? 'iPhone Safari' : nextUa.includes('Firefox') ? 'Linux Firefox' : 'Automated Script';

      await navigateToPage(state.activePage, { userAgent: nextUa });
    });

    // 7. SIMULATOR: Request Velocity Burst (−20)
    btnSimBurst.addEventListener('click', async () => {
      // Fire 7 rapid requests within 200ms
      const promises = [];
      for (let i = 0; i < 7; i++) {
        promises.push(
          fetch(state.activePage, {
            headers: {
              'X-Simulated-Burst': 'true',
              'X-Simulated-IP': state.currentIp,
              'X-Simulated-UA': state.currentUa
            }
          })
        );
      }
      await Promise.all(promises);
      await navigateToPage(state.activePage);
    });

    // 8. SIMULATOR: Time Travel (+15m, +30m, +60m half-life decay)
    timeJumpButtons.forEach(btn => {
      btn.addEventListener('click', async () => {
        const jumpSeconds = btn.getAttribute('data-jump');
        const res = await fetch('/api/simulate/time-jump', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ seconds: jumpSeconds })
        });
        const data = await res.json();
        if (data.newTrust !== undefined) {
          updateTrustDisplay(data.newTrust);
          await navigateToPage(state.activePage);
        }
      });
    });

    // 9. SIMULATOR: Normal Action (+2)
    btnSimNormal.addEventListener('click', async () => {
      await navigateToPage(state.activePage);
    });

    // 10. SIMULATOR: Step-Up 2FA (+35)
    btnSimStepUp.addEventListener('click', () => {
      modalCurrentTrust.textContent = state.currentTrust;
      modalRequiredTrust.textContent = '80 (Admin Target)';
      modalReasonText.textContent = 'Performing proactive Step-Up 2FA to raise session trust score by +35.';
      inputStepUpCode.value = '123456';
      stepUpModal.style.display = 'flex';
    });

    // 11. SIMULATOR: Reset Session (70)
    btnSimReset.addEventListener('click', async () => {
      const res = await fetch('/api/simulate/reset', { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        state.currentIp = data.session.ip;
        state.currentUa = data.session.userAgent;
        hudCurrentIp.textContent = state.currentIp;
        navClientIp.textContent = state.currentIp.split(' ')[0];
        updateTrustDisplay(70);
        await navigateToPage('/public');
      }
    });

    // 12. Audit Log Filters
    filterButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        filterButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        state.logFilter = btn.getAttribute('data-filter');
        renderLogs();
      });
    });

    // 13. Clear Logs
    btnClearLogs.addEventListener('click', () => {
      state.logs = [];
      renderLogs();
    });
  }

  // Initialize on DOM load
  window.addEventListener('DOMContentLoaded', init);
})();
