// CCN Project: Client-Side Dashboard & Simulation Controller
// Communicates with The Gate and Trust Engine

(function () {
  // Application State
  const state = {
    session: null,
    currentTrust: 0,
    currentRole: 'USER',
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
  const navUsername = document.getElementById('navUsername');
  const navUserRole = document.getElementById('navUserRole');
  const navWifiSelect = document.getElementById('navWifiSelect');
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
    '/public':  { tile: document.getElementById('tilePublic'),  state: document.getElementById('statePublic'),  req: 20 },
    '/profile': { tile: document.getElementById('tileProfile'), state: document.getElementById('stateProfile'), req: 40 },
    '/payment': { tile: document.getElementById('tilePayment'), state: document.getElementById('statePayment'), req: 60 },
    '/admin':   { tile: document.getElementById('tileAdmin'),   state: document.getElementById('stateAdmin'),   req: 80 }
  };

  // Navigation Tabs & Content
  const navTabs = document.querySelectorAll('.nav-tab');
  const pageContentBody = document.getElementById('pageContentBody');
  const pageLoading = document.getElementById('pageLoading');

  // Step-Up Modal
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

  // Audit Log
  const auditLogTbody = document.getElementById('auditLogTbody');
  const filterButtons = document.querySelectorAll('.btn-filter');
  const btnClearLogs = document.getElementById('btnClearLogs');
  const toastContainer = document.getElementById('toastContainer');

  // =========================================================================
  // TOAST NOTIFICATIONS
  // =========================================================================
  function showToast(message, type = 'info') {
    if (!toastContainer) return;
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    const icon = type === 'danger' ? '🛑' : type === 'warning' ? '⚠️' : type === 'success' ? '✅' : 'ℹ️';
    toast.innerHTML = `<span class="toast-icon">${icon}</span><span>${message}</span>`;
    toastContainer.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('show'));
    setTimeout(() => { toast.classList.remove('show'); setTimeout(() => toast.remove(), 400); }, 3500);
  }

  // =========================================================================
  // INIT
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
      setSessionInactive();
    }
  }

  function setSessionActive(session) {
    state.session = session;
    state.currentTrust = session.trustScore;
    state.currentRole = session.role || 'USER';
    state.currentIp = session.ip;
    state.currentUa = session.userAgent;

    authView.style.display = 'none';
    dashboardView.style.display = 'flex';
    navSessionStatus.style.display = 'flex';

    navUsername.textContent = session.username;
    updateRoleBadge(session.role || 'USER');
    hudCurrentIp.textContent = session.ip;
    hudCurrentUa.textContent = session.userAgent.includes('Mobile') ? 'Mobile Device' : 'Desktop Browser';
    hudSessionStatus.textContent = 'ACTIVE';
    hudSessionStatus.className = 'badge-status';

    if (navWifiSelect) {
      const match = Array.from(navWifiSelect.options).find(o => o.value === session.ip);
      if (match) navWifiSelect.value = match.value;
    }
    updateTrustDisplay(session.trustScore);
  }

  function setSessionInactive() {
    state.session = null;
    state.currentTrust = 0;
    authView.style.display = 'flex';
    dashboardView.style.display = 'none';
    navSessionStatus.style.display = 'none';
  }

  function updateRoleBadge(role) {
    state.currentRole = role;
    if (!navUserRole) return;
    navUserRole.textContent = role;
    navUserRole.className = 'badge-role ' + (role === 'ADMIN' ? 'admin' : 'user');
  }

  // =========================================================================
  // SSE STREAM
  // =========================================================================
  function connectSseStream() {
    if (state.sseSource) state.sseSource.close();
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
          if (state.session && payload.log.sessionId === state.session.sessionId) {
            updateTrustDisplay(payload.log.newTrust);
          }
        }
      } catch (err) {}
    };
    state.sseSource.onerror = () => setTimeout(connectSseStream, 3000);
  }

  // =========================================================================
  // TRUST GAUGE & MATRIX
  // =========================================================================
  function updateTrustDisplay(score) {
    state.currentTrust = score;
    hudTrustScore.textContent = Math.round(score);

    const circumference = 440;
    const offset = circumference - (circumference * Math.max(0, Math.min(100, score)) / 100);
    gaugeProgressCircle.style.strokeDashoffset = offset;

    let color, label;
    if (score >= 80) {
      color = '#10b981';
      label = state.currentRole === 'ADMIN' ? 'MAX TRUST — ADMIN UNLOCKED' : 'MAX TRUST — ADMIN ROLE REQUIRED';
    } else if (score >= 60) {
      color = '#34d399';
      label = 'HIGH TRUST (PAYMENT) — ceiling: 60 passive, Step-Up for more';
    } else if (score >= 40) {
      color = '#f59e0b';
      label = 'MODERATE TRUST (PROFILE) — passive ceiling: 60';
    } else if (score >= 20) {
      color = '#f97316';
      label = 'LOW TRUST (PUBLIC ONLY) — passive ceiling: 40';
    } else {
      color = '#ef4444';
      label = 'CRITICAL — SESSION TERMINATED';
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
      item.tile.classList.remove('unlocked', 'step-up', 'locked', 'role-blocked');
      if (route === '/admin' && state.currentRole !== 'ADMIN') {
        item.tile.classList.add('role-blocked');
        item.state.textContent = 'ROLE FORBIDDEN';
      } else if (score >= item.req) {
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
  // NAVIGATION & PAGE RENDERING
  // =========================================================================
  async function navigateToPage(route, simulatedHeaders = {}) {
    state.activePage = route;
    navTabs.forEach(tab => tab.classList.toggle('active', tab.getAttribute('data-page') === route));
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

      if (res.status === 200) {
        renderAllowedPage(data);
      } else if (res.status === 401 && data.decision === 'STEP_UP_REQUIRED') {
        renderChallengedPage(data);
        showStepUpModal(data, route);
      } else if (res.status === 403 && data.decision === 'ROLE_FORBIDDEN') {
        renderRoleForbiddenPage(data);
      } else if (res.status === 403 || data.decision === 'BLOCK_TERMINATE') {
        renderBlockedPage(data);
      }
    } catch (err) {
      pageLoading.style.display = 'none';
      pageContentBody.innerHTML = `<div class="card p-3 text-danger">Network Error: ${err.message}</div>`;
    }
  }

  function renderAllowedPage(data) {
    const roleTag = data.currentRole
      ? `<span class="badge-trust pass" style="background:rgba(16,185,129,0.15);color:#6ee7b7;border:1px solid #10b981;">Role: ${data.currentRole}</span>`
      : '';
    pageContentBody.innerHTML = `
      <div class="page-view-content">
        <div class="page-view-header">
          <h2>${data.page}</h2>
          <div class="page-badge-row">
            <span class="badge-trust pass">Gate Decision: ALLOW (200 OK)</span>
            <span class="badge-trust pass">Required: &ge;${data.requiredTrust}</span>
            <span class="badge-trust pass">Current Trust: ${data.currentTrust}/100</span>
            ${roleTag}
          </div>
        </div>
        <p class="text-muted" style="margin-bottom: 1rem;">${data.message}</p>
        <div class="page-data-card">
          <h4 style="margin-bottom: 0.5rem; color: #93c5fd;">Resource Payload:</h4>
          <pre class="font-mono" style="font-size: 0.85rem; color: #e2e8f0; overflow-x: auto; background: rgba(0,0,0,0.4); padding: 1rem; border-radius: 8px;">${JSON.stringify(data.content, null, 2)}</pre>
        </div>
      </div>`;
  }

  function renderChallengedPage(data) {
    pageContentBody.innerHTML = `
      <div class="page-view-content">
        <div class="page-view-header">
          <h2 class="text-warning">&#9888;&#65039; Step-Up Verification Required</h2>
          <div class="page-badge-row">
            <span class="badge-trust" style="background:rgba(245,158,11,0.2);color:#fbbf24;border:1px solid #f59e0b;">Gate Decision: CHALLENGE (401)</span>
            <span class="badge-trust" style="background:rgba(245,158,11,0.2);color:#fbbf24;">Required Trust: &ge;${data.requiredTrust}</span>
            <span class="badge-trust" style="background:rgba(245,158,11,0.2);color:#fbbf24;">Current: ${data.currentTrust}</span>
          </div>
        </div>
        <p style="margin: 1rem 0; color: #fbbf24;">${data.message}</p>
        <div class="page-data-card" style="border-color:rgba(245,158,11,0.3);background:rgba(245,158,11,0.05);">
          <p>Your trust score is below this page tier. Note: passive browsing is capped — only Step-Up 2FA can elevate beyond the ceiling.</p>
          <button class="btn btn-primary" style="margin-top: 1rem;" onclick="document.getElementById('stepUpModal').style.display='flex'">Open 2FA Verification Dialog</button>
        </div>
      </div>`;
  }

  function renderRoleForbiddenPage(data) {
    pageContentBody.innerHTML = `
      <div class="page-view-content">
        <div class="page-view-header">
          <h2 class="text-danger">&#128683; Role-Based Access Denied (RBAC)</h2>
          <div class="page-badge-row">
            <span class="badge-trust" style="background:rgba(239,68,68,0.2);color:#f87171;border:1px solid #ef4444;">Gate Decision: ROLE FORBIDDEN (403)</span>
            <span class="badge-trust" style="background:rgba(239,68,68,0.1);color:#f87171;">Required Role: ${data.requiredRole || 'ADMIN'}</span>
            <span class="badge-trust" style="background:rgba(239,68,68,0.1);color:#f87171;">Your Role: ${data.currentRole || state.currentRole}</span>
            <span class="badge-trust" style="background:rgba(59,130,246,0.1);color:#93c5fd;">Current Trust: ${data.currentTrust}/100</span>
          </div>
        </div>
        <p style="margin:1rem 0;color:#f87171;">${data.message}</p>
        <div class="page-data-card" style="border-color:rgba(239,68,68,0.3);background:rgba(239,68,68,0.05);">
          <p><strong style="color:#f87171;">Zero Trust RBAC Policy Enforced:</strong></p>
          <ul style="margin-top:0.75rem;padding-left:1.25rem;color:var(--text-muted);line-height:2;">
            <li>Your role is <strong style="color:#fbbf24;">${data.currentRole || state.currentRole}</strong> &mdash; only <strong style="color:#10b981;">ADMIN</strong> role can enter Admin SOC.</li>
            <li>Trust score of <strong style="color:#93c5fd;">${data.currentTrust}/100</strong> is <em>irrelevant</em> &mdash; role is checked first.</li>
            <li>Even 100/100 trust cannot override a missing role assignment.</li>
            <li>Log out and re-login as <strong>Administrator</strong> persona to access Admin SOC.</li>
          </ul>
          <div style="margin-top:1.25rem;padding:0.85rem;background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.3);border-radius:8px;">
            <p style="color:#6ee7b7;font-size:0.9rem;">&#128161; <strong>Demo Tip:</strong> Sign out and select the <strong>&#9889; Administrator</strong> persona on the login screen.</p>
          </div>
        </div>
      </div>`;
  }

  function renderBlockedPage(data) {
    pageContentBody.innerHTML = `
      <div class="page-view-content">
        <div class="page-view-header">
          <h2 class="text-danger">&#128721; Access Blocked &amp; Session Terminated</h2>
          <div class="page-badge-row">
            <span class="badge-trust" style="background:rgba(239,68,68,0.2);color:#f87171;border:1px solid #ef4444;">Gate Decision: BLOCK (403)</span>
            <span class="badge-trust" style="background:rgba(239,68,68,0.2);color:#f87171;">Session: TERMINATED</span>
          </div>
        </div>
        <p style="margin:1rem 0;color:#f87171;">${data.message || 'Session trust dropped below critical minimum (20).'}</p>
        <div class="page-data-card" style="border-color:rgba(239,68,68,0.3);background:rgba(239,68,68,0.05);">
          <p><strong>Zero Trust Policy:</strong> Trust dropped below critical minimum (20) or a severe anomaly occurred. Session token has been revoked.</p>
          <button class="btn btn-outline-danger" style="margin-top:1rem;" onclick="location.reload()">Return to Login</button>
        </div>
      </div>`;
  }

  // =========================================================================
  // STEP-UP MODAL
  // =========================================================================
  function showStepUpModal(challengeData, targetRoute) {
    state.pendingStepUpPage = targetRoute;
    modalCurrentTrust.textContent = challengeData.currentTrust;
    modalRequiredTrust.textContent = challengeData.requiredTrust;
    modalReasonText.textContent = `Accessing ${targetRoute} requires trust >= ${challengeData.requiredTrust}. Current trust: ${challengeData.currentTrust}. Only Step-Up 2FA can raise trust above the passive ceiling.`;
    inputStepUpCode.value = '123456';
    stepUpModal.style.display = 'flex';
  }

  function hideStepUpModal() { stepUpModal.style.display = 'none'; }

  // =========================================================================
  // AUDIT LOG RENDERING
  // =========================================================================
  function renderLogs() {
    const filtered = state.logs.filter(log => state.logFilter === 'ALL' || log.decision === state.logFilter);

    if (filtered.length === 0) {
      auditLogTbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-sub);padding:2rem;">No audit logs matching filter.</td></tr>`;
      return;
    }

    auditLogTbody.innerHTML = filtered.map(log => {
      const dc = log.delta > 0 ? 'positive' : log.delta < 0 ? 'negative' : 'neutral';
      const ds = log.delta > 0 ? `+${log.delta}` : `${log.delta}`;
      const reasons = log.reasons.map(r => `&bull; ${escapeHtml(r)}`).join('<br>');
      const roleTag = log.role ? `<span class="log-role-tag ${log.role.toLowerCase()}">${log.role}</span>` : '';
      return `<tr>
        <td class="font-mono text-muted">${log.formattedTime}</td>
        <td><strong class="font-mono" style="color:#93c5fd;">${escapeHtml(log.route)}</strong> ${roleTag}</td>
        <td><span class="delta-pill ${dc}">${ds}</span></td>
        <td class="font-mono">${log.oldTrust} &rarr; <strong>${log.newTrust}</strong></td>
        <td><span class="badge-decision ${log.decision}">${log.decision}</span></td>
        <td style="color:var(--text-muted);font-size:0.78rem;">${reasons}</td>
      </tr>`;
    }).join('');
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
  }

  // =========================================================================
  // EVENT LISTENERS
  // =========================================================================
  function setupEventListeners() {
    // 0. Quick Persona Buttons
    const btnSelectCommonUser = document.getElementById('btnSelectCommonUser');
    const btnSelectAdminUser = document.getElementById('btnSelectAdminUser');
    const inputUsernameEl = document.getElementById('inputUsername');
    const inputRoleEl = document.getElementById('inputRole');

    if (btnSelectCommonUser) {
      btnSelectCommonUser.addEventListener('click', () => {
        inputUsernameEl.value = 'alice@secure.lab';
        if (inputRoleEl) inputRoleEl.value = 'USER';
        btnSelectCommonUser.classList.add('active');
        btnSelectAdminUser.classList.remove('active');
      });
    }
    if (btnSelectAdminUser) {
      btnSelectAdminUser.addEventListener('click', () => {
        inputUsernameEl.value = 'admin@secure.lab';
        if (inputRoleEl) inputRoleEl.value = 'ADMIN';
        btnSelectAdminUser.classList.add('active');
        btnSelectCommonUser.classList.remove('active');
      });
    }

    // 1. Login Form
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('inputUsername').value;
      const password = document.getElementById('inputPassword').value;
      const totpCode = document.getElementById('inputTotp').value;
      const role = document.getElementById('inputRole') ? document.getElementById('inputRole').value : 'USER';
      const initialIp = document.getElementById('inputInitialNetwork').value;
      state.currentIp = initialIp;

      try {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Simulated-IP': initialIp },
          body: JSON.stringify({ username, password, totpCode, role })
        });
        const data = await res.json();
        if (data.success) {
          setSessionActive(data.session);
          await navigateToPage('/public');
          showToast(`Logged in as [${data.session.role}]: ${data.session.username}`, 'success');
        } else {
          showToast('Login Error: ' + data.message, 'danger');
        }
      } catch (err) {
        showToast('Login failed: ' + err.message, 'danger');
      }
    });

    // 2. Logout
    btnLogout.addEventListener('click', async () => {
      await fetch('/api/auth/logout', { method: 'POST' });
      setSessionInactive();
    });

    // 3. Nav Tabs
    navTabs.forEach(tab => tab.addEventListener('click', () => navigateToPage(tab.getAttribute('data-page'))));

    // 4. Live Wi-Fi Switcher in Navbar — triggers real -25 penalty
    if (navWifiSelect) {
      navWifiSelect.addEventListener('change', async () => {
        const newIp = navWifiSelect.value;
        if (newIp === state.currentIp) return;
        const oldLabel = state.currentIp.split(' ')[0];
        state.currentIp = newIp;
        hudCurrentIp.textContent = newIp;
        showToast(`Wi-Fi changed: ${oldLabel} &rarr; ${newIp.split(' ')[0]} (network change penalty: -25)`, 'warning');
        await navigateToPage(state.activePage, { ip: newIp });
      });
    }

    // 5. Step-Up 2FA Modal
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
          showToast(`Step-Up 2FA verified! Trust boosted to ${data.currentTrust}`, 'success');
          if (state.pendingStepUpPage) await navigateToPage(state.pendingStepUpPage);
        } else {
          showToast('Step-Up Failed: ' + data.message, 'danger');
          updateTrustDisplay(data.currentTrust);
        }
      } catch (err) {
        showToast('Step-up error: ' + err.message, 'danger');
      }
    });
    btnCloseStepUp.addEventListener('click', hideStepUpModal);
    btnCancelStepUp.addEventListener('click', hideStepUpModal);

    // 6. Simulator: Network Change (-25)
    btnSimNetworkChange.addEventListener('click', async () => {
      const networks = [
        '172.56.21.90 (Cellular Network)',
        '10.240.12.5 (Public Coffee Shop Wi-Fi)',
        '198.51.100.77 (Unknown Foreign Subnet)',
        '192.168.1.45 (Home Wi-Fi)'
      ];
      const nextIp = networks.find(ip => ip !== state.currentIp) || networks[0];
      state.currentIp = nextIp;
      hudCurrentIp.textContent = nextIp;
      if (navWifiSelect) {
        const match = Array.from(navWifiSelect.options).find(o => o.value === nextIp);
        navWifiSelect.value = match ? match.value : navWifiSelect.options[0].value;
      }
      showToast(`Network change simulated: ${nextIp.split(' ')[0]} (-25 penalty)`, 'warning');
      await navigateToPage(state.activePage, { ip: nextIp });
    });

    // 7. Simulator: UA Change (-30)
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
      showToast('Browser/device fingerprint changed (-30 penalty)', 'warning');
      await navigateToPage(state.activePage, { userAgent: nextUa });
    });

    // 8. Simulator: Velocity Burst (-20)
    btnSimBurst.addEventListener('click', async () => {
      const promises = Array.from({ length: 7 }, () =>
        fetch(state.activePage, { headers: { 'X-Simulated-Burst': 'true', 'X-Simulated-IP': state.currentIp, 'X-Simulated-UA': state.currentUa } })
      );
      await Promise.all(promises);
      showToast('Velocity burst: 7 rapid requests fired (-20 penalty)', 'warning');
      await navigateToPage(state.activePage);
    });

    // 9. Time Jump
    timeJumpButtons.forEach(btn => {
      btn.addEventListener('click', async () => {
        const jumpSeconds = btn.getAttribute('data-jump');
        const mins = Math.round(Number(jumpSeconds) / 60);
        const res = await fetch('/api/simulate/time-jump', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ seconds: jumpSeconds })
        });
        const data = await res.json();
        if (data.newTrust !== undefined) {
          updateTrustDisplay(data.newTrust);
          showToast(`Time jumped +${mins} min: trust ${data.oldTrust} -> ${data.newTrust}`, 'warning');
          await navigateToPage(state.activePage);
        }
      });
    });

    // 10. Normal Action (+2 with ceiling)
    btnSimNormal.addEventListener('click', async () => {
      showToast('Normal activity (+2, subject to passive tier ceiling)', 'info');
      await navigateToPage(state.activePage);
    });

    // 11. Proactive Step-Up
    btnSimStepUp.addEventListener('click', () => {
      modalCurrentTrust.textContent = state.currentTrust;
      modalRequiredTrust.textContent = '80 (Admin Target)';
      modalReasonText.textContent = 'Proactive Step-Up 2FA: boosts trust +35, overcoming the passive 60-point ceiling. Required to access Payment/Admin from degraded trust.';
      inputStepUpCode.value = '123456';
      stepUpModal.style.display = 'flex';
    });

    // 12. Reset Session
    btnSimReset.addEventListener('click', async () => {
      const res = await fetch('/api/simulate/reset', { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        state.currentIp = data.session.ip;
        state.currentUa = data.session.userAgent;
        hudCurrentIp.textContent = state.currentIp;
        if (navWifiSelect) navWifiSelect.value = state.currentIp;
        updateTrustDisplay(70);
        showToast('Session reset to baseline trust 70', 'info');
        await navigateToPage('/public');
      }
    });

    // 13. Log Filters
    filterButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        filterButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        state.logFilter = btn.getAttribute('data-filter');
        renderLogs();
      });
    });

    // 14. Clear Logs
    btnClearLogs.addEventListener('click', () => { state.logs = []; renderLogs(); });
  }

  window.addEventListener('DOMContentLoaded', init);
})();
