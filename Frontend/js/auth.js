/* ═══════════════════════════════════════════════
   auth.js  –  AuthContext (Vanilla JS)
   ═══════════════════════════════════════════════ */

const API_BASE = 'https://ppp-backend-d4ox.onrender.com/api';

const Auth = (() => {

  const getToken     = () => localStorage.getItem('ppp_token');
  const getUser      = () => JSON.parse(localStorage.getItem('ppp_user') || 'null');
  const setSession   = (token, user) => {
    localStorage.setItem('ppp_token', token);
    localStorage.setItem('ppp_user', JSON.stringify(user));
    updateHeaderUI();
  };
  const clearSession = () => {
    localStorage.removeItem('ppp_token');
    localStorage.removeItem('ppp_user');
    updateHeaderUI();
  };

  const isLoggedIn = () => !!getToken();
  const isAdmin    = () => getUser()?.role === 'admin';

  // Keep retrying every 3 seconds until backend responds with JSON
  // Render free plan takes up to 50 seconds to wake from sleep
  const wakeUp = async (onAttempt) => {
    const maxAttempts = 20;
    for (let i = 0; i < maxAttempts; i++) {
      try {
        if (onAttempt) onAttempt(i + 1, maxAttempts);
        const res = await fetch(API_BASE + '/categories', {
          method: 'GET',
          cache: 'no-store',
        });
        const ct = res.headers.get('content-type') || '';
        if (ct.includes('application/json') && res.ok) {
          return true;
        }
      } catch(e) {
        // still sleeping, keep trying
      }
      await new Promise(r => setTimeout(r, 3000));
    }
    return false;
  };

  const safeJson = async (res) => {
    const ct   = res.headers.get('content-type') || '';
    const text = await res.text();
    if (!ct.includes('application/json') || text.trim().startsWith('<')) {
      if (res.status === 401) {
        clearSession();
        window.location.href = 'login.html';
        throw new Error('Session expired. Please login again.');
      }
      throw new Error('Server was sleeping. It is now awake! Please click Save again.');
    }
    try {
      return JSON.parse(text);
    } catch(e) {
      throw new Error('Server was sleeping. It is now awake! Please click Save again.');
    }
  };

  const authFetch = async (url, options = {}) => {
    const token   = getToken();
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    if (options.body instanceof FormData) delete headers['Content-Type'];
    const res = await fetch(API_BASE + url, { ...options, headers });
    if (res.status === 401) { clearSession(); window.location.href = 'login.html'; }
    return res;
  };

  const register = async (name, email, phone, password) => {
    await wakeUp();
    const res  = await fetch(API_BASE + '/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, phone, password }),
    });
    const data = await safeJson(res);
    if (!res.ok) throw new Error(data.error || 'Registration failed');
    setSession(data.token, { name, email, role: 'customer' });
    return data;
  };

  const login = async (email, password) => {
    await wakeUp();
    const res  = await fetch(API_BASE + '/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await safeJson(res);
    if (!res.ok) throw new Error(data.error || 'Login failed');
    setSession(data.token, data.user);
    return data;
  };

  const logout = () => {
    clearSession();
    window.location.href = 'login.html';
  };

  const requireAuth = () => {
    if (!isLoggedIn()) {
      window.location.href = 'login.html?redirect=' + encodeURIComponent(window.location.href);
    }
  };

  const requireAdmin = () => {
    requireAuth();
    if (!isAdmin()) window.location.href = 'index.html';
  };

  const updateHeaderUI = () => {
    const user   = getUser();
    const acctEl = document.getElementById('headerAccount');
    const cartEl = document.getElementById('cartCount');
    if (acctEl) {
      if (user) {
        acctEl.innerHTML = `👤 <span>${user.name.split(' ')[0]}</span>`;
        acctEl.href = isAdmin() ? 'admindashboard.html' : 'profile.html';
      } else {
        acctEl.innerHTML = `👤 <span>Login</span>`;
        acctEl.href = 'login.html';
      }
    }
    if (cartEl && typeof CartStore !== 'undefined') {
      cartEl.textContent = CartStore.count();
    }
  };

  return {
    getToken, getUser, isLoggedIn, isAdmin,
    authFetch, safeJson, wakeUp,
    register, login, logout,
    requireAuth, requireAdmin,
    updateHeaderUI, API_BASE
  };
})();

document.addEventListener('DOMContentLoaded', Auth.updateHeaderUI);