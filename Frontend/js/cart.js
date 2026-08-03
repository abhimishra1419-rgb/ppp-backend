/* ═══════════════════════════════════════════════
   cart.js  –  CartStore | Header | Footer | Smart Search
   ═══════════════════════════════════════════════ */

// ── CartStore ────────────────────────────────────────────────
const CartStore = (() => {
  const CART_KEY = 'ppp_cart';
  const listeners = [];

  const _load = () => {
    try { return JSON.parse(localStorage.getItem(CART_KEY) || '[]'); }
    catch { return []; }
  };

  const _save = (items) => {
    localStorage.setItem(CART_KEY, JSON.stringify(items));
    listeners.forEach(fn => fn(items));
    _refreshCount();
  };

  const _refreshCount = () => {
    document.querySelectorAll('.cart-count, #cartCount').forEach(el => {
      el.textContent = count();
    });
  };

  const getAll   = () => _load();
  const count    = () => _load().reduce((s, i) => s + i.qty, 0);
  const subtotal = () => _load().reduce((s, i) => s + i.price * i.qty, 0);

  const gst = () => {
    const rate = parseFloat((getCachedSettings() || {}).gst_rate || 18);
    return Math.round(subtotal() * rate / 100 * 100) / 100;
  };

  const shipping = () => {
    const cached = sessionStorage.getItem('ppp_shipping_info');
    if (cached) { try { return JSON.parse(cached).shipping || 0; } catch(e) {} }
    const s   = getCachedSettings() || {};
    const min = parseFloat(s.free_shipping_min != null ? s.free_shipping_min : 999);
    const def = parseFloat(s.default_shipping_charge != null ? s.default_shipping_charge : 80);
    return subtotal() >= min ? 0 : def;
  };

  const add = (product) => {
    const items = _load();
    const idx   = items.findIndex(i => i.id === product.id);
    if (idx !== -1) { items[idx].qty += 1; }
    else             { items.push({ ...product, qty: 1 }); }
    _save(items);
    showToast('Added to cart', 'success');
  };

  const remove   = (id)   => _save(_load().filter(i => i.id !== id));
  const clear    = ()     => { localStorage.removeItem(CART_KEY); listeners.forEach(fn => fn([])); _refreshCount(); };
  const onChange = (fn)   => { listeners.push(fn); };

  const setQty = (id, qty) => {
    if (qty < 1) { remove(id); return; }
    const items = _load();
    const idx   = items.findIndex(i => i.id === id);
    if (idx !== -1) { items[idx].qty = qty; _save(items); }
  };

  return { getAll, count, subtotal, gst, shipping, add, remove, setQty, clear, onChange };
})();

// ── Settings Cache (localStorage, 5-minute TTL) ──────────────
const _SKEY = 'ppp_settings_v2';
const _STTL = 5 * 60 * 1000;

function getCachedSettings() {
  try {
    const raw = localStorage.getItem(_SKEY);
    if (!raw) return null;
    const { s, t } = JSON.parse(raw);
    if (!s || Date.now() - t > _STTL) return null;
    return s;
  } catch { return null; }
}

function _saveToCache(s) {
  try { localStorage.setItem(_SKEY, JSON.stringify({ s, t: Date.now() })); }
  catch {}
}

// Called from adminsetting.html after admin saves settings
function clearSettingsCache() {
  localStorage.removeItem(_SKEY);
  sessionStorage.removeItem('ppp_shipping_info');
}

window.settings = getCachedSettings();

// Fetches fresh settings, updates cache and applies colors/text
async function loadSiteSettings() {
  const cached = getCachedSettings();
  try {
    const API = (typeof Auth !== 'undefined') ? Auth.API_BASE : 'https://ppp-backend-d4ox.onrender.com/api';
    const res  = await fetch(API + '/settings', { cache: 'no-store' });
    const ct   = res.headers.get('content-type') || '';
    if (!ct.includes('application/json')) return cached;
    const s = await res.json();
    _saveToCache(s);
    window.settings  = s;
    window._waNum    = s.whatsapp_number || '';
    return s;
  } catch { return cached; }
}

// Apply settings to page (colors + dynamic text elements)
function applySettings(s) {
  if (!s) return;
  const root = document.documentElement.style;
  if (s.color_primary)   root.setProperty('--blue-dark', s.color_primary);
  if (s.color_secondary) root.setProperty('--blue-mid',  s.color_secondary);
  if (s.color_accent)    root.setProperty('--teal',      s.color_accent);

  const wa = s.whatsapp_number || '';
  window._waNum = wa;

  const topbar = document.getElementById('topbarEl');
  if (topbar && s.announcement_bar) {
    topbar.innerHTML = s.announcement_bar +
      (wa ? ' &nbsp;|&nbsp; <a href="https://wa.me/91' + wa + '">WhatsApp: ' + wa + '</a>' : '');
  }

  const wb = document.getElementById('waBannerEl');
  if (wb && wa) {
    wb.innerHTML = (s.whatsapp_banner_text || 'For queries, contact us on WhatsApp') +
      ': <strong>' + wa + '</strong>' +
      ' &nbsp;|&nbsp; All prices exclusive of ' + (s.gst_rate || 18) + '% GST';
  }

  // Logo refresh
  const logoLink = document.getElementById('headerLogoLink');
  if (logoLink) logoLink.innerHTML = _buildLogoHtml(s);

  // Footer fields
  const byId = id => document.getElementById(id);
  const socWA = s.social_whatsapp || ('https://wa.me/91' + wa);
  if (byId('footerBrandName')) byId('footerBrandName').textContent = (s.site_name || 'PrinterSpareParts');
  if (byId('footerTagline'))   byId('footerTagline').textContent   = s.footer_tagline || '';
  if (byId('footerWa'))        { byId('footerWa').textContent = wa; byId('footerWa').href = socWA; }
  if (byId('footerEmail'))     { byId('footerEmail').textContent = s.footer_email || ''; byId('footerEmail').href = 'mailto:' + (s.footer_email || ''); }
  if (byId('footerAddr'))      byId('footerAddr').textContent = s.footer_address || '';
  if (byId('footerCopy'))      byId('footerCopy').textContent = s.footer_copyright || '';

  // Nav links refresh
  const navInner = document.querySelector('.nav-inner');
  if (navInner && s.nav_links) {
    try {
      const links = JSON.parse(s.nav_links);
      navInner.innerHTML = links.map(n =>
        '<a href="' + n.url + '">' + (n.icon ? n.icon + ' ' : '') + n.label + '</a>'
      ).join('');
    } catch(e) {}
  }

  const pt = document.getElementById('pageTitle');
  if (pt && s.site_name) pt.textContent = s.site_name + (s.tagline ? ' – ' + s.tagline : '');

  const md = document.getElementById('metaDesc');
  if (md && s.meta_description) md.content = s.meta_description;
}

// Runs synchronously on load — applies cached colors before first paint
;(function initSettings() {
  const cached = getCachedSettings();
  if (cached) {
    const r = document.documentElement.style;
    if (cached.color_primary)   r.setProperty('--blue-dark', cached.color_primary);
    if (cached.color_secondary) r.setProperty('--blue-mid',  cached.color_secondary);
    if (cached.color_accent)    r.setProperty('--teal',      cached.color_accent);
    window.settings = cached;
    window._waNum   = cached.whatsapp_number || '';
  }
  // Background refresh — does not block rendering
  const API = (typeof Auth !== 'undefined') ? Auth.API_BASE : 'https://ppp-backend-d4ox.onrender.com/api';
  fetch(API + '/settings', { cache: 'no-store' })
    .then(r => r.ok ? r.json() : null)
    .then(s => { if (s) { _saveToCache(s); applySettings(s); } })
    .catch(() => {});
}());

// ── Shipping API ──────────────────────────────────────────────
async function loadShipping() {
  try {
    const items = CartStore.getAll().map(i => ({ product_id: i.id, qty: i.qty }));
    if (!items.length) {
      sessionStorage.setItem('ppp_shipping_info', JSON.stringify({ shipping: 0, free: true }));
      return { shipping: 0, free: true, amount_for_free: 0 };
    }
    const API = (typeof Auth !== 'undefined') ? Auth.API_BASE : 'https://ppp-backend-d4ox.onrender.com/api';
    const res  = await fetch(API + '/shipping/calculate', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ items }),
    });
    if (!res.ok) return null;
    const ct = res.headers.get('content-type') || '';
    if (!ct.includes('application/json')) return null;
    const data = await res.json();
    sessionStorage.setItem('ppp_shipping_info', JSON.stringify(data));
    return data;
  } catch { return null; }
}

// ── Toast ─────────────────────────────────────────────────────
function showToast(msg, type) {
  let el = document.getElementById('toast');
  if (!el) { el = document.createElement('div'); el.id = 'toast'; document.body.appendChild(el); }
  el.textContent = msg;
  el.className   = type || '';
  el.classList.add('show');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 3200);
}

// ── Logo HTML builder ─────────────────────────────────────────
function _buildLogoHtml(s) {
  const API  = (typeof Auth !== 'undefined') ? Auth.API_BASE.replace('/api', '') : 'https://ppp-backend-d4ox.onrender.com';
  const name = (s && s.site_name) || 'PrinterSpareParts';
  const tag  = (s && s.tagline)   || '';

  if (s && s.logo_url) {
    const src = s.logo_url.startsWith('http') ? s.logo_url : API + s.logo_url;
    return '<div class="logo-circle" style="overflow:hidden;padding:0">' +
      '<img src="' + src + '" alt="' + name + '" style="width:100%;height:100%;object-fit:cover;border-radius:50%" onerror="this.style.display=\'none\'"/>' +
      '</div>' +
      '<div class="logo-text"><strong>' + name + '</strong>' + (tag ? '<span>' + tag + '</span>' : '') + '</div>';
  }

  const svgPath = 'M19 8H5c-1.66 0-3 1.34-3 3v6h4v4h12v-4h4v-6c0-1.66-1.34-3-3-3zm-3 11H8v-5h8v5zm3-7c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1zm-1-9H6v4h12V3z';
  return '<div class="logo-circle">' +
    '<svg viewBox="0 0 24 24" style="width:26px;height:26px;fill:var(--blue-dark)"><path d="' + svgPath + '"/></svg>' +
    '</div>' +
    '<div class="logo-text"><strong>' + name + '</strong>' + (tag ? '<span>' + tag + '</span>' : '') + '</div>';
}

// ── Render Header ─────────────────────────────────────────────
function renderHeader(activePage) {
  activePage = activePage || '';
  const s       = getCachedSettings() || {};
  const user    = (typeof Auth !== 'undefined') ? Auth.getUser() : null;
  const qty     = CartStore.count();
  const wa      = s.whatsapp_number  || '';
  const gstRate = s.gst_rate         || 18;
  const annoBar = s.announcement_bar || ('Free Shipping on orders above Rs.999 | All Prices Exclusive of ' + gstRate + '% GST');
  const waText  = s.whatsapp_banner_text || 'For queries, contact us on WhatsApp';

  let navLinks = [];
  try { navLinks = JSON.parse(s.nav_links || '[]'); } catch(e) {}
  if (!navLinks.length) navLinks = [
    { label: 'Home',         url: 'index.html'    },
    { label: 'Products',     url: 'products.html' },
    { label: 'Track Order',  url: 'track.html'    },
    { label: 'Contact',      url: 'contact.html'  },
  ];

  const navHtml = navLinks.map(n => {
    const active = activePage && n.url && n.url.includes(activePage);
    return '<a href="' + n.url + '"' + (active ? ' class="active"' : '') + '>' +
      (n.icon ? n.icon + ' ' : '') + n.label + '</a>';
  }).join('');

  const acctHref  = user ? (user.role === 'admin' ? 'admindashboard.html' : 'profile.html') : 'login.html';
  const acctLabel = user ? user.name.split(' ')[0] : 'Login';

  return [
    '<div class="topbar" id="topbarEl">',
      annoBar,
      wa ? ' &nbsp;|&nbsp; <a href="https://wa.me/91' + wa + '">WhatsApp: ' + wa + '</a>' : '',
    '</div>',
    '<header>',
      '<div class="header-inner">',
        '<button class="hamburger" onclick="document.getElementById(\'mainNav\').classList.toggle(\'open\')" aria-label="Menu">',
          '<span></span><span></span><span></span>',
        '</button>',
        '<a href="index.html" class="logo" id="headerLogoLink">', _buildLogoHtml(s), '</a>',
        '<div class="search-bar" style="position:relative;flex:1;max-width:520px">',
          '<input type="text" id="searchInput" placeholder="Search printer parts..."',
            ' autocomplete="off"',
            ' onfocus="openSuggest()"',
            ' oninput="handleSearchInput(this.value)"',
            ' onkeydown="handleSearchKey(event)"/>',
          '<button onclick="doSearch()">&#9906;</button>',
          '<div id="searchDropdown" style="display:none;position:absolute;top:calc(100% + 4px);left:0;right:0;',
            'background:#fff;border-radius:12px;box-shadow:0 8px 32px rgba(13,44,107,.18);z-index:999;',
            'max-height:480px;overflow-y:auto;border:1.5px solid #e0eaf8"></div>',
        '</div>',
        '<div class="header-actions">',
          '<a href="' + acctHref + '" id="headerAccount">&#128100; <span>' + acctLabel + '</span></a>',
          '<a href="cart.html" style="position:relative">&#128722; <span>Cart</span>',
            '<span class="cart-count" id="cartCount">' + qty + '</span>',
          '</a>',
        '</div>',
      '</div>',
    '</header>',
    '<nav id="mainNav"><div class="nav-inner">', navHtml, '</div></nav>',
    '<div class="whatsapp-banner" id="waBannerEl">',
      waText, ': <strong>', wa, '</strong>',
      ' &nbsp;|&nbsp; All prices exclusive of ', gstRate, '% GST',
    '</div>',
  ].join('');
}

// ── Render Footer ─────────────────────────────────────────────
function renderFooter() {
  const s     = getCachedSettings() || {};
  const wa    = s.whatsapp_number  || '';
  const email = s.footer_email     || '';
  const addr  = s.footer_address   || '';
  const tag   = s.footer_tagline   || 'Your trusted source for genuine printer spare parts across India.';
  const copy  = s.footer_copyright || '2025 PrinterSpareParts. All rights reserved.';
  const name  = s.site_name        || 'PrinterSpareParts';
  const socWA = s.social_whatsapp  || (wa ? 'https://wa.me/91' + wa : '');
  const socFB = s.social_facebook  || '';
  const socIG = s.social_instagram || '';
  const socYT = s.social_youtube   || '';

  const socialHtml = [
    socWA ? '<a href="' + socWA + '" target="_blank" style="width:36px;height:36px;background:#25D366;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:1.1rem;text-decoration:none">&#128172;</a>' : '',
    socFB ? '<a href="' + socFB + '" target="_blank" style="width:36px;height:36px;background:#1877F2;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:1.1rem;text-decoration:none">&#128216;</a>' : '',
    socIG ? '<a href="' + socIG + '" target="_blank" style="width:36px;height:36px;background:#E1306C;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:1.1rem;text-decoration:none">&#128248;</a>' : '',
    socYT ? '<a href="' + socYT + '" target="_blank" style="width:36px;height:36px;background:#FF0000;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:1.1rem;text-decoration:none">&#128250;</a>' : '',
  ].filter(Boolean).join('');

  const brandSection =
    '<div>' +
    '<h4 id="footerBrandName" style="color:#ffffff;font-size:1rem;font-weight:700;margin-bottom:14px">' + name + '</h4>' +
    '<p id="footerTagline" style="color:#c8d5ea;font-size:.88rem;line-height:1.7;margin-bottom:14px">' + tag + '</p>' +
    (wa ? '<div class="footer-contact-line">Phone / WhatsApp: <a id="footerWa" href="https://wa.me/91' + wa + '" style="color:#7dd3f0;text-decoration:none;font-weight:500">+91 ' + wa + '</a></div>' : '') +
    (email ? '<div class="footer-contact-line">Email: <a id="footerEmail" href="mailto:' + email + '" style="color:#7dd3f0;text-decoration:none;font-weight:500">' + email + '</a></div>' : '<div class="footer-contact-line">Email: <a id="footerEmail" href="#" style="color:#7dd3f0;text-decoration:none;font-weight:500"></a></div>') +
    (addr ? '<div class="footer-contact-line"><span id="footerAddr" style="color:#c8d5ea">' + addr + '</span></div>' : '<div class="footer-contact-line"><span id="footerAddr" style="color:#c8d5ea"></span></div>') +
    (socialHtml ? '<div style="display:flex;gap:10px;margin-top:14px">' + socialHtml + '</div>' : '') +
    '</div>';

  const catSection =
    '<div>' +
    '<h4 style="color:#ffffff;font-size:1rem;font-weight:700;margin-bottom:14px">Categories</h4>' +
    '<ul style="list-style:none">' +
    '<li style="margin-bottom:10px"><a href="products.html?cat=laser" style="color:#a8bcd8;text-decoration:none;font-size:.86rem">Laser Printer Parts</a></li>' +
    '<li style="margin-bottom:10px"><a href="products.html?cat=inkjet" style="color:#a8bcd8;text-decoration:none;font-size:.86rem">Inkjet Parts</a></li>' +
    '<li style="margin-bottom:10px"><a href="products.html?cat=toner" style="color:#a8bcd8;text-decoration:none;font-size:.86rem">Toner Spare Parts</a></li>' +
    '<li style="margin-bottom:10px"><a href="products.html?cat=thermal" style="color:#a8bcd8;text-decoration:none;font-size:.86rem">Thermal / POS Parts</a></li>' +
    '<li style="margin-bottom:10px"><a href="products.html?cat=dmp" style="color:#a8bcd8;text-decoration:none;font-size:.86rem">DMP Parts</a></li>' +
    '<li style="margin-bottom:10px"><a href="products.html?cat=drum" style="color:#a8bcd8;text-decoration:none;font-size:.86rem">Drum Units</a></li>' +
    '</ul></div>';

  const quickSection =
    '<div>' +
    '<h4 style="color:#ffffff;font-size:1rem;font-weight:700;margin-bottom:14px">Quick Links</h4>' +
    '<ul style="list-style:none">' +
    '<li style="margin-bottom:10px"><a href="index.html" style="color:#a8bcd8;text-decoration:none;font-size:.86rem">Home</a></li>' +
    '<li style="margin-bottom:10px"><a href="products.html" style="color:#a8bcd8;text-decoration:none;font-size:.86rem">All Products</a></li>' +
    '<li style="margin-bottom:10px"><a href="track.html" style="color:#a8bcd8;text-decoration:none;font-size:.86rem">Track Order</a></li>' +
    '<li style="margin-bottom:10px"><a href="contact.html" style="color:#a8bcd8;text-decoration:none;font-size:.86rem">Contact Us</a></li>' +
    '<li style="margin-bottom:10px"><a href="profile.html" style="color:#a8bcd8;text-decoration:none;font-size:.86rem">My Account</a></li>' +
    '</ul></div>';

  const supportSection =
    '<div>' +
    '<h4 style="color:#ffffff;font-size:1rem;font-weight:700;margin-bottom:14px">Support</h4>' +
    '<ul style="list-style:none">' +
    '<li style="margin-bottom:10px"><a href="contact.html" style="color:#a8bcd8;text-decoration:none;font-size:.86rem">Help Center</a></li>' +
    '<li style="margin-bottom:10px"><a href="contact.html" style="color:#a8bcd8;text-decoration:none;font-size:.86rem">Return Policy</a></li>' +
    '<li style="margin-bottom:10px"><a href="contact.html" style="color:#a8bcd8;text-decoration:none;font-size:.86rem">Shipping Info</a></li>' +
    '<li style="margin-bottom:10px"><a href="contact.html" style="color:#a8bcd8;text-decoration:none;font-size:.86rem">Wholesale Enquiry</a></li>' +
    (wa ? '<li style="margin-bottom:10px"><a href="https://wa.me/91' + wa + '" style="color:#a8bcd8;text-decoration:none;font-size:.86rem">WhatsApp Support</a></li>' : '') +
    '</ul></div>';

  return '<footer>' +
    '<div class="footer-grid">' + brandSection + catSection + quickSection + supportSection + '</div>' +
    '<div class="footer-bottom">&#169; <span id="footerCopy" style="color:#7dd3f0;font-weight:600">' + copy + '</span></div>' +
    '</footer>' +
    '<div id="toast"></div>';
}

// ── Init cart count on DOM ready ──────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.cart-count, #cartCount').forEach(el => {
    el.textContent = CartStore.count();
  });
});

// ════════════════════════════════════════════════════════════════
//   SMART SEARCH — suggestions, trending, recent
// ════════════════════════════════════════════════════════════════

var _searchTimer = null;
var _focusIdx    = -1;

function doSearch(q) {
  var query = q || (document.getElementById('searchInput') ? document.getElementById('searchInput').value.trim() : '');
  if (!query) return;
  closeSuggest();
  var API = (typeof Auth !== 'undefined') ? Auth.API_BASE : 'https://ppp-backend-d4ox.onrender.com/api';
  fetch(API + '/search/track', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: query })
  }).catch(function() {});
  saveRecentSearch(query);
  window.location.href = 'products.html?search=' + encodeURIComponent(query);
}

function goToProduct(id) {
  closeSuggest();
  window.location.href = 'productdetails.html?id=' + id;
}

function goToCategory(slug) {
  closeSuggest();
  window.location.href = 'products.html?cat=' + slug;
}

// ── Recent searches ───────────────────────────────────────────
function saveRecentSearch(q) {
  try {
    var recent = JSON.parse(localStorage.getItem('ppp_recent_searches') || '[]');
    recent = [q].concat(recent.filter(function(r) { return r.toLowerCase() !== q.toLowerCase(); })).slice(0, 8);
    localStorage.setItem('ppp_recent_searches', JSON.stringify(recent));
  } catch(e) {}
}

function getRecentSearches() {
  try { return JSON.parse(localStorage.getItem('ppp_recent_searches') || '[]'); }
  catch(e) { return []; }
}

function clearRecentSearches() {
  localStorage.removeItem('ppp_recent_searches');
  openSuggest();
}

// ── Keyboard handling ─────────────────────────────────────────
function handleSearchInput(val) {
  clearTimeout(_searchTimer);
  _focusIdx = -1;
  if (!val || !val.trim()) { openSuggest(); return; }
  _searchTimer = setTimeout(function() { fetchSuggestions(val.trim()); }, 220);
}

function handleSearchKey(e) {
  var dd = document.getElementById('searchDropdown');
  if (!dd || dd.style.display === 'none') {
    if (e.key === 'Enter') doSearch();
    return;
  }
  var items = dd.querySelectorAll('.ss-item');
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    _focusIdx = Math.min(_focusIdx + 1, items.length - 1);
    items.forEach(function(el, i) { el.classList.toggle('ss-focus', i === _focusIdx); });
    if (items[_focusIdx] && items[_focusIdx].dataset.query) {
      document.getElementById('searchInput').value = items[_focusIdx].dataset.query;
    }
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    _focusIdx = Math.max(_focusIdx - 1, 0);
    items.forEach(function(el, i) { el.classList.toggle('ss-focus', i === _focusIdx); });
    if (items[_focusIdx] && items[_focusIdx].dataset.query) {
      document.getElementById('searchInput').value = items[_focusIdx].dataset.query;
    }
  } else if (e.key === 'Enter') {
    if (_focusIdx >= 0 && items[_focusIdx]) {
      var pid = items[_focusIdx].dataset.pid;
      if (pid) goToProduct(pid);
      else doSearch(items[_focusIdx].dataset.query);
    } else {
      doSearch();
    }
  } else if (e.key === 'Escape') {
    closeSuggest();
  }
}

// ── Fetch suggestions from API ────────────────────────────────
async function fetchSuggestions(q) {
  var API = (typeof Auth !== 'undefined') ? Auth.API_BASE : 'https://ppp-backend-d4ox.onrender.com/api';
  try {
    var res = await fetch(API + '/search/suggestions?q=' + encodeURIComponent(q), { cache: 'no-store' });
    var ct  = res.headers.get('content-type') || '';
    if (!ct.includes('application/json')) { renderNoResults(q); return; }
    var data = await res.json();
    renderSuggestions(q, data);
  } catch(e) { renderNoResults(q); }
}

// ── Open dropdown (trending + recent when bar is focused) ─────
async function openSuggest() {
  var dd  = document.getElementById('searchDropdown');
  if (!dd) return;
  var val = (document.getElementById('searchInput') ? document.getElementById('searchInput').value : '').trim();
  if (val.length >= 2) { await fetchSuggestions(val); return; }

  var API    = (typeof Auth !== 'undefined') ? Auth.API_BASE : 'https://ppp-backend-d4ox.onrender.com/api';
  var recent = getRecentSearches();
  var parts  = [];

  if (recent.length) {
    parts.push(ssLabel('Recent Searches', true));
    recent.forEach(function(r) { parts.push(ssSearchRow(r, '&#128336;')); });
    parts.push(ssDivider());
  }

  try {
    var res = await fetch(API + '/search/suggestions', { cache: 'no-store' });
    var ct  = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      var data = await res.json();
      if (data.trending && data.trending.length) {
        parts.push(ssLabel('Trending Searches', false));
        data.trending.slice(0, 6).forEach(function(t) { parts.push(ssSearchRow(t, '&#128293;')); });
        parts.push(ssDivider());
      }
      if (data.popular && data.popular.length) {
        parts.push(ssLabel('Popular Products', false));
        data.popular.forEach(function(p) { parts.push(ssProductRow(p)); });
      }
    }
  } catch(e) {}

  dd.innerHTML = '<div style="padding:6px 0">' + parts.join('') + '</div>';
  dd.style.display = 'block';
}

// ── Render suggestions ────────────────────────────────────────
function renderSuggestions(q, data) {
  var dd = document.getElementById('searchDropdown');
  if (!dd) return;
  if (!data || (!data.products.length && !data.categories.length && !data.related.length)) {
    renderNoResults(q); return;
  }
  var parts = [];
  if (data.categories && data.categories.length) {
    parts.push(ssLabel('Categories', false));
    data.categories.forEach(function(c) { parts.push(ssCategoryRow(c)); });
    parts.push(ssDivider());
  }
  if (data.products && data.products.length) {
    parts.push(ssLabel('Products', false));
    data.products.forEach(function(p) { parts.push(ssProductRow(p)); });
    parts.push(ssDivider());
  }
  if (data.related && data.related.length) {
    parts.push(ssLabel('Related Searches', false));
    data.related.slice(0, 4).forEach(function(r) { parts.push(ssSearchRow(r, '&#128269;')); });
    parts.push(ssDivider());
  }
  parts.push(ssViewAll(q));
  dd.innerHTML = '<div style="padding:6px 0">' + parts.join('') + '</div>';
  dd.style.display = 'block';
}

function renderNoResults(q) {
  var dd = document.getElementById('searchDropdown');
  if (!dd) return;
  var recent = getRecentSearches();
  var parts  = [];
  if (recent.length) {
    parts.push(ssLabel('Recent Searches', false));
    recent.slice(0, 4).forEach(function(r) { parts.push(ssSearchRow(r, '&#128336;')); });
    parts.push(ssDivider());
  }
  parts.push('<div style="padding:12px 14px;font-size:.85rem;color:#8899bb;text-align:center">No results for <strong style="color:#1a2540">' + escHtml(q) + '</strong></div>');
  parts.push(ssViewAll(q));
  dd.innerHTML = '<div style="padding:6px 0">' + parts.join('') + '</div>';
  dd.style.display = 'block';
}

// ── Suggestion row builders ───────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function ssLabel(text, withClear) {
  var clear = withClear
    ? '<button onclick="clearRecentSearches()" style="background:none;border:none;color:#e53e3e;font-size:.72rem;cursor:pointer;padding:0;font-family:inherit">Clear all</button>'
    : '';
  return '<div style="padding:8px 14px 4px;font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:#8899bb;font-weight:600;display:flex;justify-content:space-between;align-items:center">' + text + clear + '</div>';
}

function ssDivider() {
  return '<div style="border-top:1px solid #edf2f7;margin:4px 0"></div>';
}

function ssSearchRow(query, icon) {
  var safe = escHtml(query);
  return '<div class="ss-item" data-query="' + safe + '"' +
    ' onclick="doSearch(this.dataset.query)"' +
    ' style="display:flex;align-items:center;gap:10px;padding:9px 14px;cursor:pointer"' +
    ' onmouseenter="this.style.background=\'#f0f4fb\'" onmouseleave="this.style.background=\'\'">' +
    '<span style="font-size:.95rem;color:#8899bb">' + icon + '</span>' +
    '<span style="font-size:.85rem;color:#1a2540">' + safe + '</span>' +
    '<span style="margin-left:auto;font-size:.75rem;color:#aab">&#8599;</span>' +
    '</div>';
}

function ssCategoryRow(c) {
  return '<div class="ss-item" data-query="' + escHtml(c.name) + '"' +
    ' onclick="goToCategory(\'' + escHtml(c.slug) + '\')"' +
    ' style="display:flex;align-items:center;gap:10px;padding:8px 14px;cursor:pointer"' +
    ' onmouseenter="this.style.background=\'#f0f4fb\'" onmouseleave="this.style.background=\'\'">' +
    '<span style="font-size:.9rem">&#128193;</span>' +
    '<span style="font-size:.85rem;color:#1a2540">' + escHtml(c.name) + '</span>' +
    '<span style="margin-left:auto;font-size:.72rem;color:#aab;background:#f0f4fb;padding:2px 8px;border-radius:10px">Category</span>' +
    '</div>';
}

function ssProductRow(p) {
  var img = p.image_url
    ? '<img src="' + escHtml(p.image_url) + '" style="width:100%;height:100%;object-fit:contain" onerror="this.parentNode.innerHTML=\'&#128424;\'">'
    : '&#128424;';
  var savePct = (p.old_price && p.old_price > p.price)
    ? Math.round((p.old_price - p.price) / p.old_price * 100) + '% off'
    : '';
  return '<div class="ss-item" data-pid="' + p.id + '"' +
    ' onclick="goToProduct(' + p.id + ')"' +
    ' style="display:flex;align-items:center;gap:12px;padding:8px 14px;cursor:pointer"' +
    ' onmouseenter="this.style.background=\'#f0f4fb\'" onmouseleave="this.style.background=\'\'">' +
    '<div style="width:44px;height:44px;background:#f0f4fb;border-radius:8px;flex-shrink:0;display:flex;align-items:center;justify-content:center;overflow:hidden;font-size:1.2rem">' + img + '</div>' +
    '<div style="flex:1;min-width:0">' +
      '<div style="font-size:.83rem;font-weight:600;color:#1a2540;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + escHtml(p.name) + '</div>' +
      '<div style="font-size:.75rem;color:#8899bb;margin-top:1px">' + escHtml(p.category || '') + '</div>' +
    '</div>' +
    '<div style="text-align:right;flex-shrink:0">' +
      '<div style="font-size:.85rem;font-weight:700;color:#e53e3e">Rs.' + p.price.toLocaleString('en-IN') + '</div>' +
      (savePct ? '<div style="font-size:.7rem;color:#22c55e;font-weight:600">' + savePct + '</div>' : '') +
    '</div>' +
    '</div>';
}

function ssViewAll(q) {
  return '<div onclick="doSearch(\'' + escHtml(q) + '\')"' +
    ' style="padding:10px 14px;cursor:pointer;font-size:.85rem;color:#1a4298;font-weight:600;display:flex;align-items:center;gap:8px"' +
    ' onmouseenter="this.style.background=\'#e8f0fe\'" onmouseleave="this.style.background=\'\'">' +
    '&#128269; See all results for <strong style="margin-left:4px">' + escHtml(q) + '</strong>' +
    '</div>';
}

// ── Close dropdown ────────────────────────────────────────────
function closeSuggest() {
  var dd = document.getElementById('searchDropdown');
  if (dd) dd.style.display = 'none';
  _focusIdx = -1;
}

// Close when clicking outside the search bar
document.addEventListener('click', function(e) {
  if (!e.target.closest || !e.target.closest('.search-bar')) closeSuggest();
});

// Focus highlight style for keyboard navigation
;(function() {
  var style = document.createElement('style');
  style.textContent = '.ss-item.ss-focus { background: #f0f4fb !important; }';
  document.head.appendChild(style);
}());