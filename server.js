// ════════════════════════════════════════════════════════════════
//   PrinterPartsPoint – Production Backend
//   Security: Helmet, Rate Limiting, Input Validation
//   Payments: Razorpay (UPI/Card/NetBanking/Wallets)
//   Emails:   Nodemailer (Order confirmation, status updates)
//   Orders:   Cancel, Return, Full tracking timeline
// ════════════════════════════════════════════════════════════════

const express     = require('express');
const bcrypt      = require('bcryptjs');
const jwt         = require('jsonwebtoken');
const cors        = require('cors');
const multer      = require('multer');
const path        = require('path');
const fs          = require('fs');
const crypto      = require('crypto');
const helmet      = require('helmet');
const rateLimit   = require('express-rate-limit');
const nodemailer  = require('nodemailer');
const Razorpay    = require('razorpay');

const app     = express();
const PORT    = process.env.PORT    || 5000;
const JWT_SECRET   = process.env.JWT_SECRET    || 'printerpartspoint_secret_change_in_production';
const BASE_URL     = process.env.BASE_URL      || ('http://localhost:' + PORT);
const DB_FILE      = path.join(__dirname, 'database.json');

// Razorpay
const RAZORPAY_KEY_ID     = process.env.RAZORPAY_KEY_ID     || '';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || '';
let razorpay = null;
try {
  if (RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET) {
    razorpay = new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET });
    console.log('✅ Razorpay configured');
  } else { console.log('⚠️  Razorpay not configured — add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET'); }
} catch(e) { console.log('⚠️  Razorpay init failed:', e.message); }

// Email (Nodemailer)
const EMAIL_USER = process.env.EMAIL_USER || '';
const EMAIL_PASS = process.env.EMAIL_PASS || '';
const EMAIL_FROM = process.env.EMAIL_FROM || 'PrinterPartsPoint <noreply@printerpartspoint.in>';
let transporter = null;
try {
  if (EMAIL_USER && EMAIL_PASS) {
    transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: EMAIL_USER, pass: EMAIL_PASS },
    });
    console.log('✅ Email configured');
  } else { console.log('⚠️  Email not configured — add EMAIL_USER and EMAIL_PASS in Render environment'); }
} catch(e) { console.log('⚠️  Email init failed:', e.message); }

// ── SECURITY MIDDLEWARE ──────────────────────────────────────
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: false,
}));
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'] }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Rate limiting — prevents brute force attacks
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // max 20 login attempts per 15 min per IP
  message: { error: 'Too many attempts. Please try again after 15 minutes.' },
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute per IP
  message: { error: 'Too many requests. Please slow down.' },
});
app.use('/api/auth', authLimiter);
app.use('/api', apiLimiter);

// ── FILE UPLOAD ──────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads', 'products');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1e9) + ext);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg','.jpeg','.png','.webp','.gif'];
    allowed.includes(path.extname(file.originalname).toLowerCase()) ? cb(null,true) : cb(new Error('Only image files allowed'));
  },
});

// ── DB HELPERS ───────────────────────────────────────────────
const readDB  = () => JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
const writeDB = data => fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
const nextId  = arr  => arr.length ? Math.max(...arr.map(r => r.id)) + 1 : 1;

// Input sanitizer — prevent XSS
const sanitize = str => typeof str === 'string' ? str.replace(/[<>]/g, '').trim() : str;

// ── DATABASE SETUP ───────────────────────────────────────────
function setupDatabase() {
  if (fs.existsSync(DB_FILE)) { console.log('✅ database.json loaded'); return; }
  const adminHash = bcrypt.hashSync('Admin@1234', 12);
  const db = {
    settings: {
      site_name:'PrinterPartsPoint', tagline:"India's #1 Printer Spare Parts Store",
      hero_title:"India's #1 Source for Printer Spare Parts",
      hero_subtitle:'Genuine & compatible parts for HP, Canon, Epson, Ricoh, Brother printers.',
      hero_btn_primary:'Shop Now', hero_btn_secondary:'New Arrivals',
      announcement_bar:'Free Shipping on orders above Rs.999 | All Prices Exclusive of 18% GST',
      whatsapp_number:'9990774445', whatsapp_banner_text:'For any queries contact us on WhatsApp',
      gst_rate:18, free_shipping_min:999,
      show_new_arrivals:true, show_best_sellers:true, show_categories:true,
      footer_address:'Karol Bagh, New Delhi - 110005',
      footer_email:'support@printerpartspoint.in',
      working_hours:'Mon-Sat: 10:00 AM - 7:00 PM',
      cancel_window_hours: 24, // customers can cancel within 24 hours
      return_window_days:  7,  // customers can request return within 7 days
      meta_title:'PrinterPartsPoint - Printer Spare Parts India',
      meta_description:'Buy genuine printer spare parts online in India.',
    },
    users:        [{ id:1, name:'Admin', email:'admin@printerpartspoint.in', phone:'9990774445', password:adminHash, role:'admin', addresses:[], created_at:new Date().toISOString() }],
    categories:   [
      { id:1, name:'Laser Printer Parts',      slug:'laser',    sort_order:1 },
      { id:2, name:'DMP Printer Parts',         slug:'dmp',      sort_order:2 },
      { id:3, name:'Inkjet Printer Parts',      slug:'inkjet',   sort_order:3 },
      { id:4, name:'Scanner Parts',             slug:'scanner',  sort_order:4 },
      { id:5, name:'Thermal/POS Printer Parts', slug:'thermal',  sort_order:5 },
      { id:6, name:'Toner Spare Parts',         slug:'toner',    sort_order:6 },
      { id:7, name:'Complete Printer',          slug:'complete', sort_order:7 },
      { id:8, name:'Drum Units',                slug:'drum',     sort_order:8 },
    ],
    products:     [],
    orders:       [],
    order_items:  [],
    order_events: [], // full timeline of all status changes
    reviews:      [], // product reviews
    enquiries:    [],
    wishlists:    [],
    payment_logs: [],
  };
  writeDB(db);
  console.log('✅ database.json created');
  console.log('🔑 Admin: admin@printerpartspoint.in / Admin@1234');
}
setupDatabase();

// ── AUTH MIDDLEWARE ──────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Please login to continue' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Session expired. Please login again.' }); }
}
function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    next();
  });
}

// ── EMAIL HELPER ─────────────────────────────────────────────
async function sendEmail(to, subject, html) {
  if (!transporter) return; // silently skip if email not configured
  try {
    await transporter.sendMail({ from: EMAIL_FROM, to, subject, html });
    console.log('📧 Email sent to:', to);
  } catch(e) { console.log('📧 Email failed:', e.message); }
}

function orderConfirmationEmail(order, user, items) {
  const itemRows = items.map(i =>
    `<tr><td style="padding:8px;border-bottom:1px solid #eee">${i.name}</td>
     <td style="padding:8px;border-bottom:1px solid #eee;text-align:center">${i.qty}</td>
     <td style="padding:8px;border-bottom:1px solid #eee;text-align:right">Rs.${(i.price*i.qty).toLocaleString('en-IN')}</td></tr>`
  ).join('');
  let addr = {};
  try { addr = JSON.parse(order.shipping_address); } catch(e) {}
  return `
  <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
    <div style="background:#1a4298;color:#fff;padding:24px;text-align:center">
      <h1 style="margin:0;font-size:24px">PrinterPartsPoint</h1>
      <p style="margin:8px 0 0;opacity:.8">Order Confirmation</p>
    </div>
    <div style="padding:24px;background:#f5f8ff">
      <div style="background:#fff;border-radius:12px;padding:24px;margin-bottom:16px">
        <h2 style="color:#0d2c6b;margin:0 0 16px">Hello ${user.name},</h2>
        <p style="color:#555">Your order has been ${order.payment_status==='paid'?'<strong style="color:#22c55e">confirmed</strong>':'placed and is pending confirmation'}.</p>
        <div style="background:#f0f4fb;border-radius:8px;padding:16px;margin:16px 0">
          <strong>Order Number: ${order.order_number}</strong><br/>
          <span style="color:#777;font-size:14px">Date: ${new Date(order.created_at).toLocaleDateString('en-IN',{day:'numeric',month:'long',year:'numeric'})}</span>
        </div>
        <table style="width:100%;border-collapse:collapse">
          <thead><tr style="background:#0d2c6b;color:#fff">
            <th style="padding:10px;text-align:left">Item</th>
            <th style="padding:10px;text-align:center">Qty</th>
            <th style="padding:10px;text-align:right">Price</th>
          </tr></thead>
          <tbody>${itemRows}</tbody>
          <tfoot>
            <tr><td colspan="2" style="padding:8px;text-align:right;color:#777">Subtotal (excl. GST)</td><td style="padding:8px;text-align:right">Rs.${order.subtotal.toLocaleString('en-IN',{minimumFractionDigits:2})}</td></tr>
            <tr><td colspan="2" style="padding:8px;text-align:right;color:#777">GST @18%</td><td style="padding:8px;text-align:right">Rs.${order.gst.toLocaleString('en-IN',{minimumFractionDigits:2})}</td></tr>
            <tr><td colspan="2" style="padding:8px;text-align:right;font-weight:bold">Total</td><td style="padding:8px;text-align:right;font-weight:bold;color:#e53e3e">Rs.${order.total.toLocaleString('en-IN',{minimumFractionDigits:2})}</td></tr>
          </tfoot>
        </table>
      </div>
      <div style="background:#fff;border-radius:12px;padding:16px;margin-bottom:16px">
        <h3 style="margin:0 0 8px;color:#0d2c6b">Shipping Address</h3>
        <p style="margin:0;color:#555">${addr.name} | ${addr.phone}<br/>${addr.line}, ${addr.city}, ${addr.state} – ${addr.pin}</p>
      </div>
      <div style="background:#fff;border-radius:12px;padding:16px;margin-bottom:16px">
        <h3 style="margin:0 0 8px;color:#0d2c6b">Payment</h3>
        <p style="margin:0;color:#555">${order.payment_method==='cod'?'Cash on Delivery — pay when your order arrives':'Online Payment — Rs.'+order.total.toLocaleString('en-IN')+' received'}</p>
      </div>
      <p style="text-align:center;color:#777;font-size:13px">For queries: WhatsApp us at +91 9990774445<br/>or email support@printerpartspoint.in</p>
    </div>
  </div>`;
}

function orderStatusEmail(order, user, newStatus, trackingNumber) {
  const statusMsg = {
    confirmed:  { emoji:'✅', msg:'Your order has been confirmed and is being prepared.' },
    processing: { emoji:'⚙️', msg:'Your order is being processed and packed.' },
    shipped:    { emoji:'🚚', msg:'Your order has been shipped!' + (trackingNumber?` Tracking: <strong>${trackingNumber}</strong>`:'') },
    delivered:  { emoji:'🎉', msg:'Your order has been delivered. Thank you for shopping with us!' },
    cancelled:  { emoji:'❌', msg:'Your order has been cancelled.' },
  };
  const s = statusMsg[newStatus] || { emoji:'📦', msg:'Your order status has been updated.' };
  return `
  <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
    <div style="background:#1a4298;color:#fff;padding:24px;text-align:center">
      <h1 style="margin:0;font-size:24px">PrinterPartsPoint</h1>
    </div>
    <div style="padding:24px;background:#f5f8ff">
      <div style="background:#fff;border-radius:12px;padding:24px">
        <h2 style="color:#0d2c6b">${s.emoji} Order Update</h2>
        <p>Hello ${user.name},</p>
        <p>${s.msg}</p>
        <div style="background:#f0f4fb;border-radius:8px;padding:16px">
          <strong>Order: ${order.order_number}</strong><br/>
          <strong>Status: ${newStatus.toUpperCase()}</strong>
        </div>
        <p style="margin-top:16px;color:#777;font-size:13px">Track your order at: <a href="${BASE_URL.replace(':5000','')}track.html?order=${order.order_number}">Track Order</a></p>
      </div>
    </div>
  </div>`;
}

// ── ORDER EVENT LOGGER (full timeline) ───────────────────────
function logOrderEvent(db, orderId, status, note, actorRole) {
  db.order_events = db.order_events || [];
  db.order_events.push({
    id:        nextId(db.order_events),
    order_id:  orderId,
    status,
    note:      note || '',
    actor:     actorRole || 'system',
    created_at:new Date().toISOString(),
  });
}

// ════════════════════════════════════════════════════════════════
//   SETTINGS
// ════════════════════════════════════════════════════════════════
app.get('/api/settings', (req, res) => res.json(readDB().settings));
app.put('/api/settings', adminMiddleware, (req, res) => {
  const db = readDB();
  db.settings = { ...db.settings, ...req.body };
  writeDB(db);
  res.json({ message:'Settings saved', settings:db.settings });
});

// ════════════════════════════════════════════════════════════════
//   AUTH
// ════════════════════════════════════════════════════════════════
app.post('/api/auth/register', async (req, res) => {
  try {
    const name     = sanitize(req.body.name);
    const email    = sanitize(req.body.email)?.toLowerCase();
    const phone    = sanitize(req.body.phone);
    const password = req.body.password;
    if (!name || !email || !password) return res.status(400).json({ error:'Name, email and password are required' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error:'Invalid email address' });
    if (password.length < 8) return res.status(400).json({ error:'Password must be at least 8 characters' });
    if (phone && !/^\d{10}$/.test(phone)) return res.status(400).json({ error:'Phone must be 10 digits' });
    const db = readDB();
    if (db.users.find(u => u.email === email)) return res.status(409).json({ error:'This email is already registered. Please login.' });
    const user = { id:nextId(db.users), name, email, phone:phone||null, password:bcrypt.hashSync(password,12), role:'customer', addresses:[], created_at:new Date().toISOString() };
    db.users.push(user); writeDB(db);
    const token = jwt.sign({ id:user.id, email, role:'customer' }, JWT_SECRET, { expiresIn:'30d' });
    // Send welcome email
    sendEmail(email, 'Welcome to PrinterPartsPoint!',
      `<div style="font-family:Arial,sans-serif;padding:24px;max-width:500px;margin:auto">
        <h2 style="color:#1a4298">Welcome, ${name}! 🎉</h2>
        <p>Your account has been created successfully on PrinterPartsPoint.</p>
        <p>You can now shop for genuine printer spare parts delivered across India.</p>
        <p style="color:#777;font-size:13px">For queries: WhatsApp +91 9990774445</p>
      </div>`
    );
    res.json({ message:'Account created successfully', token, user:{ id:user.id, name, email, role:'customer' } });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error. Please try again.' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email    = sanitize(req.body.email)?.toLowerCase();
    const password = req.body.password;
    if (!email || !password) return res.status(400).json({ error:'Email and password are required' });
    const db   = readDB();
    const user = db.users.find(u => u.email === email);
    if (!user) return res.status(401).json({ error:'No account found with this email. Please register first.' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error:'Incorrect password. Please try again.' });
    const token = jwt.sign({ id:user.id, email:user.email, role:user.role }, JWT_SECRET, { expiresIn:'30d' });
    res.json({ token, user:{ id:user.id, name:user.name, email:user.email, role:user.role } });
  } catch(e) { res.status(500).json({ error:'Server error. Please try again.' }); }
});
// ════════════════════════════════════════════════════════════════
//   FORGOT PASSWORD — OTP via Email
// ════════════════════════════════════════════════════════════════

// In-memory OTP store (resets on server restart — fine for Render)
const otpStore = new Map(); // key: email, value: { otp, expires, name }

// STEP 1: Request OTP — user enters email or phone
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const input = sanitize(req.body.email_or_phone || '').toLowerCase().trim();
    if (!input) return res.status(400).json({ error: 'Please enter your email address or phone number' });
    const db   = readDB();
    // Find user by email or phone
    const user = db.users.find(u =>
      u.email === input ||
      u.email === input.toLowerCase() ||
      (u.phone && u.phone === input.replace(/\D/g,'').slice(-10))
    );
    if (!user) {
      // Don't reveal if email exists — security best practice
      return res.json({ message: 'If this account exists, an OTP has been sent to the registered email.' });
    }
    if (!user.email) {
      return res.status(400).json({ error: 'No email address linked to this account. Please contact support on WhatsApp.' });
    }
    // Generate 6-digit OTP
    const otp     = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + 10 * 60 * 1000; // 10 minutes
    otpStore.set(user.email, { otp, expires, userId: user.id, name: user.name });
    // Send OTP email
    const emailHtml = `
    <div style="font-family:Arial,sans-serif;max-width:500px;margin:auto">
      <div style="background:#1a4298;color:#fff;padding:24px;text-align:center;border-radius:12px 12px 0 0">
        <h2 style="margin:0;font-size:22px">PrinterPartsPoint</h2>
        <p style="margin:6px 0 0;opacity:.8">Password Reset OTP</p>
      </div>
      <div style="background:#f5f8ff;padding:28px;border-radius:0 0 12px 12px">
        <p style="margin:0 0 16px">Hello <strong>${user.name}</strong>,</p>
        <p style="margin:0 0 20px;color:#555">You requested to reset your password. Use this OTP to continue:</p>
        <div style="background:#fff;border:2px solid #00b5d8;border-radius:12px;text-align:center;padding:20px;margin:20px 0">
          <div style="font-size:40px;font-weight:800;letter-spacing:12px;color:#0d2c6b;font-family:monospace">${otp}</div>
          <div style="font-size:13px;color:#888;margin-top:8px">Valid for 10 minutes only</div>
        </div>
        <p style="color:#e53e3e;font-size:13px;margin:0 0 16px">⚠️ Never share this OTP with anyone. PrinterPartsPoint will never ask for your OTP.</p>
        <p style="color:#888;font-size:12px">If you did not request this, ignore this email. Your account is safe.</p>
        <hr style="border:none;border-top:1px solid #e2e8f0;margin:20px 0"/>
        <p style="font-size:12px;color:#999;text-align:center">PrinterPartsPoint | Karol Bagh, New Delhi | WhatsApp: +91 9990774445</p>
      </div>
    </div>`;
    await sendEmail(user.email, 'Your OTP for Password Reset — PrinterPartsPoint', emailHtml);
    console.log('OTP for', user.email, ':', otp); // show in Render logs for debugging
    res.json({
      message: 'OTP sent to ' + user.email.replace(/(.{2})(.*)(@.*)/, '$1****$3'),
      email_masked: user.email.replace(/(.{2})(.*)(@.*)/, '$1****$3'),
    });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// STEP 2: Verify OTP
app.post('/api/auth/verify-otp', (req, res) => {
  try {
    const input = sanitize(req.body.email_or_phone || '').toLowerCase().trim();
    const otp   = sanitize(req.body.otp || '').trim();
    if (!input || !otp) return res.status(400).json({ error: 'Email and OTP are required' });
    const db   = readDB();
    const user = db.users.find(u =>
      u.email === input ||
      (u.phone && u.phone === input.replace(/\D/g,'').slice(-10))
    );
    if (!user) return res.status(400).json({ error: 'Account not found' });
    const record = otpStore.get(user.email);
    if (!record)              return res.status(400).json({ error: 'OTP not found. Please request a new OTP.' });
    if (Date.now() > record.expires) {
      otpStore.delete(user.email);
      return res.status(400).json({ error: 'OTP has expired. Please request a new OTP.' });
    }
    if (record.otp !== otp) return res.status(400).json({ error: 'Incorrect OTP. Please try again.' });
    // OTP is correct — generate a short-lived reset token
    const resetToken = jwt.sign({ id:user.id, email:user.email, purpose:'reset' }, JWT_SECRET, { expiresIn:'15m' });
    otpStore.delete(user.email); // OTP used — delete it
    res.json({ message: 'OTP verified', reset_token: resetToken });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// STEP 3: Set new password using reset token
app.post('/api/auth/reset-password', (req, res) => {
  try {
    const { reset_token, new_password } = req.body;
    if (!reset_token || !new_password) return res.status(400).json({ error: 'Reset token and new password are required' });
    if (new_password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    let decoded;
    try {
      decoded = jwt.verify(reset_token, JWT_SECRET);
    } catch(e) {
      return res.status(400).json({ error: 'Reset link has expired. Please start again.' });
    }
    if (decoded.purpose !== 'reset') return res.status(400).json({ error: 'Invalid reset token' });
    const db  = readDB();
    const idx = db.users.findIndex(u => u.id === decoded.id);
    if (idx === -1) return res.status(404).json({ error: 'Account not found' });
    db.users[idx].password   = bcrypt.hashSync(new_password, 12);
    db.users[idx].updated_at = new Date().toISOString();
    writeDB(db);
    // Send confirmation email
    sendEmail(db.users[idx].email, 'Password Changed — PrinterPartsPoint',
      `<div style="font-family:Arial;padding:24px;max-width:500px;margin:auto">
        <h2 style="color:#1a4298">Password Changed Successfully</h2>
        <p>Hello ${db.users[idx].name},</p>
        <p>Your password has been changed successfully.</p>
        <p style="color:#e53e3e">If you did not make this change, contact us immediately on WhatsApp: +91 9990774445</p>
      </div>`
    );
    res.json({ message: 'Password changed successfully! You can now login with your new password.' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ════════════════════════════════════════════════════════════════
//   PRODUCTS
// ════════════════════════════════════════════════════════════════
app.get('/api/products', (req, res) => {
  try {
    const { cat, search, sort, page=1, limit=12, new:isNew, bestseller } = req.query;
    const db = readDB();
    let list = db.products.filter(p => p.is_active);
    if (cat && cat !== 'all') {
      const c = db.categories.find(c => c.slug === cat);
      if (c) list = list.filter(p => p.category_id === c.id);
    }
    if (search) {
      const q = sanitize(search).toLowerCase();
      list = list.filter(p => p.name.toLowerCase().includes(q) || (p.sku||'').toLowerCase().includes(q) || (p.description||'').toLowerCase().includes(q));
    }
    if (isNew === '1')      list = list.filter(p => p.is_new);
    if (bestseller === '1') list = list.filter(p => p.is_bestseller);
    const sortFns = { price_asc:(a,b)=>a.price-b.price, price_desc:(a,b)=>b.price-a.price, name:(a,b)=>a.name.localeCompare(b.name) };
    list.sort(sortFns[sort] || ((a,b) => new Date(b.created_at)-new Date(a.created_at)));
    // Add review stats and image URL
    list = list.map(p => {
      const revs    = (db.reviews||[]).filter(r => r.product_id === p.id && r.approved);
      const avgRating = revs.length ? (revs.reduce((s,r) => s+r.rating,0)/revs.length).toFixed(1) : null;
      return { ...p, category_name:db.categories.find(c=>c.id===p.category_id)?.name||'', image_url:p.image?BASE_URL+p.image:null, avg_rating:avgRating, review_count:revs.length };
    });
    const total = list.length, offset = (parseInt(page)-1)*parseInt(limit);
    res.json({ products:list.slice(offset,offset+parseInt(limit)), total, page:parseInt(page), limit:parseInt(limit) });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.get('/api/products/:id', (req, res) => {
  const db = readDB();
  const p  = db.products.find(p => p.id===parseInt(req.params.id) && p.is_active);
  if (!p) return res.status(404).json({ error:'Product not found' });
  const revs   = (db.reviews||[]).filter(r => r.product_id===p.id && r.approved);
  const avgRating = revs.length ? (revs.reduce((s,r)=>s+r.rating,0)/revs.length).toFixed(1) : null;
  res.json({ ...p, category_name:db.categories.find(c=>c.id===p.category_id)?.name||'', image_url:p.image?BASE_URL+p.image:null, avg_rating:avgRating, review_count:revs.length, reviews:revs.slice(0,10) });
});

app.post('/api/products', adminMiddleware, upload.single('image'), (req, res) => {
  try {
    const db = readDB();
    const { name, description, sku, category_id, price, old_price, stock, is_new, is_bestseller } = req.body;
    if (!name || !price) return res.status(400).json({ error:'Name and price are required' });
    const prod = { id:nextId(db.products), name:sanitize(name), description:sanitize(description)||'', sku:sanitize(sku)||'', category_id:category_id?parseInt(category_id):null, price:parseFloat(price), old_price:old_price?parseFloat(old_price):null, stock:parseInt(stock)||0, image:req.file?'/uploads/products/'+req.file.filename:null, is_new:is_new==='1', is_bestseller:is_bestseller==='1', is_active:true, created_at:new Date().toISOString() };
    db.products.push(prod); writeDB(db);
    res.json({ message:'Product added', id:prod.id, product:prod });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.put('/api/products/:id', adminMiddleware, upload.single('image'), (req, res) => {
  try {
    const db = readDB(), idx = db.products.findIndex(p => p.id===parseInt(req.params.id));
    if (idx===-1) return res.status(404).json({ error:'Product not found' });
    if (req.file && db.products[idx].image) { const old=path.join(__dirname,db.products[idx].image); if(fs.existsSync(old)) fs.unlinkSync(old); }
    const { name, description, sku, category_id, price, old_price, stock, is_new, is_bestseller, is_active } = req.body;
    db.products[idx] = { ...db.products[idx], name:sanitize(name)||db.products[idx].name, description:sanitize(description)??db.products[idx].description, sku:sanitize(sku)??db.products[idx].sku, category_id:category_id?parseInt(category_id):db.products[idx].category_id, price:price?parseFloat(price):db.products[idx].price, old_price:old_price!==undefined?(old_price?parseFloat(old_price):null):db.products[idx].old_price, stock:stock!==undefined?parseInt(stock):db.products[idx].stock, image:req.file?'/uploads/products/'+req.file.filename:db.products[idx].image, is_new:is_new==='1', is_bestseller:is_bestseller==='1', is_active:is_active!=='0'&&is_active!==false, updated_at:new Date().toISOString() };
    writeDB(db);
    res.json({ message:'Product updated', product:db.products[idx] });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.delete('/api/products/:id', adminMiddleware, (req, res) => {
  try {
    const db=readDB(), idx=db.products.findIndex(p=>p.id===parseInt(req.params.id));
    if (idx===-1) return res.status(404).json({ error:'Product not found' });
    if (db.products[idx].image) { const p=path.join(__dirname,db.products[idx].image); if(fs.existsSync(p)) fs.unlinkSync(p); }
    db.products.splice(idx,1); writeDB(db);
    res.json({ message:'Product deleted' });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.delete('/api/products/:id/image', adminMiddleware, (req, res) => {
  const db=readDB(), idx=db.products.findIndex(p=>p.id===parseInt(req.params.id));
  if (idx===-1) return res.status(404).json({ error:'Not found' });
  if (db.products[idx].image) { const p=path.join(__dirname,db.products[idx].image); if(fs.existsSync(p)) fs.unlinkSync(p); db.products[idx].image=null; writeDB(db); }
  res.json({ message:'Image removed' });
});

// ════════════════════════════════════════════════════════════════
//   PRODUCT REVIEWS
// ════════════════════════════════════════════════════════════════
app.post('/api/products/:id/reviews', authMiddleware, (req, res) => {
  try {
    const { rating, title, comment } = req.body;
    if (!rating || rating < 1 || rating > 5) return res.status(400).json({ error:'Rating must be 1–5' });
    if (!comment) return res.status(400).json({ error:'Review comment is required' });
    const db      = readDB();
    const product = db.products.find(p => p.id===parseInt(req.params.id));
    if (!product) return res.status(404).json({ error:'Product not found' });
    // Check if user actually ordered this product
    const userOrders    = db.orders.filter(o => o.user_id===req.user.id && o.status==='delivered');
    const boughtProduct = userOrders.some(o => (db.order_items||[]).some(i => i.order_id===o.id && i.product_id===product.id));
    if (!boughtProduct) return res.status(403).json({ error:'You can only review products you have purchased and received' });
    // Check no duplicate review
    db.reviews = db.reviews || [];
    if (db.reviews.find(r => r.product_id===product.id && r.user_id===req.user.id)) return res.status(409).json({ error:'You have already reviewed this product' });
    const user   = db.users.find(u => u.id===req.user.id);
    const review = { id:nextId(db.reviews), product_id:product.id, user_id:req.user.id, user_name:user?.name||'Customer', rating:parseInt(rating), title:sanitize(title)||'', comment:sanitize(comment), approved:true, created_at:new Date().toISOString() };
    db.reviews.push(review); writeDB(db);
    res.json({ message:'Review submitted successfully', review });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

// ════════════════════════════════════════════════════════════════
//   CATEGORIES
// ════════════════════════════════════════════════════════════════
app.get('/api/categories', (req,res) => res.json(readDB().categories.sort((a,b)=>a.sort_order-b.sort_order)));
app.post('/api/categories', adminMiddleware, (req,res) => {
  const db=readDB(); const {name,slug}=req.body;
  if (!name||!slug) return res.status(400).json({error:'Name and slug required'});
  if (db.categories.find(c=>c.slug===slug)) return res.status(409).json({error:'This slug already exists'});
  const c={id:nextId(db.categories),name:sanitize(name),slug:sanitize(slug),sort_order:db.categories.length+1};
  db.categories.push(c); writeDB(db); res.json({id:c.id,message:'Category added'});
});
app.put('/api/categories/:id', adminMiddleware, (req,res) => {
  const db=readDB(),idx=db.categories.findIndex(c=>c.id===parseInt(req.params.id));
  if (idx===-1) return res.status(404).json({error:'Not found'});
  db.categories[idx]={...db.categories[idx],...req.body}; writeDB(db); res.json({message:'Updated'});
});
app.delete('/api/categories/:id', adminMiddleware, (req,res) => {
  const db=readDB(),idx=db.categories.findIndex(c=>c.id===parseInt(req.params.id));
  if (idx===-1) return res.status(404).json({error:'Not found'});
  db.categories.splice(idx,1); writeDB(db); res.json({message:'Deleted'});
});

// ════════════════════════════════════════════════════════════════
//   PAYMENT — RAZORPAY
// ════════════════════════════════════════════════════════════════
app.post('/api/payment/create-order', authMiddleware, (req, res) => {
  try {
    if (!razorpay) return res.status(503).json({ error:'Payment gateway not configured. Please contact admin or use COD.' });
    const { items, shipping_address } = req.body;
    if (!items?.length) return res.status(400).json({ error:'No items in cart' });
    const db = readDB();
    let subtotal = 0; const validated = [];
    for (const item of items) {
      const p = db.products.find(p => p.id===item.product_id && p.is_active);
      if (!p)            return res.status(400).json({ error:`Product not found: ${item.product_id}` });
      if (p.stock < item.qty) return res.status(400).json({ error:`Only ${p.stock} units available for: ${p.name}` });
      subtotal += p.price * item.qty;
      validated.push({ product_id:item.product_id, qty:item.qty, price:p.price, name:p.name });
    }
    const gst   = Math.round(subtotal*0.18*100)/100;
    const total = Math.round((subtotal+gst)*100); // paise
    razorpay.orders.create({ amount:total, currency:'INR', receipt:'PPP_'+Date.now(), notes:{ user_id:req.user.id } }, (err, order) => {
      if (err) { console.error('Razorpay error:', err); return res.status(500).json({ error:'Could not create payment: '+(err.error?.description||err.message) }); }
      res.json({ razorpay_order_id:order.id, amount:order.amount, currency:order.currency, key_id:RAZORPAY_KEY_ID, subtotal, gst, total:subtotal+gst, validated_items:validated, shipping_address });
    });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.post('/api/payment/verify', authMiddleware, async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, items, shipping_address, notes } = req.body;
    // Verify Razorpay signature
    const expected = crypto.createHmac('sha256', RAZORPAY_KEY_SECRET).update(razorpay_order_id+'|'+razorpay_payment_id).digest('hex');
    if (expected !== razorpay_signature) return res.status(400).json({ error:'Payment verification failed. Please contact support with payment ID: '+razorpay_payment_id });
    const db = readDB();
    let subtotal = 0; const resolvedItems = [];
    for (const item of items) {
      const p = db.products.find(p => p.id===item.product_id && p.is_active);
      if (!p) return res.status(400).json({ error:'Product not found during order creation' });
      subtotal += p.price * item.qty;
      resolvedItems.push({ product_id:item.product_id, qty:item.qty, price:p.price, name:p.name, image:p.image?BASE_URL+p.image:null });
    }
    const gst = Math.round(subtotal*0.18*100)/100, total = subtotal+gst;
    const order_number = 'PPP'+Date.now(), orderId = nextId(db.orders);
    const order = { id:orderId, order_number, user_id:req.user.id, subtotal, gst, total, shipping_address:JSON.stringify(shipping_address), payment_method:'online', payment_status:'paid', razorpay_order_id, razorpay_payment_id, status:'confirmed', tracking_number:null, tracking_url:null, notes:sanitize(notes)||null, cancel_reason:null, return_requested:false, created_at:new Date().toISOString(), updated_at:new Date().toISOString() };
    db.orders.push(order);
    resolvedItems.forEach(item => {
      db.order_items.push({ id:nextId(db.order_items), order_id:orderId, product_id:item.product_id, qty:item.qty, price:item.price });
      const pi = db.products.findIndex(p=>p.id===item.product_id); if(pi!==-1) db.products[pi].stock -= item.qty;
    });
    db.payment_logs.push({ razorpay_order_id, razorpay_payment_id, amount:total, user_id:req.user.id, created_at:new Date().toISOString() });
    logOrderEvent(db, orderId, 'confirmed', 'Order confirmed — online payment received via Razorpay', 'system');
    writeDB(db);
    // Send confirmation email
    const user = db.users.find(u=>u.id===req.user.id);
    if (user?.email) sendEmail(user.email, `Order Confirmed — ${order_number} | PrinterPartsPoint`, orderConfirmationEmail(order, user, resolvedItems));
    res.json({ success:true, message:'Payment verified. Order confirmed!', order_id:orderId, order_number, total });
  } catch(e) { console.error(e); res.status(500).json({ error:'Order creation failed: '+e.message }); }
});

// ════════════════════════════════════════════════════════════════
//   ORDERS
// ════════════════════════════════════════════════════════════════

// COD Order
app.post('/api/orders/cod', authMiddleware, async (req, res) => {
  try {
    const { items, shipping_address, notes } = req.body;
    if (!items?.length) return res.status(400).json({ error:'No items in cart' });
    const db = readDB();
    let subtotal = 0; const resolvedItems = [];
    for (const item of items) {
      const p = db.products.find(p=>p.id===item.product_id&&p.is_active);
      if (!p) return res.status(400).json({ error:`Product not found: ${item.product_id}` });
      if (p.stock < item.qty) return res.status(400).json({ error:`Only ${p.stock} units available for: ${p.name}` });
      subtotal += p.price * item.qty;
      resolvedItems.push({ product_id:item.product_id, qty:item.qty, price:p.price, name:p.name });
    }
    const gst = Math.round(subtotal*0.18*100)/100, total = subtotal+gst;
    const order_number = 'PPP'+Date.now(), orderId = nextId(db.orders);
    const order = { id:orderId, order_number, user_id:req.user.id, subtotal, gst, total, shipping_address:JSON.stringify(shipping_address), payment_method:'cod', payment_status:'pending', razorpay_order_id:null, razorpay_payment_id:null, status:'pending', tracking_number:null, tracking_url:null, notes:sanitize(notes)||null, cancel_reason:null, return_requested:false, created_at:new Date().toISOString(), updated_at:new Date().toISOString() };
    db.orders.push(order);
    resolvedItems.forEach(item => {
      db.order_items.push({ id:nextId(db.order_items), order_id:orderId, product_id:item.product_id, qty:item.qty, price:item.price });
      const pi=db.products.findIndex(p=>p.id===item.product_id); if(pi!==-1) db.products[pi].stock -= item.qty;
    });
    logOrderEvent(db, orderId, 'pending', 'COD order placed — awaiting confirmation', 'system');
    writeDB(db);
    const user = db.users.find(u=>u.id===req.user.id);
    if (user?.email) sendEmail(user.email, `Order Placed — ${order_number} | PrinterPartsPoint`, orderConfirmationEmail(order, user, resolvedItems));
    res.json({ success:true, message:'COD order placed', order_id:orderId, order_number, total });
  } catch(e) { console.error(e); res.status(500).json({ error:'Order failed: '+e.message }); }
});

// Get my orders (with full item details)
app.get('/api/orders', authMiddleware, (req, res) => {
  const db = readDB();
  const orders = db.orders.filter(o=>o.user_id===req.user.id)
    .sort((a,b)=>new Date(b.created_at)-new Date(a.created_at))
    .map(o => {
      const ois = (db.order_items||[]).filter(i=>i.order_id===o.id);
      const items = ois.map(i => { const p=db.products.find(p=>p.id===i.product_id); return { product_id:i.product_id, name:p?.name||'Product', qty:i.qty, price:i.price, image_url:p?.image?BASE_URL+p.image:null }; });
      const events = (db.order_events||[]).filter(e=>e.order_id===o.id).sort((a,b)=>new Date(a.created_at)-new Date(b.created_at));
      return { ...o, items, events };
    });
  res.json(orders);
});

// Get single order with full timeline
app.get('/api/orders/:id', authMiddleware, (req, res) => {
  const db    = readDB();
  const order = db.orders.find(o=>o.id===parseInt(req.params.id)&&(o.user_id===req.user.id||req.user.role==='admin'));
  if (!order) return res.status(404).json({ error:'Order not found' });
  const ois    = (db.order_items||[]).filter(i=>i.order_id===order.id);
  const items  = ois.map(i => { const p=db.products.find(p=>p.id===i.product_id); return { product_id:i.product_id, name:p?.name||'Product', qty:i.qty, price:i.price, image_url:p?.image?BASE_URL+p.image:null }; });
  const events = (db.order_events||[]).filter(e=>e.order_id===order.id).sort((a,b)=>new Date(a.created_at)-new Date(b.created_at));
  res.json({ ...order, items, events });
});

// Track order (public)
app.get('/api/orders/track/:order_number', (req, res) => {
  const db    = readDB();
  const order = db.orders.find(o=>o.order_number===req.params.order_number);
  if (!order) return res.status(404).json({ error:'Order not found. Please check the order number and try again.' });
  const ois   = (db.order_items||[]).filter(i=>i.order_id===order.id);
  const items = ois.map(i => { const p=db.products.find(p=>p.id===i.product_id); return (p?.name||'Product')+' x'+i.qty; }).join(', ');
  const events= (db.order_events||[]).filter(e=>e.order_id===order.id).sort((a,b)=>new Date(a.created_at)-new Date(b.created_at));
  res.json({ order_number:order.order_number, status:order.status, payment_status:order.payment_status, payment_method:order.payment_method, tracking_number:order.tracking_number, tracking_url:order.tracking_url, items, total:order.total, created_at:order.created_at, events });
});

// Cancel order (customer — within cancel window)
app.post('/api/orders/:id/cancel', authMiddleware, (req, res) => {
  try {
    const db  = readDB();
    const idx = db.orders.findIndex(o=>o.id===parseInt(req.params.id)&&o.user_id===req.user.id);
    if (idx===-1) return res.status(404).json({ error:'Order not found' });
    const order = db.orders[idx];
    if (['delivered','cancelled'].includes(order.status)) return res.status(400).json({ error:'This order cannot be cancelled' });
    if (order.status === 'shipped') return res.status(400).json({ error:'Order is already shipped. Please request return after delivery.' });
    // Check cancel window
    const settings    = db.settings;
    const cancelHours = settings.cancel_window_hours || 24;
    const hoursPassed = (Date.now()-new Date(order.created_at).getTime())/(1000*60*60);
    if (hoursPassed > cancelHours) return res.status(400).json({ error:`Cancel window of ${cancelHours} hours has passed. Please contact us on WhatsApp.` });
    const reason = sanitize(req.body.reason) || 'Cancelled by customer';
    db.orders[idx].status        = 'cancelled';
    db.orders[idx].cancel_reason = reason;
    db.orders[idx].updated_at    = new Date().toISOString();
    // Restore stock
    const ois = (db.order_items||[]).filter(i=>i.order_id===order.id);
    ois.forEach(item => { const pi=db.products.findIndex(p=>p.id===item.product_id); if(pi!==-1) db.products[pi].stock += item.qty; });
    logOrderEvent(db, order.id, 'cancelled', 'Order cancelled by customer: '+reason, 'customer');
    writeDB(db);
    // Send cancellation email
    const user = db.users.find(u=>u.id===req.user.id);
    if (user?.email) sendEmail(user.email, `Order Cancelled — ${order.order_number} | PrinterPartsPoint`, orderStatusEmail(order, user, 'cancelled', null));
    res.json({ success:true, message:'Order cancelled successfully. Refund (if applicable) will be processed in 5–7 business days.' });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

// Return request (customer — after delivery)
app.post('/api/orders/:id/return', authMiddleware, (req, res) => {
  try {
    const db  = readDB();
    const idx = db.orders.findIndex(o=>o.id===parseInt(req.params.id)&&o.user_id===req.user.id);
    if (idx===-1) return res.status(404).json({ error:'Order not found' });
    const order = db.orders[idx];
    if (order.status !== 'delivered') return res.status(400).json({ error:'Return can only be requested for delivered orders' });
    if (order.return_requested)       return res.status(400).json({ error:'Return already requested for this order' });
    const settings    = db.settings;
    const returnDays  = settings.return_window_days || 7;
    const daysPassed  = (Date.now()-new Date(order.updated_at||order.created_at).getTime())/(1000*60*60*24);
    if (daysPassed > returnDays) return res.status(400).json({ error:`Return window of ${returnDays} days has passed. Please contact us on WhatsApp.` });
    const reason = sanitize(req.body.reason) || 'Return requested by customer';
    db.orders[idx].return_requested = true;
    db.orders[idx].return_reason    = reason;
    db.orders[idx].return_status    = 'requested';
    db.orders[idx].updated_at       = new Date().toISOString();
    logOrderEvent(db, order.id, 'return_requested', 'Return requested: '+reason, 'customer');
    writeDB(db);
    const user = db.users.find(u=>u.id===req.user.id);
    if (user?.email) sendEmail(user.email, `Return Request — ${order.order_number} | PrinterPartsPoint`,
      `<div style="font-family:Arial;padding:24px;max-width:500px;margin:auto">
        <h2 style="color:#1a4298">Return Request Received</h2>
        <p>Hello ${user.name},</p>
        <p>Your return request for order <strong>${order.order_number}</strong> has been received.</p>
        <p>Reason: ${reason}</p>
        <p>Our team will contact you within 24–48 hours to arrange pickup.</p>
        <p style="color:#777">WhatsApp: +91 9990774445</p>
      </div>`
    );
    res.json({ success:true, message:'Return request submitted. Our team will contact you within 24-48 hours.' });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

// Admin: Update order status
app.put('/api/orders/:id/status', adminMiddleware, async (req, res) => {
  try {
    const db  = readDB();
    const idx = db.orders.findIndex(o=>o.id===parseInt(req.params.id));
    if (idx===-1) return res.status(404).json({ error:'Order not found' });
    const { status, tracking_number, tracking_url, note } = req.body;
    const old = db.orders[idx].status;
    db.orders[idx].status          = status;
    db.orders[idx].tracking_number = tracking_number || db.orders[idx].tracking_number;
    db.orders[idx].tracking_url    = tracking_url    || db.orders[idx].tracking_url;
    db.orders[idx].updated_at      = new Date().toISOString();
    // Mark as paid if confirmed COD
    if (status === 'delivered' && db.orders[idx].payment_method==='cod') { db.orders[idx].payment_status = 'paid'; }
    logOrderEvent(db, db.orders[idx].id, status, note||('Status changed from '+old+' to '+status+' by admin'), 'admin');
    writeDB(db);
    // Send status update email to customer
    const user = db.users.find(u=>u.id===db.orders[idx].user_id);
    if (user?.email) sendEmail(user.email, `Order ${status.charAt(0).toUpperCase()+status.slice(1)} — ${db.orders[idx].order_number} | PrinterPartsPoint`, orderStatusEmail(db.orders[idx], user, status, tracking_number));
    res.json({ message:'Order updated and customer notified' });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

// Admin: Get all orders
app.get('/api/admin/orders', adminMiddleware, (req, res) => {
  const { status, page=1, limit=20, search } = req.query;
  const db = readDB();
  let orders = [...db.orders].sort((a,b)=>new Date(b.created_at)-new Date(a.created_at));
  if (status)  orders = orders.filter(o=>o.status===status);
  if (search)  orders = orders.filter(o=>o.order_number.includes(search.toUpperCase())||(db.users.find(u=>u.id===o.user_id)?.name||'').toLowerCase().includes(search.toLowerCase()));
  orders = orders.map(o => {
    const u    = db.users.find(u=>u.id===o.user_id);
    const ois  = (db.order_items||[]).filter(i=>i.order_id===o.id);
    const items= ois.map(i=>db.products.find(p=>p.id===i.product_id)?.name||'Product').join(', ');
    return { ...o, customer_name:u?.name, customer_email:u?.email, customer_phone:u?.phone, items };
  });
  const total = orders.length, offset = (parseInt(page)-1)*parseInt(limit);
  res.json({ orders:orders.slice(offset,offset+parseInt(limit)), total });
});

// ════════════════════════════════════════════════════════════════
//   WISHLIST
// ════════════════════════════════════════════════════════════════
app.get('/api/wishlist', authMiddleware, (req, res) => {
  const db   = readDB();
  const list = (db.wishlists||[]).filter(w=>w.user_id===req.user.id);
  const items = list.map(w => { const p=db.products.find(p=>p.id===w.product_id&&p.is_active); return p?{ ...w, product:{ ...p, image_url:p.image?BASE_URL+p.image:null } }:null; }).filter(Boolean);
  res.json(items);
});

app.post('/api/wishlist/:product_id', authMiddleware, (req, res) => {
  const db = readDB(); db.wishlists = db.wishlists||[];
  const pid = parseInt(req.params.product_id);
  const existing = db.wishlists.findIndex(w=>w.user_id===req.user.id&&w.product_id===pid);
  if (existing!==-1) { db.wishlists.splice(existing,1); writeDB(db); return res.json({ message:'Removed from wishlist', added:false }); }
  db.wishlists.push({ id:nextId(db.wishlists), user_id:req.user.id, product_id:pid, created_at:new Date().toISOString() });
  writeDB(db); res.json({ message:'Added to wishlist', added:true });
});

// ════════════════════════════════════════════════════════════════
//   USER PROFILE & ADDRESSES
// ════════════════════════════════════════════════════════════════
app.get('/api/user/profile', authMiddleware, (req, res) => {
  const u = readDB().users.find(u=>u.id===req.user.id);
  if (!u) return res.status(404).json({ error:'Not found' });
  const { password, ...safe } = u; res.json(safe);
});

app.put('/api/user/profile', authMiddleware, (req, res) => {
  const db=readDB(), idx=db.users.findIndex(u=>u.id===req.user.id);
  if (idx===-1) return res.status(404).json({ error:'Not found' });
  if (req.body.name)  db.users[idx].name  = sanitize(req.body.name);
  if (req.body.phone) db.users[idx].phone = sanitize(req.body.phone);
  writeDB(db); res.json({ message:'Profile updated' });
});

app.put('/api/user/password', authMiddleware, (req, res) => {
  const { current_password, new_password } = req.body;
  const db=readDB(), idx=db.users.findIndex(u=>u.id===req.user.id);
  if (idx===-1) return res.status(404).json({ error:'Not found' });
  if (!bcrypt.compareSync(current_password, db.users[idx].password)) return res.status(401).json({ error:'Current password is incorrect' });
  if (new_password.length < 8) return res.status(400).json({ error:'New password must be at least 8 characters' });
  db.users[idx].password = bcrypt.hashSync(new_password, 12); writeDB(db);
  res.json({ message:'Password changed successfully' });
});

// Multiple saved addresses (like Amazon/Flipkart)
app.get('/api/user/addresses', authMiddleware, (req, res) => {
  const u = readDB().users.find(u=>u.id===req.user.id);
  res.json(u?.addresses||[]);
});

app.post('/api/user/addresses', authMiddleware, (req, res) => {
  const db=readDB(), idx=db.users.findIndex(u=>u.id===req.user.id);
  if (idx===-1) return res.status(404).json({ error:'Not found' });
  db.users[idx].addresses = db.users[idx].addresses||[];
  const addr = { id:nextId(db.users[idx].addresses.length?db.users[idx].addresses:[{id:0}]), ...req.body, created_at:new Date().toISOString() };
  if (req.body.is_default || !db.users[idx].addresses.length) {
    db.users[idx].addresses.forEach(a=>a.is_default=false); addr.is_default=true;
  }
  db.users[idx].addresses.push(addr); writeDB(db);
  res.json({ message:'Address saved', address:addr });
});

app.delete('/api/user/addresses/:id', authMiddleware, (req, res) => {
  const db=readDB(), idx=db.users.findIndex(u=>u.id===req.user.id);
  if (idx===-1) return res.status(404).json({ error:'Not found' });
  db.users[idx].addresses = (db.users[idx].addresses||[]).filter(a=>a.id!==parseInt(req.params.id));
  writeDB(db); res.json({ message:'Address deleted' });
});

// ════════════════════════════════════════════════════════════════
//   ADMIN STATS
// ════════════════════════════════════════════════════════════════
app.get('/api/admin/stats', adminMiddleware, (req, res) => {
  const db = readDB();
  const paidOrders = db.orders.filter(o=>o.payment_status==='paid');
  res.json({
    orders:        db.orders.length,
    revenue:       paidOrders.reduce((s,o)=>s+o.total,0),
    products:      db.products.filter(p=>p.is_active).length,
    users:         db.users.filter(u=>u.role!=='admin').length,
    pending:       db.orders.filter(o=>o.status==='pending').length,
    confirmed:     db.orders.filter(o=>o.status==='confirmed').length,
    shipped:       db.orders.filter(o=>o.status==='shipped').length,
    delivered:     db.orders.filter(o=>o.status==='delivered').length,
    cancelled:     db.orders.filter(o=>o.status==='cancelled').length,
    returns:       db.orders.filter(o=>o.return_requested).length,
    cod_pending:   db.orders.filter(o=>o.payment_method==='cod'&&o.payment_status==='pending').length,
  });
});

// ════════════════════════════════════════════════════════════════
//   CONTACT
// ════════════════════════════════════════════════════════════════
app.post('/api/contact', (req, res) => {
  const db=readDB();
  const { name, email, phone, message } = req.body;
  if (!name||!message) return res.status(400).json({ error:'Name and message are required' });
  db.enquiries.push({ id:nextId(db.enquiries), name:sanitize(name), email:sanitize(email)||null, phone:sanitize(phone)||null, message:sanitize(message), is_read:false, created_at:new Date().toISOString() });
  writeDB(db);
  // Notify admin
  if (transporter) sendEmail(EMAIL_USER, 'New Contact Enquiry — PrinterPartsPoint', `<p>From: ${name} (${email||'no email'}) — ${phone||'no phone'}</p><p>${message}</p>`);
  res.json({ message:'Enquiry submitted. We will contact you within 24 hours.' });
});

// ════════════════════════════════════════════════════════════════
//   START
// ════════════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║   PrinterPartsPoint Production Backend           ║');
  console.log(`║   Running at: http://localhost:${PORT}               ║`);
  console.log('║   Security:   Helmet + Rate Limiting             ║');
  console.log(`║   Razorpay:   ${razorpay ? 'CONFIGURED ✅' : 'NOT configured ⚠️ '}              ║`);
  console.log(`║   Email:      ${transporter ? 'CONFIGURED ✅' : 'NOT configured ⚠️ '}              ║`);
  console.log('╚══════════════════════════════════════════════════╝');
  console.log('');
});