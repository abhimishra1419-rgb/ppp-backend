// ════════════════════════════════════════════════════════════════
//   PrintersReports – Production Backend
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
const JWT_SECRET   = process.env.JWT_SECRET    || 'printersreports_secret_change_in_production';
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
const EMAIL_FROM = process.env.EMAIL_FROM || 'PrintersReports <noreply@printersreports.in>';
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

// ── Shipping calculator ──────────────────────────────────────
// Returns shipping charge for a cart of items
function calculateShipping(items, productsDb, settings) {
  const subtotal      = items.reduce((s, i) => s + i.price * i.qty, 0);
  const freeThreshold = settings.free_shipping_min || 999;
  const defaultCharge = settings.default_shipping_charge !== undefined ? settings.default_shipping_charge : 80;

  // Free shipping if subtotal meets threshold
  if (subtotal >= freeThreshold) return 0;

  // Calculate shipping per item
  let shippingTotal = 0;
  items.forEach(item => {
    const product = productsDb.find(p => p.id === item.product_id);
    if (!product) return;
    // Use product-specific shipping charge if set, else global default
    const itemShipping = (product.shipping_charge !== null && product.shipping_charge !== undefined)
      ? product.shipping_charge
      : defaultCharge;
    shippingTotal += itemShipping * item.qty;
  });

  // Cap at a max (don't charge shipping more than once for single-item orders)
  // For multi-item: charge per item or a flat cap — use flat cap approach
  // Take max of individual item charges (not per-qty) for fairness
  if (items.length > 0) {
    const itemCharges = items.map(item => {
      const product = productsDb.find(p => p.id === item.product_id);
      return (product && product.shipping_charge !== null && product.shipping_charge !== undefined)
        ? product.shipping_charge
        : defaultCharge;
    });
    // Use the highest individual product shipping charge as the order shipping
    return Math.max(...itemCharges);
  }
  return defaultCharge;
}


// ── DATABASE SETUP ───────────────────────────────────────────
function setupDatabase() {
  if (fs.existsSync(DB_FILE)) { console.log('✅ database.json loaded'); return; }
  const adminHash = bcrypt.hashSync('Admin@1234', 12);
  const db = {
    settings: {
      logo_url:null, site_name:'PrintersReports', tagline:"India's #1 Printer Reports Store",
      hero_title:"India's #1 Source for Printer Reports",
      hero_subtitle:'Genuine & compatible parts for HP, Canon, Epson, Ricoh, Brother printers.',
      hero_btn_primary:'Shop Now', hero_btn_secondary:'New Arrivals',
      announcement_bar:'Free Shipping on orders above Rs.999 | All Prices Exclusive of 18% GST',
      whatsapp_number:'', whatsapp_banner_text:'For any queries contact us on WhatsApp',
      gst_rate:18, free_shipping_min:999,
      default_shipping_charge: 80,   // Rs.80 default shipping per order
      shipping_message: 'Free shipping on orders above Rs.999',
      show_new_arrivals:true, show_best_sellers:true, show_categories:true,
      footer_address:'',
      footer_email:'support@printersreports.in',
      working_hours:'Mon-Sat: 10:00 AM - 7:00 PM',
      cancel_window_hours: 24, // customers can cancel within 24 hours
      return_window_days:  7,  // customers can request return within 7 days
      meta_title:'PrintersReports - Printer Reports India',
      meta_description:'Buy genuine printer reports online in India.',
      // Nav links — admin can edit these
      nav_links: JSON.stringify([
        { label:'Home',        url:'index.html',              icon:'🏠' },
        { label:'All Products',url:'products.html',           icon:'📦' },
        { label:'Laser Parts', url:'products.html?cat=laser', icon:'🖨️' },
        { label:'Inkjet Parts',url:'products.html?cat=inkjet',icon:'💧' },
        { label:'Toner Parts', url:'products.html?cat=toner', icon:'🖤' },
        { label:'Thermal/POS', url:'products.html?cat=thermal',icon:'🧾' },
        { label:'Track Order', url:'track.html',              icon:'📦' },
        { label:'Contact',     url:'contact.html',            icon:'📞' },
      ]),
      // Social media links
      social_whatsapp: '',
      social_facebook:  '',
      social_instagram: '',
      social_youtube:   '',
      // Footer text
      footer_tagline: 'Your trusted source for genuine printer reports across India.',
      footer_copyright: '2025 PrintersReports. All rights reserved.',
      // Theme colors
      color_primary: '#0d2c6b',
      color_secondary: '#1a4298',
      color_accent: '#00b5d8',
    },
    users:        [{ id:1, name:'Admin', email:'admin@printersreports.in', phone:'', password:adminHash, role:'admin', addresses:[], created_at:new Date().toISOString() }],
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
  console.log('🔑 Admin: admin@printersreports.in / Admin@1234');
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
  if (!transporter) {
    console.log('📧 Email not configured — EMAIL_USER / EMAIL_PASS not set in Render environment');
    return { sent: false, reason: 'not_configured' };
  }
  try {
    await transporter.sendMail({ from: EMAIL_FROM, to, subject, html });
    console.log('📧 Email sent to:', to);
    return { sent: true };
  } catch(e) {
    console.log('📧 Email FAILED to:', to, '|', e.message);
    return { sent: false, reason: e.message };
  }
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
      <h1 style="margin:0;font-size:24px">PrintersReports</h1>
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
      <p style="text-align:center;color:#777;font-size:13px">For queries: WhatsApp us at your support number<br/>or email support@printersreports.in</p>
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
      <h1 style="margin:0;font-size:24px">PrintersReports</h1>
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
// Logo upload — stores file in uploads/logo/ folder
const logoStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads', 'logo');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, 'logo' + ext); // always overwrite with same name
  },
});
const uploadLogo = multer({
  storage: logoStorage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB max for logo
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg','.jpeg','.png','.webp','.svg','.gif'];
    allowed.includes(path.extname(file.originalname).toLowerCase()) ? cb(null,true) : cb(new Error('Image files only'));
  },
});

// Upload logo image
app.post('/api/settings/logo', adminMiddleware, uploadLogo.single('logo'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No logo file uploaded' });
    const db = readDB();
    // Remove old logo file if different extension
    const logoDir = path.join(__dirname, 'uploads', 'logo');
    const ext     = path.extname(req.file.filename).toLowerCase();
    const exts    = ['.jpg','.jpeg','.png','.webp','.svg','.gif'];
    exts.filter(e => e !== ext).forEach(e => {
      const old = path.join(logoDir, 'logo'+e);
      if (fs.existsSync(old)) fs.unlinkSync(old);
    });
    db.settings.logo_url = '/uploads/logo/' + req.file.filename;
    writeDB(db);
    res.json({ message: 'Logo uploaded', logo_url: BASE_URL + db.settings.logo_url });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Upload failed' }); }
});

// Delete logo — revert to text logo
app.delete('/api/settings/logo', adminMiddleware, (req, res) => {
  const db = readDB();
  if (db.settings.logo_url) {
    const p = path.join(__dirname, db.settings.logo_url);
    if (fs.existsSync(p)) fs.unlinkSync(p);
    db.settings.logo_url = null;
    writeDB(db);
  }
  res.json({ message: 'Logo removed' });
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
    sendEmail(email, 'Welcome to PrintersReports!',
      `<div style="font-family:Arial,sans-serif;padding:24px;max-width:500px;margin:auto">
        <h2 style="color:#1a4298">Welcome, ${name}! 🎉</h2>
        <p>Your account has been created successfully on PrintersReports.</p>
        <p>You can now shop for genuine printer reports delivered across India.</p>
        <p style="color:#777;font-size:13px">For queries: WhatsApp ${process.env.WHATSAPP_NUMBER || "your WhatsApp number"}</p>
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

// ════════════════════════════════════════════════════════════════
//   GOOGLE LOGIN — Verify Google ID token and login/register user
// ════════════════════════════════════════════════════════════════
app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body; // Google ID token from frontend
    if (!credential) return res.status(400).json({ error: 'No Google credential provided' });

    // Verify token with Google's tokeninfo endpoint (no extra package needed)
    const googleRes = await fetch(
      'https://oauth2.googleapis.com/tokeninfo?id_token=' + credential
    );
    const googleData = await googleRes.json();

    if (!googleRes.ok || googleData.error) {
      return res.status(401).json({ error: 'Invalid Google token. Please try again.' });
    }

    // Check audience matches our Client ID
    const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
    if (GOOGLE_CLIENT_ID && googleData.aud !== GOOGLE_CLIENT_ID) {
      return res.status(401).json({ error: 'Google token audience mismatch.' });
    }

    const email = googleData.email;
    const name  = googleData.name || googleData.email.split('@')[0];
    const googleId = googleData.sub;

    if (!email) return res.status(400).json({ error: 'Could not get email from Google account' });

    const db = readDB();

    // Check if user already exists
    let user = db.users.find(u => u.email === email);

    if (user) {
      // Existing user — update Google ID if not set
      const idx = db.users.findIndex(u => u.email === email);
      if (!db.users[idx].google_id) {
        db.users[idx].google_id = googleId;
        writeDB(db);
      }
      user = db.users[idx];
    } else {
      // New user — create account automatically (no password needed)
      user = {
        id:         nextId(db.users),
        name:       sanitize(name),
        email:      email.toLowerCase(),
        phone:      null,
        password:   null,        // no password for social login
        google_id:  googleId,
        role:       'customer',
        addresses:  [],
        created_at: new Date().toISOString(),
      };
      db.users.push(user);
      writeDB(db);
      console.log('New user via Google:', email);
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
      is_new: !db.users.find(u => u.email === email && u.created_at !== user.created_at),
    });
  } catch(e) {
    console.error('Google login error:', e);
    res.status(500).json({ error: 'Google login failed. Please try again.' });
  }
});

// ════════════════════════════════════════════════════════════════
//   FACEBOOK LOGIN — Verify Facebook access token
// ════════════════════════════════════════════════════════════════
app.post('/api/auth/facebook', async (req, res) => {
  try {
    const { accessToken, userID } = req.body;
    if (!accessToken || !userID) return res.status(400).json({ error: 'No Facebook token provided' });

    const FACEBOOK_APP_ID     = process.env.FACEBOOK_APP_ID     || '';
    const FACEBOOK_APP_SECRET = process.env.FACEBOOK_APP_SECRET || '';

    // Verify token with Facebook Graph API
    let verifyUrl = 'https://graph.facebook.com/debug_token?input_token=' + accessToken;
    if (FACEBOOK_APP_ID && FACEBOOK_APP_SECRET) {
      verifyUrl += '&access_token=' + FACEBOOK_APP_ID + '|' + FACEBOOK_APP_SECRET;
    }
    const verifyRes  = await fetch(verifyUrl);
    const verifyData = await verifyRes.json();

    if (!verifyData.data || !verifyData.data.is_valid) {
      return res.status(401).json({ error: 'Invalid Facebook token. Please try again.' });
    }

    // Get user info from Facebook
    const fbUserRes  = await fetch('https://graph.facebook.com/' + userID + '?fields=id,name,email&access_token=' + accessToken);
    const fbUserData = await fbUserRes.json();

    if (!fbUserData.email) {
      return res.status(400).json({ error: 'Facebook account does not have a public email. Please use email/password login.' });
    }

    const email      = fbUserData.email;
    const name       = fbUserData.name || email.split('@')[0];
    const facebookId = fbUserData.id;

    const db = readDB();
    let user = db.users.find(u => u.email === email);

    if (user) {
      const idx = db.users.findIndex(u => u.email === email);
      if (!db.users[idx].facebook_id) { db.users[idx].facebook_id = facebookId; writeDB(db); }
      user = db.users[idx];
    } else {
      user = {
        id:          nextId(db.users),
        name:        sanitize(name),
        email:       email.toLowerCase(),
        phone:       null,
        password:    null,
        facebook_id: facebookId,
        role:        'customer',
        addresses:   [],
        created_at:  new Date().toISOString(),
      };
      db.users.push(user);
      writeDB(db);
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch(e) {
    console.error('Facebook login error:', e);
    res.status(500).json({ error: 'Facebook login failed. Please try again.' });
  }
});

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
        <h2 style="margin:0;font-size:22px">PrintersReports</h2>
        <p style="margin:6px 0 0;opacity:.8">Password Reset OTP</p>
      </div>
      <div style="background:#f5f8ff;padding:28px;border-radius:0 0 12px 12px">
        <p style="margin:0 0 16px">Hello <strong>${user.name}</strong>,</p>
        <p style="margin:0 0 20px;color:#555">You requested to reset your password. Use this OTP to continue:</p>
        <div style="background:#fff;border:2px solid #00b5d8;border-radius:12px;text-align:center;padding:20px;margin:20px 0">
          <div style="font-size:40px;font-weight:800;letter-spacing:12px;color:#0d2c6b;font-family:monospace">${otp}</div>
          <div style="font-size:13px;color:#888;margin-top:8px">Valid for 10 minutes only</div>
        </div>
        <p style="color:#e53e3e;font-size:13px;margin:0 0 16px">⚠️ Never share this OTP with anyone. PrintersReports will never ask for your OTP.</p>
        <p style="color:#888;font-size:12px">If you did not request this, ignore this email. Your account is safe.</p>
        <hr style="border:none;border-top:1px solid #e2e8f0;margin:20px 0"/>
        <p style="font-size:12px;color:#999;text-align:center">PrintersReports | ${process.env.BUSINESS_ADDRESS || ""} | WhatsApp: ${process.env.WHATSAPP_NUMBER || ""}</p>
      </div>
    </div>`;
    const emailResult = await sendEmail(user.email, 'Your OTP for Password Reset — PrintersReports', emailHtml);
    
    // ALWAYS log OTP to Render console so admin can find it
    console.log('');
    console.log('╔══════════════════════════════════════════╗');
    console.log('║  🔑 PASSWORD RESET OTP                   ║');
    console.log('║  Email  :', user.email);
    console.log('║  OTP    :', otp);
    console.log('║  Expires: 10 minutes from now            ║');
    console.log('╚══════════════════════════════════════════╝');
    console.log('');

    const maskedEmail = user.email.replace(/(.{2})(.*)(@.*)/, '$1****$3');

    if (!emailResult || !emailResult.sent) {
      // Email not configured or failed — tell user clearly
      const reason = emailResult?.reason || 'unknown';
      const isNotConfigured = reason === 'not_configured';
      return res.json({
        message: isNotConfigured
          ? 'OTP generated! Email is not configured yet — please check Render logs for the OTP, or contact admin.'
          : 'OTP generated but email failed to send. Please contact admin on WhatsApp.',
        email_masked: maskedEmail,
        email_sent:   false,
        // For development/testing — show OTP in response if email not configured
        // REMOVE THIS LINE in production once email is working:
        debug_otp: isNotConfigured ? otp : undefined,
      });
    }

    res.json({
      message:      'OTP sent to ' + maskedEmail,
      email_masked: maskedEmail,
      email_sent:   true,
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
    sendEmail(db.users[idx].email, 'Password Changed — PrintersReports',
      `<div style="font-family:Arial;padding:24px;max-width:500px;margin:auto">
        <h2 style="color:#1a4298">Password Changed Successfully</h2>
        <p>Hello ${db.users[idx].name},</p>
        <p>Your password has been changed successfully.</p>
        <p style="color:#e53e3e">If you did not make this change, contact us immediately on WhatsApp: ${process.env.WHATSAPP_NUMBER || "your WhatsApp number"}</p>
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
      return { ...p, category_name:db.categories.find(c=>c.id===p.category_id)?.name||'', image_url:p.image?BASE_URL+p.image:null, avg_rating:avgRating, review_count:revs.length, shipping_charge:p.shipping_charge };
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
    const shippingCharge = req.body.shipping_charge !== undefined && req.body.shipping_charge !== '' ? parseFloat(req.body.shipping_charge) : null;
    const prod = { id:nextId(db.products), name:sanitize(name), description:sanitize(description)||'', sku:sanitize(sku)||'', category_id:category_id?parseInt(category_id):null, price:parseFloat(price), old_price:old_price?parseFloat(old_price):null, stock:parseInt(stock)||0, shipping_charge:shippingCharge, image:req.file?'/uploads/products/'+req.file.filename:null, is_new:is_new==='1', is_bestseller:is_bestseller==='1', is_active:true, created_at:new Date().toISOString() };
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
    const updatedShipping = req.body.shipping_charge !== undefined ? (req.body.shipping_charge===''||req.body.shipping_charge===null?null:parseFloat(req.body.shipping_charge)) : db.products[idx].shipping_charge;
    db.products[idx] = { ...db.products[idx], name:sanitize(name)||db.products[idx].name, description:sanitize(description)??db.products[idx].description, sku:sanitize(sku)??db.products[idx].sku, category_id:category_id?parseInt(category_id):db.products[idx].category_id, price:price?parseFloat(price):db.products[idx].price, old_price:old_price!==undefined?(old_price?parseFloat(old_price):null):db.products[idx].old_price, stock:stock!==undefined?parseInt(stock):db.products[idx].stock, shipping_charge:updatedShipping, image:req.file?'/uploads/products/'+req.file.filename:db.products[idx].image, is_new:is_new==='1', is_bestseller:is_bestseller==='1', is_active:is_active!=='0'&&is_active!==false, updated_at:new Date().toISOString() };
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
// ── GET shipping cost for cart ─────────────────────────────────
app.post('/api/shipping/calculate', (req, res) => {
  try {
    const { items } = req.body;
    if (!items || !items.length) return res.json({ shipping: 0, free: true, message: 'Empty cart' });
    const db       = readDB();
    const settings = db.settings;
    const subtotal = items.reduce((s, i) => {
      const p = db.products.find(p => p.id === i.product_id);
      return s + (p ? p.price * i.qty : 0);
    }, 0);
    const freeMin  = settings.free_shipping_min || 999;
    const shipping = calculateShipping(
      items.map(i => {
        const p = db.products.find(p => p.id === i.product_id);
        return { product_id:i.product_id, qty:i.qty, price:p?.price||0 };
      }),
      db.products,
      settings
    );
    const amountNeededForFree = Math.max(0, freeMin - subtotal);
    res.json({
      shipping,
      free: shipping === 0,
      subtotal,
      free_threshold:     freeMin,
      amount_for_free:    amountNeededForFree,
      default_charge:     settings.default_shipping_charge || 80,
      shipping_message:   settings.shipping_message || ('Free shipping on orders above Rs.' + freeMin),
    });
  } catch(e) { console.error(e); res.status(500).json({ shipping: 0, error: 'Could not calculate' }); }
});

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
    const settings = db.settings;
    const shipping = calculateShipping(validated, db.products, settings);
    const gst      = Math.round(subtotal*0.18*100)/100;
    const total    = Math.round((subtotal+gst+shipping)*100); // paise
    razorpay.orders.create({ amount:total, currency:'INR', receipt:'PPP_'+Date.now(), notes:{ user_id:req.user.id } }, (err, order) => {
      if (err) { console.error('Razorpay error:', err); return res.status(500).json({ error:'Could not create payment: '+(err.error?.description||err.message) }); }
      res.json({ razorpay_order_id:order.id, amount:order.amount, currency:order.currency, key_id:RAZORPAY_KEY_ID, subtotal, gst, shipping, total:subtotal+gst+shipping, validated_items:validated, shipping_address });
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
    const settings = db.settings;
    const shipping  = calculateShipping(resolvedItems, db.products, settings);
    const gst = Math.round(subtotal*0.18*100)/100, total = subtotal+gst+shipping;
    const order_number = 'PPP'+Date.now(), orderId = nextId(db.orders);
    const order = { id:orderId, order_number, user_id:req.user.id, subtotal, gst, shipping, total, shipping_address:JSON.stringify(shipping_address), payment_method:'online', payment_status:'paid', razorpay_order_id, razorpay_payment_id, status:'confirmed', tracking_number:null, tracking_url:null, notes:sanitize(notes)||null, cancel_reason:null, return_requested:false, created_at:new Date().toISOString(), updated_at:new Date().toISOString() };
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
    if (user?.email) sendEmail(user.email, `Order Confirmed — ${order_number} | PrintersReports`, orderConfirmationEmail(order, user, resolvedItems));
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
    const settings = db.settings;
    const shipping  = calculateShipping(resolvedItems, db.products, settings);
    const gst = Math.round(subtotal*0.18*100)/100, total = subtotal+gst+shipping;
    const order_number = 'PPP'+Date.now(), orderId = nextId(db.orders);
    const order = { id:orderId, order_number, user_id:req.user.id, subtotal, gst, shipping, total, shipping_address:JSON.stringify(shipping_address), payment_method:'cod', payment_status:'pending', razorpay_order_id:null, razorpay_payment_id:null, status:'pending', tracking_number:null, tracking_url:null, notes:sanitize(notes)||null, cancel_reason:null, return_requested:false, created_at:new Date().toISOString(), updated_at:new Date().toISOString() };
    db.orders.push(order);
    resolvedItems.forEach(item => {
      db.order_items.push({ id:nextId(db.order_items), order_id:orderId, product_id:item.product_id, qty:item.qty, price:item.price });
      const pi=db.products.findIndex(p=>p.id===item.product_id); if(pi!==-1) db.products[pi].stock -= item.qty;
    });
    logOrderEvent(db, orderId, 'pending', 'COD order placed — awaiting confirmation', 'system');
    writeDB(db);
    const user = db.users.find(u=>u.id===req.user.id);
    if (user?.email) sendEmail(user.email, `Order Placed — ${order_number} | PrintersReports`, orderConfirmationEmail(order, user, resolvedItems));
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
    if (user?.email) sendEmail(user.email, `Order Cancelled — ${order.order_number} | PrintersReports`, orderStatusEmail(order, user, 'cancelled', null));
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
    if (user?.email) sendEmail(user.email, `Return Request — ${order.order_number} | PrintersReports`,
      `<div style="font-family:Arial;padding:24px;max-width:500px;margin:auto">
        <h2 style="color:#1a4298">Return Request Received</h2>
        <p>Hello ${user.name},</p>
        <p>Your return request for order <strong>${order.order_number}</strong> has been received.</p>
        <p>Reason: ${reason}</p>
        <p>Our team will contact you within 24–48 hours to arrange pickup.</p>
        <p style="color:#777">WhatsApp: ${process.env.WHATSAPP_NUMBER || "your WhatsApp number"}</p>
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
    if (user?.email) sendEmail(user.email, `Order ${status.charAt(0).toUpperCase()+status.slice(1)} — ${db.orders[idx].order_number} | PrintersReports`, orderStatusEmail(db.orders[idx], user, status, tracking_number));
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

// ════════════════════════════════════════════════════════════════
//   SMART SEARCH — Live suggestions + trending + search history
// ════════════════════════════════════════════════════════════════

// Track search queries — used for trending/popular searches
function trackSearch(query) {
  try {
    const db = readDB();
    db.search_logs = db.search_logs || [];
    // Only log non-empty searches longer than 2 chars
    if (!query || query.length < 2) return;
    const q = query.toLowerCase().trim();
    const existing = db.search_logs.find(s => s.query === q);
    if (existing) {
      existing.count++;
      existing.last_searched = new Date().toISOString();
    } else {
      db.search_logs.push({ query: q, count: 1, last_searched: new Date().toISOString() });
    }
    // Keep only top 500 search logs
    if (db.search_logs.length > 500) {
      db.search_logs.sort((a,b) => b.count - a.count);
      db.search_logs = db.search_logs.slice(0, 500);
    }
    writeDB(db);
  } catch(e) {}
}

// GET /api/search/suggestions?q=drum
// Returns: matching products + categories + trending searches
app.get('/api/search/suggestions', (req, res) => {
  try {
    const q  = sanitize(req.query.q || '').toLowerCase().trim();
    const db = readDB();

    if (q.length < 1) {
      // No query — return trending searches and popular products
      const trending = (db.search_logs || [])
        .sort((a,b) => b.count - a.count)
        .slice(0, 8)
        .map(s => s.query);

      const popular = db.products
        .filter(p => p.is_active && p.is_bestseller)
        .slice(0, 4)
        .map(p => ({ id:p.id, name:p.name, price:p.price, image_url:p.image?BASE_URL+p.image:null, category:db.categories.find(c=>c.id===p.category_id)?.name||'' }));

      const recent = db.products
        .filter(p => p.is_active)
        .sort((a,b) => new Date(b.created_at) - new Date(a.created_at))
        .slice(0, 4)
        .map(p => ({ id:p.id, name:p.name, price:p.price, image_url:p.image?BASE_URL+p.image:null, category:db.categories.find(c=>c.id===p.category_id)?.name||'' }));

      return res.json({ trending, popular, recent, products:[], categories:[] });
    }

    // Track this search
    trackSearch(q);

    // Match products by name, SKU, description
    const products = db.products
      .filter(p => {
        if (!p.is_active) return false;
        const name = (p.name||'').toLowerCase();
        const sku  = (p.sku||'').toLowerCase();
        const desc = (p.description||'').toLowerCase();
        return name.includes(q) || sku.includes(q) || desc.includes(q) ||
               q.split(' ').every(word => name.includes(word)); // multi-word search
      })
      .slice(0, 6)
      .map(p => ({
        id:       p.id,
        name:     p.name,
        price:    p.price,
        old_price:p.old_price,
        sku:      p.sku,
        image_url:p.image ? BASE_URL+p.image : null,
        category: db.categories.find(c=>c.id===p.category_id)?.name || '',
        stock:    p.stock,
      }));

    // Match categories
    const categories = db.categories
      .filter(c => c.name.toLowerCase().includes(q))
      .slice(0, 3)
      .map(c => ({ id:c.id, name:c.name, slug:c.slug }));

    // Related search suggestions (other searches containing this query)
    const related = (db.search_logs || [])
      .filter(s => s.query.includes(q) && s.query !== q)
      .sort((a,b) => b.count - a.count)
      .slice(0, 5)
      .map(s => s.query);

    res.json({ products, categories, related, trending:[], popular:[], recent:[] });
  } catch(e) { console.error(e); res.status(500).json({ products:[], categories:[], related:[], trending:[] }); }
});

// GET /api/search/trending — top searched terms
app.get('/api/search/trending', (req, res) => {
  try {
    const db = readDB();
    const trending = (db.search_logs || [])
      .sort((a,b) => b.count - a.count)
      .slice(0, 10)
      .map(s => ({ query: s.query, count: s.count }));
    res.json(trending);
  } catch(e) { res.json([]); }
});

// POST /api/search/track — manually track a search (when customer hits enter)
app.post('/api/search/track', (req, res) => {
  trackSearch(sanitize(req.body.query || ''));
  res.json({ ok: true });
});


// ════════════════════════════════════════════════════════════════
//   ADMIN — FULL CONTROL: Delete & Edit Orders, Users, Enquiries
// ════════════════════════════════════════════════════════════════

// ── DELETE single order (admin) ───────────────────────────────
app.delete('/api/admin/orders/:id', adminMiddleware, (req, res) => {
  try {
    const db  = readDB();
    const idx = db.orders.findIndex(o => o.id === parseInt(req.params.id));
    if (idx === -1) return res.status(404).json({ error: 'Order not found' });
    const order = db.orders[idx];
    // Also remove order items and events for this order
    db.order_items  = (db.order_items  || []).filter(i => i.order_id !== order.id);
    db.order_events = (db.order_events || []).filter(e => e.order_id !== order.id);
    db.orders.splice(idx, 1);
    writeDB(db);
    res.json({ message: 'Order #' + order.order_number + ' deleted successfully' });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// ── DELETE ALL orders (admin — nuclear option) ─────────────────
app.delete('/api/admin/orders', adminMiddleware, (req, res) => {
  try {
    const db = readDB();
    const count = db.orders.length;
    db.orders       = [];
    db.order_items  = [];
    db.order_events = [];
    writeDB(db);
    res.json({ message: count + ' orders deleted successfully' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── EDIT order details (admin) — change any field ─────────────
app.put('/api/admin/orders/:id', adminMiddleware, (req, res) => {
  try {
    const db  = readDB();
    const idx = db.orders.findIndex(o => o.id === parseInt(req.params.id));
    if (idx === -1) return res.status(404).json({ error: 'Order not found' });
    const allowed = [
      'status','payment_status','payment_method','tracking_number','tracking_url',
      'shipping_address','notes','cancel_reason','total','subtotal','gst',
    ];
    allowed.forEach(field => {
      if (req.body[field] !== undefined) db.orders[idx][field] = req.body[field];
    });
    db.orders[idx].updated_at = new Date().toISOString();
    if (req.body.note) {
      logOrderEvent(db, db.orders[idx].id, db.orders[idx].status, 'Admin edited: ' + req.body.note, 'admin');
    }
    writeDB(db);
    res.json({ message: 'Order updated', order: db.orders[idx] });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── GET all customers/users (admin) ───────────────────────────
app.get('/api/admin/users', adminMiddleware, (req, res) => {
  try {
    const { page=1, limit=20, search } = req.query;
    const db = readDB();
    let users = db.users.filter(u => u.role !== 'admin');
    if (search) {
      const q = search.toLowerCase();
      users = users.filter(u =>
        (u.name||'').toLowerCase().includes(q) ||
        (u.email||'').toLowerCase().includes(q) ||
        (u.phone||'').includes(q)
      );
    }
    users = users.sort((a,b) => new Date(b.created_at) - new Date(a.created_at));
    // Add order count per user
    const result = users.map(u => {
      const { password, ...safe } = u;
      const orderCount = db.orders.filter(o => o.user_id === u.id).length;
      const totalSpent = db.orders.filter(o => o.user_id===u.id && o.payment_status==='paid').reduce((s,o)=>s+o.total,0);
      return { ...safe, order_count: orderCount, total_spent: totalSpent };
    });
    const total = result.length, offset = (parseInt(page)-1)*parseInt(limit);
    res.json({ users: result.slice(offset, offset+parseInt(limit)), total });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── EDIT customer details (admin) ─────────────────────────────
app.put('/api/admin/users/:id', adminMiddleware, (req, res) => {
  try {
    const db  = readDB();
    const idx = db.users.findIndex(u => u.id === parseInt(req.params.id));
    if (idx === -1) return res.status(404).json({ error: 'User not found' });
    if (db.users[idx].role === 'admin') return res.status(403).json({ error: 'Cannot edit admin account from here' });
    const { name, phone, email } = req.body;
    if (name)  db.users[idx].name  = sanitize(name);
    if (phone) db.users[idx].phone = sanitize(phone);
    if (email) {
      // Check email not taken by another user
      const taken = db.users.find(u => u.email === email.toLowerCase() && u.id !== db.users[idx].id);
      if (taken) return res.status(409).json({ error: 'This email is already used by another account' });
      db.users[idx].email = email.toLowerCase();
    }
    // Admin can also reset password
    if (req.body.new_password) {
      if (req.body.new_password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
      db.users[idx].password = require('bcryptjs').hashSync(req.body.new_password, 12);
    }
    db.users[idx].updated_at = new Date().toISOString();
    writeDB(db);
    const { password, ...safe } = db.users[idx];
    res.json({ message: 'Customer updated', user: safe });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── DELETE customer (admin) ────────────────────────────────────
app.delete('/api/admin/users/:id', adminMiddleware, (req, res) => {
  try {
    const db  = readDB();
    const idx = db.users.findIndex(u => u.id === parseInt(req.params.id));
    if (idx === -1) return res.status(404).json({ error: 'User not found' });
    if (db.users[idx].role === 'admin') return res.status(403).json({ error: 'Cannot delete admin account' });
    const name = db.users[idx].name;
    db.users.splice(idx, 1);
    writeDB(db);
    res.json({ message: 'Customer "' + name + '" deleted' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── GET all enquiries (admin) ──────────────────────────────────
app.get('/api/admin/enquiries', adminMiddleware, (req, res) => {
  const db = readDB();
  const list = (db.enquiries||[]).sort((a,b)=>new Date(b.created_at)-new Date(a.created_at));
  res.json(list);
});

// ── DELETE enquiry (admin) ─────────────────────────────────────
app.delete('/api/admin/enquiries/:id', adminMiddleware, (req, res) => {
  const db  = readDB();
  const idx = (db.enquiries||[]).findIndex(e => e.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Enquiry not found' });
  db.enquiries.splice(idx, 1);
  writeDB(db);
  res.json({ message: 'Enquiry deleted' });
});

// ── Mark enquiry as read (admin) ──────────────────────────────
app.put('/api/admin/enquiries/:id/read', adminMiddleware, (req, res) => {
  const db  = readDB();
  const idx = (db.enquiries||[]).findIndex(e => e.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.enquiries[idx].is_read = true;
  writeDB(db);
  res.json({ message: 'Marked as read' });
});

// ── Admin: reset/clear search logs ────────────────────────────
app.delete('/api/admin/search-logs', adminMiddleware, (req, res) => {
  const db = readDB();
  db.search_logs = [];
  writeDB(db);
  res.json({ message: 'Search history cleared' });
});

// ── Admin: export all data as JSON backup ─────────────────────
app.get('/api/admin/export', adminMiddleware, (req, res) => {
  const db = readDB();
  const exportData = {
    exported_at: new Date().toISOString(),
    orders: db.orders,
    order_items: db.order_items,
    users: db.users.map(u => { const { password, ...safe } = u; return safe; }),
    products: db.products,
    categories: db.categories,
    enquiries: db.enquiries,
  };
  res.setHeader('Content-Disposition', 'attachment; filename="ppp-backup-' + Date.now() + '.json"');
  res.setHeader('Content-Type', 'application/json');
  res.json(exportData);
});


// ════════════════════════════════════════════════════════════════
//   ADMIN PROFILE — Change own name, email, password, phone
// ════════════════════════════════════════════════════════════════

// GET admin's own profile
app.get('/api/admin/profile', adminMiddleware, (req, res) => {
  const db   = readDB();
  const user = db.users.find(u => u.id === req.user.id && u.role === 'admin');
  if (!user) return res.status(404).json({ error: 'Admin not found' });
  const { password, ...safe } = user;
  res.json(safe);
});

// UPDATE admin name, email, phone
app.put('/api/admin/profile', adminMiddleware, (req, res) => {
  try {
    const db  = readDB();
    const idx = db.users.findIndex(u => u.id === req.user.id && u.role === 'admin');
    if (idx === -1) return res.status(404).json({ error: 'Admin not found' });

    const { name, email, phone } = req.body;

    if (name  && name.trim())  db.users[idx].name  = sanitize(name.trim());
    if (phone && phone.trim()) db.users[idx].phone = sanitize(phone.trim());

    if (email && email.trim()) {
      const newEmail = email.trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail)) {
        return res.status(400).json({ error: 'Invalid email address' });
      }
      // Check not taken by another user
      const taken = db.users.find(u => u.email === newEmail && u.id !== req.user.id);
      if (taken) return res.status(409).json({ error: 'This email is already used by another account' });
      db.users[idx].email = newEmail;
    }

    db.users[idx].updated_at = new Date().toISOString();
    writeDB(db);

    const { password, ...safe } = db.users[idx];
    // Return new token so session updates with new email
    const token = require('jsonwebtoken').sign(
      { id: db.users[idx].id, email: db.users[idx].email, role: 'admin' },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    res.json({ message: 'Profile updated successfully', user: safe, token });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// CHANGE admin password — requires current password verification
app.put('/api/admin/password', adminMiddleware, (req, res) => {
  try {
    const { current_password, new_password, confirm_password } = req.body;
    if (!current_password || !new_password) {
      return res.status(400).json({ error: 'Current password and new password are required' });
    }
    if (new_password.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters' });
    }
    if (confirm_password && new_password !== confirm_password) {
      return res.status(400).json({ error: 'New passwords do not match' });
    }
    const db  = readDB();
    const idx = db.users.findIndex(u => u.id === req.user.id && u.role === 'admin');
    if (idx === -1) return res.status(404).json({ error: 'Admin not found' });

    // Verify current password
    if (!require('bcryptjs').compareSync(current_password, db.users[idx].password)) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    // Set new password
    db.users[idx].password    = require('bcryptjs').hashSync(new_password, 12);
    db.users[idx].updated_at  = new Date().toISOString();
    writeDB(db);
    res.json({ message: 'Password changed successfully. Please login again with your new password.' });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/contact', (req, res) => {
  const db=readDB();
  const { name, email, phone, message } = req.body;
  if (!name||!message) return res.status(400).json({ error:'Name and message are required' });
  db.enquiries.push({ id:nextId(db.enquiries), name:sanitize(name), email:sanitize(email)||null, phone:sanitize(phone)||null, message:sanitize(message), is_read:false, created_at:new Date().toISOString() });
  writeDB(db);
  // Notify admin
  if (transporter) sendEmail(EMAIL_USER, 'New Contact Enquiry — PrintersReports', `<p>From: ${name} (${email||'no email'}) — ${phone||'no phone'}</p><p>${message}</p>`);
  res.json({ message:'Enquiry submitted. We will contact you within 24 hours.' });
});

// ════════════════════════════════════════════════════════════════
//   START
// ════════════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║   PrintersReports Production Backend           ║');
  console.log(`║   Running at: http://localhost:${PORT}               ║`);
  console.log('║   Security:   Helmet + Rate Limiting             ║');
  console.log(`║   Razorpay:   ${razorpay ? 'CONFIGURED ✅' : 'NOT configured ⚠️ '}              ║`);
  console.log(`║   Email:      ${transporter ? 'CONFIGURED ✅' : 'NOT configured ⚠️ '}              ║`);
  console.log('╚══════════════════════════════════════════════════╝');
  console.log('');
});