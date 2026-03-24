// ════════════════════════════════════════════════════════════════
//   PrintersReports – Production Backend
//   Images:   Cloudinary (permanent — survives restarts)
//   Database: MongoDB Atlas (permanent — survives restarts)
//   Payments: Razorpay
//   Emails:   Nodemailer
// ════════════════════════════════════════════════════════════════

const express    = require('express');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const multer     = require('multer');
const path       = require('path');
const fs         = require('fs');
const crypto     = require('crypto');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const nodemailer = require('nodemailer');
const Razorpay   = require('razorpay');

const app   = express();
const PORT  = process.env.PORT || 5000;
const JWT_SECRET  = process.env.JWT_SECRET  || 'printersreports_secret_change_in_production';
const BASE_URL    = process.env.BASE_URL    || ('http://localhost:' + PORT);
const DB_FILE     = path.join(__dirname, 'database.json');
const MONGODB_URI = process.env.MONGODB_URI || '';

// ── Razorpay ─────────────────────────────────────────────────
const RAZORPAY_KEY_ID     = process.env.RAZORPAY_KEY_ID     || '';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || '';
let razorpay = null;
try {
  if (RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET) {
    razorpay = new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET });
    console.log('✅ Razorpay configured');
  } else { console.log('⚠️  Razorpay not configured'); }
} catch(e) { console.log('⚠️  Razorpay init failed:', e.message); }

// ── Email ─────────────────────────────────────────────────────
const EMAIL_USER = process.env.EMAIL_USER || '';
const EMAIL_PASS = process.env.EMAIL_PASS || '';
const EMAIL_FROM = process.env.EMAIL_FROM || 'PrintersReports <noreply@printersreports.in>';
let transporter = null;
try {
  if (EMAIL_USER && EMAIL_PASS) {
    transporter = nodemailer.createTransport({ service: 'gmail', auth: { user: EMAIL_USER, pass: EMAIL_PASS } });
    console.log('✅ Email configured');
  } else { console.log('⚠️  Email not configured — add EMAIL_USER and EMAIL_PASS in Render environment'); }
} catch(e) { console.log('⚠️  Email init failed:', e.message); }

// ── Cloudinary — permanent image storage ─────────────────────
// Images uploaded here survive server restarts forever.
// Free tier: 25GB storage, 25GB bandwidth/month — more than enough.
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME || '';
const CLOUDINARY_API_KEY    = process.env.CLOUDINARY_API_KEY    || '';
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET || '';
let cloudinary = null;
try {
  if (CLOUDINARY_CLOUD_NAME && CLOUDINARY_API_KEY && CLOUDINARY_API_SECRET) {
    cloudinary = require('cloudinary').v2;
    cloudinary.config({
      cloud_name: CLOUDINARY_CLOUD_NAME,
      api_key:    CLOUDINARY_API_KEY,
      api_secret: CLOUDINARY_API_SECRET,
    });
    console.log('✅ Cloudinary configured — images are permanent');
  } else {
    console.log('⚠️  Cloudinary not configured — images will reset on restart!');
    console.log('   Add CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET to Render env');
  }
} catch(e) { console.log('⚠️  Cloudinary init failed:', e.message); }

// Upload a file buffer to Cloudinary and return the secure URL
async function uploadToCloudinary(buffer, folder, publicId) {
  if (!cloudinary) return null;
  return new Promise((resolve, reject) => {
    const opts = { folder: 'printersreports/' + folder, resource_type: 'image' };
    if (publicId) opts.public_id = publicId;
    const stream = cloudinary.uploader.upload_stream(opts, (err, result) => {
      if (err) reject(err);
      else resolve(result.secure_url);
    });
    stream.end(buffer);
  });
}

// Delete an image from Cloudinary by URL
async function deleteFromCloudinary(url) {
  if (!cloudinary || !url || !url.includes('cloudinary')) return;
  try {
    // Extract public_id from URL: .../upload/v123/printersreports/products/xyz.jpg
    const match = url.match(/\/upload\/(?:v\d+\/)?(.+)\.[a-z]+$/i);
    if (match) await cloudinary.uploader.destroy(match[1]);
  } catch(e) { console.log('Cloudinary delete warning:', e.message); }
}

// ── SECURITY MIDDLEWARE ──────────────────────────────────────
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' }, contentSecurityPolicy: false }));
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'] }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 20, message: { error: 'Too many attempts. Please try again after 15 minutes.' } });
const apiLimiter  = rateLimit({ windowMs: 60*1000,    max: 100, message: { error: 'Too many requests. Please slow down.' } });
app.use('/api/auth', authLimiter);
app.use('/api', apiLimiter);

// ── FILE UPLOAD — memory storage (for Cloudinary) ────────────
// Files go into memory buffer, then straight to Cloudinary.
// Nothing is saved to local disk, so restarts don't lose images.
const upload     = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: (req, file, cb) => { const ok = ['.jpg','.jpeg','.png','.webp','.gif','.svg']; ok.includes(path.extname(file.originalname).toLowerCase()) ? cb(null,true) : cb(new Error('Only image files allowed')); } });
const uploadLogo = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 }, fileFilter: (req, file, cb) => { const ok = ['.jpg','.jpeg','.png','.webp','.gif','.svg']; ok.includes(path.extname(file.originalname).toLowerCase()) ? cb(null,true) : cb(new Error('Image files only')); } });

// ── DB HELPERS — MongoDB Atlas + in-memory cache ─────────────
let dbCache        = null;
let mongoClient    = null;
let mongoCollection = null;

async function connectMongo() {
  if (!MONGODB_URI) {
    console.log('⚠️  MONGODB_URI not set — data will reset on every restart!');
    return false;
  }
  try {
    const { MongoClient } = require('mongodb');
    // Close old connection if exists
    if (mongoClient) { try { await mongoClient.close(); } catch(e) {} }
    mongoClient = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 10000, connectTimeoutMS: 10000 });
    await mongoClient.connect();
    const db = mongoClient.db('printersreports');
    mongoCollection = db.collection('store');
    // Verify connection works
    await mongoCollection.findOne({ _id: 'ping' });
    console.log('✅ MongoDB Atlas connected — data is permanent');
    return true;
  } catch(e) {
    console.error('❌ MongoDB connection failed:', e.message);
    mongoClient = null;
    mongoCollection = null;
    return false;
  }
}

async function getCollection() {
  // If connected and working, return immediately
  if (mongoCollection) {
    try { await mongoCollection.findOne({ _id: 'ping' }); return mongoCollection; } catch(e) {}
  }
  // Reconnect
  console.log('MongoDB reconnecting...');
  await connectMongo();
  return mongoCollection;
}

async function loadFromMongo() {
  try {
    const col = await getCollection();
    if (!col) return null;
    const doc = await col.findOne({ _id: 'main' });
    if (doc) { const { _id, ...data } = doc; return data; }
    return null;
  } catch(e) { console.error('MongoDB read error:', e.message); return null; }
}

async function saveToMongo(data) {
  try {
    const col = await getCollection();
    if (!col) { console.error('MongoDB not available — save failed'); return false; }
    await col.replaceOne({ _id: 'main' }, { _id: 'main', ...data }, { upsert: true });
    return true;
  } catch(e) {
    console.error('MongoDB write error:', e.message);
    return false;
  }
}

const readDB = () => {
  if (!dbCache) {
    try { dbCache = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch(e) {}
  }
  return dbCache;
};

// writeDB: update memory instantly, save to MongoDB asynchronously
const writeDB = (data) => {
  dbCache = data;
  // Save to MongoDB — retry once if it fails
  saveToMongo(data).then(ok => {
    if (!ok) {
      console.log('MongoDB save failed — retrying in 3s...');
      setTimeout(() => saveToMongo(data).catch(e => console.error('Retry save failed:', e.message)), 3000);
    }
  }).catch(e => console.error('writeDB error:', e.message));
  // Also save to local file as emergency backup
  try { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8'); } catch(e) {}
};

const nextId   = arr => arr.length ? Math.max(...arr.map(r => r.id)) + 1 : 1;
const sanitize = str => typeof str === 'string' ? str.replace(/[<>]/g, '').trim() : str;

// ── Shipping calculator ──────────────────────────────────────
function calculateShipping(items, productsDb, settings) {
  const subtotal      = items.reduce((s, i) => s + i.price * i.qty, 0);
  const freeThreshold = settings.free_shipping_min || 999;
  const defaultCharge = settings.default_shipping_charge !== undefined ? settings.default_shipping_charge : 80;
  if (subtotal >= freeThreshold) return 0;
  if (items.length > 0) {
    const itemCharges = items.map(item => {
      const product = productsDb.find(p => p.id === item.product_id);
      return (product && product.shipping_charge !== null && product.shipping_charge !== undefined) ? product.shipping_charge : defaultCharge;
    });
    return Math.max(...itemCharges);
  }
  return defaultCharge;
}

// ── DATABASE SETUP ───────────────────────────────────────────
function getDefaultDb() {
  const adminHash = bcrypt.hashSync('Admin@1234', 12);
  return {
    settings: {
      logo_url:null, site_name:'PrintersReports', tagline:"India's #1 Printer Reports Store",
      hero_title:"India's #1 Source for Printer Reports",
      hero_subtitle:'Genuine & compatible parts for HP, Canon, Epson, Ricoh, Brother printers.',
      hero_btn_primary:'Shop Now', hero_btn_secondary:'New Arrivals',
      announcement_bar:'Free Shipping on orders above Rs.999 | All Prices Exclusive of 18% GST',
      whatsapp_number:'', whatsapp_banner_text:'For any queries contact us on WhatsApp',
      gst_rate:18, free_shipping_min:999, default_shipping_charge:80,
      shipping_message:'Free shipping on orders above Rs.999',
      show_new_arrivals:true, show_best_sellers:true, show_categories:true,
      footer_address:'', footer_email:'support@printersreports.in',
      working_hours:'Mon-Sat: 10:00 AM - 7:00 PM',
      cancel_window_hours:24, return_window_days:7,
      meta_title:'PrintersReports - Printer Reports India',
      meta_description:'Buy genuine printer reports online in India.',
      nav_links: JSON.stringify([
        { label:'Home',        url:'index.html',               icon:'🏠' },
        { label:'All Products',url:'products.html',            icon:'📦' },
        { label:'Laser Parts', url:'products.html?cat=laser',  icon:'🖨️' },
        { label:'Inkjet Parts',url:'products.html?cat=inkjet', icon:'💧' },
        { label:'Toner Parts', url:'products.html?cat=toner',  icon:'🖤' },
        { label:'Thermal/POS', url:'products.html?cat=thermal',icon:'🧾' },
        { label:'Track Order', url:'track.html',               icon:'📦' },
        { label:'Contact',     url:'contact.html',             icon:'📞' },
      ]),
      social_whatsapp:'', social_facebook:'', social_instagram:'', social_youtube:'',
      footer_tagline:'Your trusted source for genuine printer reports across India.',
      footer_copyright:'2025 PrintersReports. All rights reserved.',
      color_primary:'#0d2c6b', color_secondary:'#1a4298', color_accent:'#00b5d8',
    },
    users: [{ id:1, name:'Admin', email:'admin@printersreports.in', phone:'', password:adminHash, role:'admin', addresses:[], created_at:new Date().toISOString() }],
    categories: [
      { id:1, name:'Laser Printer Parts',      slug:'laser',    sort_order:1 },
      { id:2, name:'DMP Printer Parts',         slug:'dmp',      sort_order:2 },
      { id:3, name:'Inkjet Printer Parts',      slug:'inkjet',   sort_order:3 },
      { id:4, name:'Scanner Parts',             slug:'scanner',  sort_order:4 },
      { id:5, name:'Thermal/POS Printer Parts', slug:'thermal',  sort_order:5 },
      { id:6, name:'Toner Spare Parts',         slug:'toner',    sort_order:6 },
      { id:7, name:'Complete Printer',          slug:'complete', sort_order:7 },
      { id:8, name:'Drum Units',                slug:'drum',     sort_order:8 },
    ],
    products:[], orders:[], order_items:[], order_events:[],
    reviews:[], enquiries:[], wishlists:[], payment_logs:[], search_logs:[],
  };
}

async function setupDatabase() {
  await connectMongo();
  const mongoData = await loadFromMongo();
  if (mongoData && mongoData.users) {
    dbCache = mongoData;
    console.log('✅ Database loaded from MongoDB —', mongoData.products?.length||0, 'products,', mongoData.orders?.length||0, 'orders');
    return;
  }
  if (fs.existsSync(DB_FILE)) {
    try {
      const fileData = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
      dbCache = fileData;
      console.log('✅ Loaded from local file — migrating to MongoDB...');
      await saveToMongo(fileData);
      console.log('✅ Migrated to MongoDB');
      return;
    } catch(e) { console.log('⚠️  Could not read local file:', e.message); }
  }
  const defaultDb = getDefaultDb();
  dbCache = defaultDb;
  await saveToMongo(defaultDb);
  try { fs.writeFileSync(DB_FILE, JSON.stringify(defaultDb, null, 2), 'utf8'); } catch(e) {}
  console.log('✅ Fresh database created');
  console.log('🔑 Admin: admin@printersreports.in / Admin@1234');
}

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

// ── EMAIL HELPERS ─────────────────────────────────────────────
async function sendEmail(to, subject, html) {
  if (!transporter) return { sent: false, reason: 'not_configured' };
  try { await transporter.sendMail({ from: EMAIL_FROM, to, subject, html }); console.log('📧 Email sent to:', to); return { sent: true }; }
  catch(e) { console.log('📧 Email FAILED to:', to, '|', e.message); return { sent: false, reason: e.message }; }
}

function orderConfirmationEmail(order, user, items) {
  const itemRows = items.map(i =>
    `<tr><td style="padding:8px;border-bottom:1px solid #eee">${i.name}</td>
     <td style="padding:8px;border-bottom:1px solid #eee;text-align:center">${i.qty}</td>
     <td style="padding:8px;border-bottom:1px solid #eee;text-align:right">Rs.${(i.price*i.qty).toLocaleString('en-IN')}</td></tr>`
  ).join('');
  let addr = {};
  try { addr = JSON.parse(order.shipping_address); } catch(e) {}
  return `<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
    <div style="background:#1a4298;color:#fff;padding:24px;text-align:center"><h1 style="margin:0">PrintersReports</h1><p style="margin:8px 0 0;opacity:.8">Order Confirmation</p></div>
    <div style="padding:24px;background:#f5f8ff">
      <div style="background:#fff;border-radius:12px;padding:24px;margin-bottom:16px">
        <h2 style="color:#0d2c6b;margin:0 0 16px">Hello ${user.name},</h2>
        <p>Your order has been ${order.payment_status==='paid'?'<strong style="color:#22c55e">confirmed</strong>':'placed'}.</p>
        <div style="background:#f0f4fb;border-radius:8px;padding:16px;margin:16px 0"><strong>Order: ${order.order_number}</strong></div>
        <table style="width:100%;border-collapse:collapse">
          <thead><tr style="background:#0d2c6b;color:#fff"><th style="padding:10px;text-align:left">Item</th><th style="padding:10px;text-align:center">Qty</th><th style="padding:10px;text-align:right">Price</th></tr></thead>
          <tbody>${itemRows}</tbody>
          <tfoot>
            <tr><td colspan="2" style="padding:8px;text-align:right;color:#777">Subtotal</td><td style="padding:8px;text-align:right">Rs.${order.subtotal.toLocaleString('en-IN',{minimumFractionDigits:2})}</td></tr>
            <tr><td colspan="2" style="padding:8px;text-align:right;color:#777">GST @18%</td><td style="padding:8px;text-align:right">Rs.${order.gst.toLocaleString('en-IN',{minimumFractionDigits:2})}</td></tr>
            <tr><td colspan="2" style="padding:8px;text-align:right;font-weight:bold">Total</td><td style="padding:8px;text-align:right;font-weight:bold;color:#e53e3e">Rs.${order.total.toLocaleString('en-IN',{minimumFractionDigits:2})}</td></tr>
          </tfoot>
        </table>
      </div>
      <div style="background:#fff;border-radius:12px;padding:16px;margin-bottom:16px">
        <h3 style="margin:0 0 8px;color:#0d2c6b">Shipping Address</h3>
        <p style="margin:0;color:#555">${addr.name} | ${addr.phone}<br/>${addr.line}, ${addr.city}, ${addr.state} – ${addr.pin}</p>
      </div>
    </div></div>`;
}

function orderStatusEmail(order, user, newStatus, trackingNumber) {
  const msg = { confirmed:'Your order has been confirmed.', processing:'Your order is being packed.', shipped:'Your order has been shipped!'+(trackingNumber?` Tracking: <strong>${trackingNumber}</strong>`:''), delivered:'Your order has been delivered. Thank you!', cancelled:'Your order has been cancelled.' };
  return `<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
    <div style="background:#1a4298;color:#fff;padding:24px;text-align:center"><h1 style="margin:0">PrintersReports</h1></div>
    <div style="padding:24px;background:#f5f8ff"><div style="background:#fff;border-radius:12px;padding:24px">
      <h2 style="color:#0d2c6b">Order Update</h2>
      <p>Hello ${user.name},</p><p>${msg[newStatus]||'Your order status has been updated.'}</p>
      <div style="background:#f0f4fb;border-radius:8px;padding:16px"><strong>Order: ${order.order_number}</strong><br/><strong>Status: ${newStatus.toUpperCase()}</strong></div>
    </div></div></div>`;
}

function logOrderEvent(db, orderId, status, note, actorRole) {
  db.order_events = db.order_events || [];
  db.order_events.push({ id:nextId(db.order_events), order_id:orderId, status, note:note||'', actor:actorRole||'system', created_at:new Date().toISOString() });
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

// ── Logo upload — goes to Cloudinary, not local disk ──────────
app.post('/api/settings/logo', adminMiddleware, uploadLogo.single('logo'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No logo file uploaded' });
    const db = readDB();

    // Delete old logo from Cloudinary if it was a Cloudinary URL
    if (db.settings.logo_url && db.settings.logo_url.includes('cloudinary')) {
      await deleteFromCloudinary(db.settings.logo_url);
    }

    let logoUrl;
    if (cloudinary) {
      // Upload to Cloudinary with fixed public_id so it overwrites
      logoUrl = await uploadToCloudinary(req.file.buffer, 'logo', 'site_logo');
      if (!logoUrl) return res.status(500).json({ error: 'Cloudinary upload failed. Add CLOUDINARY credentials to Render.' });
    } else {
      // Fallback: save locally (will reset on restart — add Cloudinary to fix permanently)
      const dir = path.join(__dirname, 'uploads', 'logo');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const ext = path.extname(req.file.originalname).toLowerCase();
      const filename = 'logo' + ext;
      fs.writeFileSync(path.join(dir, filename), req.file.buffer);
      logoUrl = '/uploads/logo/' + filename;
    }

    db.settings.logo_url = logoUrl;
    writeDB(db);
    res.json({ message: 'Logo uploaded', logo_url: logoUrl.startsWith('http') ? logoUrl : BASE_URL + logoUrl });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Upload failed: ' + e.message }); }
});

app.delete('/api/settings/logo', adminMiddleware, async (req, res) => {
  const db = readDB();
  if (db.settings.logo_url) {
    await deleteFromCloudinary(db.settings.logo_url);
    // Also try local file
    try { const p = path.join(__dirname, db.settings.logo_url); if (fs.existsSync(p)) fs.unlinkSync(p); } catch(e) {}
    db.settings.logo_url = null;
    writeDB(db);
  }
  res.json({ message: 'Logo removed' });
});

// ════════════════════════════════════════════════════════════════
//   AUTH
// ════════════════════════════════════════════════════════════════
const otpStore = new Map();

app.post('/api/auth/register', async (req, res) => {
  try {
    const name = sanitize(req.body.name), email = sanitize(req.body.email)?.toLowerCase(), phone = sanitize(req.body.phone), password = req.body.password;
    if (!name||!email||!password) return res.status(400).json({ error:'Name, email and password are required' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error:'Invalid email address' });
    if (password.length < 8) return res.status(400).json({ error:'Password must be at least 8 characters' });
    if (phone && !/^\d{10}$/.test(phone)) return res.status(400).json({ error:'Phone must be 10 digits' });
    const db = readDB();
    if (db.users.find(u => u.email === email)) return res.status(409).json({ error:'This email is already registered. Please login.' });
    const user = { id:nextId(db.users), name, email, phone:phone||null, password:bcrypt.hashSync(password,12), role:'customer', addresses:[], created_at:new Date().toISOString() };
    db.users.push(user); writeDB(db);
    const token = jwt.sign({ id:user.id, email, role:'customer' }, JWT_SECRET, { expiresIn:'30d' });
    res.json({ message:'Account created successfully', token, user:{ id:user.id, name, email, role:'customer' } });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error. Please try again.' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = sanitize(req.body.email)?.toLowerCase(), password = req.body.password;
    if (!email||!password) return res.status(400).json({ error:'Email and password are required' });
    const db = readDB(), user = db.users.find(u => u.email === email);
    if (!user) return res.status(401).json({ error:'No account found with this email. Please register first.' });
    if (!user.password) return res.status(401).json({ error:'This account was created with Google or Facebook. Please use those buttons to sign in.' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error:'Incorrect password. Please try again.' });
    const token = jwt.sign({ id:user.id, email:user.email, role:user.role }, JWT_SECRET, { expiresIn:'30d' });
    res.json({ token, user:{ id:user.id, name:user.name, email:user.email, role:user.role } });
  } catch(e) { res.status(500).json({ error:'Server error. Please try again.' }); }
});

app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'No Google credential provided' });
    const googleRes = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + credential);
    const googleData = await googleRes.json();
    if (!googleRes.ok || googleData.error) return res.status(401).json({ error: 'Invalid Google token. Please try again.' });
    const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
    if (GOOGLE_CLIENT_ID && googleData.aud !== GOOGLE_CLIENT_ID) return res.status(401).json({ error: 'Google token audience mismatch.' });
    const email = googleData.email, name = googleData.name || googleData.email.split('@')[0], googleId = googleData.sub;
    if (!email) return res.status(400).json({ error: 'Could not get email from Google account' });
    const db = readDB();
    let user = db.users.find(u => u.email === email);
    if (user) { const idx = db.users.findIndex(u => u.email === email); if (!db.users[idx].google_id) { db.users[idx].google_id = googleId; writeDB(db); } user = db.users[idx]; }
    else { user = { id:nextId(db.users), name:sanitize(name), email:email.toLowerCase(), phone:null, password:null, google_id:googleId, role:'customer', addresses:[], created_at:new Date().toISOString() }; db.users.push(user); writeDB(db); }
    const token = jwt.sign({ id:user.id, email:user.email, role:user.role }, JWT_SECRET, { expiresIn:'30d' });
    res.json({ token, user:{ id:user.id, name:user.name, email:user.email, role:user.role } });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Google login failed. Please try again.' }); }
});

app.post('/api/auth/facebook', async (req, res) => {
  try {
    const { accessToken, userID } = req.body;
    if (!accessToken || !userID) return res.status(400).json({ error: 'No Facebook token provided' });
    const FACEBOOK_APP_ID = process.env.FACEBOOK_APP_ID||'', FACEBOOK_APP_SECRET = process.env.FACEBOOK_APP_SECRET||'';
    let verifyUrl = 'https://graph.facebook.com/debug_token?input_token=' + accessToken;
    if (FACEBOOK_APP_ID && FACEBOOK_APP_SECRET) verifyUrl += '&access_token=' + FACEBOOK_APP_ID + '|' + FACEBOOK_APP_SECRET;
    const verifyRes = await fetch(verifyUrl), verifyData = await verifyRes.json();
    if (!verifyData.data || !verifyData.data.is_valid) return res.status(401).json({ error: 'Invalid Facebook token. Please try again.' });
    const fbUserRes = await fetch('https://graph.facebook.com/' + userID + '?fields=id,name,email&access_token=' + accessToken);
    const fbUserData = await fbUserRes.json();
    if (!fbUserData.email) return res.status(400).json({ error: 'Facebook account does not have a public email.' });
    const email = fbUserData.email, name = fbUserData.name||email.split('@')[0], facebookId = fbUserData.id;
    const db = readDB();
    let user = db.users.find(u => u.email === email);
    if (user) { const idx = db.users.findIndex(u => u.email === email); if (!db.users[idx].facebook_id) { db.users[idx].facebook_id = facebookId; writeDB(db); } user = db.users[idx]; }
    else { user = { id:nextId(db.users), name:sanitize(name), email:email.toLowerCase(), phone:null, password:null, facebook_id:facebookId, role:'customer', addresses:[], created_at:new Date().toISOString() }; db.users.push(user); writeDB(db); }
    const token = jwt.sign({ id:user.id, email:user.email, role:user.role }, JWT_SECRET, { expiresIn:'30d' });
    res.json({ token, user:{ id:user.id, name:user.name, email:user.email, role:user.role } });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Facebook login failed. Please try again.' }); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const input = sanitize(req.body.email_or_phone || '').toLowerCase().trim();
    if (!input) return res.status(400).json({ error: 'Please enter your email address or phone number' });
    const db = readDB(), user = db.users.find(u => u.email === input || u.email === input.toLowerCase() || (u.phone && u.phone === input.replace(/\D/g,'').slice(-10)));
    if (!user) return res.json({ message: 'If this account exists, an OTP has been sent to the registered email.' });
    if (!user.email) return res.status(400).json({ error: 'No email address linked to this account.' });
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore.set(user.email, { otp, expires: Date.now() + 10*60*1000, userId: user.id, name: user.name });
    const emailHtml = `<div style="font-family:Arial,sans-serif;max-width:500px;margin:auto"><div style="background:#1a4298;color:#fff;padding:24px;text-align:center;border-radius:12px 12px 0 0"><h2 style="margin:0">PrintersReports</h2><p style="margin:6px 0 0;opacity:.8">Password Reset OTP</p></div><div style="background:#f5f8ff;padding:28px;border-radius:0 0 12px 12px"><p>Hello <strong>${user.name}</strong>,</p><div style="background:#fff;border:2px solid #00b5d8;border-radius:12px;text-align:center;padding:20px;margin:20px 0"><div style="font-size:40px;font-weight:800;letter-spacing:12px;color:#0d2c6b;font-family:monospace">${otp}</div><div style="font-size:13px;color:#888;margin-top:8px">Valid for 10 minutes only</div></div><p style="color:#e53e3e;font-size:13px">⚠️ Never share this OTP with anyone.</p></div></div>`;
    const emailResult = await sendEmail(user.email, 'Your OTP for Password Reset — PrintersReports', emailHtml);
    console.log('\n🔑 PASSWORD RESET OTP — Email:', user.email, '| OTP:', otp, '\n');
    const maskedEmail = user.email.replace(/(.{2})(.*)(@.*)/, '$1****$3');
    if (!emailResult || !emailResult.sent) {
      const isNotConfigured = emailResult?.reason === 'not_configured';
      return res.json({ message: isNotConfigured ? 'OTP generated! Check Render logs for the OTP.' : 'OTP generated but email failed.', email_masked: maskedEmail, email_sent: false, debug_otp: isNotConfigured ? otp : undefined });
    }
    res.json({ message: 'OTP sent to ' + maskedEmail, email_masked: maskedEmail, email_sent: true });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

app.post('/api/auth/verify-otp', (req, res) => {
  try {
    const input = sanitize(req.body.email_or_phone || '').toLowerCase().trim(), otp = sanitize(req.body.otp || '').trim();
    if (!input || !otp) return res.status(400).json({ error: 'Email and OTP are required' });
    const db = readDB(), user = db.users.find(u => u.email === input || (u.phone && u.phone === input.replace(/\D/g,'').slice(-10)));
    if (!user) return res.status(400).json({ error: 'Account not found' });
    const record = otpStore.get(user.email);
    if (!record) return res.status(400).json({ error: 'OTP not found. Please request a new OTP.' });
    if (Date.now() > record.expires) { otpStore.delete(user.email); return res.status(400).json({ error: 'OTP has expired. Please request a new OTP.' }); }
    if (record.otp !== otp) return res.status(400).json({ error: 'Incorrect OTP. Please try again.' });
    const resetToken = jwt.sign({ id:user.id, email:user.email, purpose:'reset' }, JWT_SECRET, { expiresIn:'15m' });
    otpStore.delete(user.email);
    res.json({ message: 'OTP verified', reset_token: resetToken });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/auth/reset-password', (req, res) => {
  try {
    const { reset_token, new_password } = req.body;
    if (!reset_token || !new_password) return res.status(400).json({ error: 'Reset token and new password are required' });
    if (new_password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    let decoded;
    try { decoded = jwt.verify(reset_token, JWT_SECRET); } catch(e) { return res.status(400).json({ error: 'Reset link has expired.' }); }
    if (decoded.purpose !== 'reset') return res.status(400).json({ error: 'Invalid reset token' });
    const db = readDB(), idx = db.users.findIndex(u => u.id === decoded.id);
    if (idx === -1) return res.status(404).json({ error: 'Account not found' });
    db.users[idx].password = bcrypt.hashSync(new_password, 12); db.users[idx].updated_at = new Date().toISOString();
    writeDB(db);
    res.json({ message: 'Password changed successfully! You can now login with your new password.' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ════════════════════════════════════════════════════════════════
//   PRODUCTS — images go to Cloudinary
// ════════════════════════════════════════════════════════════════
app.get('/api/products', (req, res) => {
  try {
    const { cat, search, sort, page=1, limit=12, new:isNew, bestseller } = req.query;
    const db = readDB();
    let list = db.products.filter(p => p.is_active);
    if (cat && cat !== 'all') { const c = db.categories.find(c => c.slug === cat); if (c) list = list.filter(p => p.category_id === c.id); }
    if (search) { const q = sanitize(search).toLowerCase(); list = list.filter(p => p.name.toLowerCase().includes(q)||(p.sku||'').toLowerCase().includes(q)||(p.description||'').toLowerCase().includes(q)); }
    if (isNew === '1') list = list.filter(p => p.is_new);
    if (bestseller === '1') list = list.filter(p => p.is_bestseller);
    const sortFns = { price_asc:(a,b)=>a.price-b.price, price_desc:(a,b)=>b.price-a.price, name:(a,b)=>a.name.localeCompare(b.name) };
    list.sort(sortFns[sort] || ((a,b) => new Date(b.created_at)-new Date(a.created_at)));
    list = list.map(p => {
      const revs = (db.reviews||[]).filter(r => r.product_id === p.id && r.approved);
      const avgRating = revs.length ? (revs.reduce((s,r) => s+r.rating,0)/revs.length).toFixed(1) : null;
      // image_url: if Cloudinary URL (starts with https) return as-is, else prepend BASE_URL
      const image_url = p.image ? (p.image.startsWith('http') ? p.image : BASE_URL+p.image) : null;
      return { ...p, category_name:db.categories.find(c=>c.id===p.category_id)?.name||'', image_url, avg_rating:avgRating, review_count:revs.length };
    });
    const total = list.length, offset = (parseInt(page)-1)*parseInt(limit);
    res.json({ products:list.slice(offset,offset+parseInt(limit)), total, page:parseInt(page), limit:parseInt(limit) });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.get('/api/products/:id', (req, res) => {
  const db = readDB(), p = db.products.find(p => p.id===parseInt(req.params.id) && p.is_active);
  if (!p) return res.status(404).json({ error:'Product not found' });
  const revs = (db.reviews||[]).filter(r => r.product_id===p.id && r.approved);
  const avgRating = revs.length ? (revs.reduce((s,r)=>s+r.rating,0)/revs.length).toFixed(1) : null;
  const image_url = p.image ? (p.image.startsWith('http') ? p.image : BASE_URL+p.image) : null;
  res.json({ ...p, category_name:db.categories.find(c=>c.id===p.category_id)?.name||'', image_url, avg_rating:avgRating, review_count:revs.length, reviews:revs.slice(0,10) });
});

app.post('/api/products', adminMiddleware, upload.single('image'), async (req, res) => {
  try {
    const db = readDB();
    const { name, description, sku, category_id, price, old_price, stock, is_new, is_bestseller } = req.body;
    if (!name || !price) return res.status(400).json({ error:'Name and price are required' });
    const shippingCharge = req.body.shipping_charge !== undefined && req.body.shipping_charge !== '' ? parseFloat(req.body.shipping_charge) : null;

    let imageUrl = null;
    if (req.file) {
      if (cloudinary) {
        imageUrl = await uploadToCloudinary(req.file.buffer, 'products', null);
      } else {
        // Fallback to local if Cloudinary not set up
        const dir = path.join(__dirname, 'uploads', 'products');
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        const ext = path.extname(req.file.originalname).toLowerCase();
        const filename = Date.now() + '-' + Math.round(Math.random()*1e9) + ext;
        fs.writeFileSync(path.join(dir, filename), req.file.buffer);
        imageUrl = '/uploads/products/' + filename;
      }
    }

    const prod = { id:nextId(db.products), name:sanitize(name), description:sanitize(description)||'', sku:sanitize(sku)||'', category_id:category_id?parseInt(category_id):null, price:parseFloat(price), old_price:old_price?parseFloat(old_price):null, stock:parseInt(stock)||0, shipping_charge:shippingCharge, image:imageUrl, is_new:is_new==='1', is_bestseller:is_bestseller==='1', is_active:true, created_at:new Date().toISOString() };
    db.products.push(prod); writeDB(db);
    res.json({ message:'Product added', id:prod.id, product:prod });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.put('/api/products/:id', adminMiddleware, upload.single('image'), async (req, res) => {
  try {
    const db = readDB(), idx = db.products.findIndex(p => p.id===parseInt(req.params.id));
    if (idx===-1) return res.status(404).json({ error:'Product not found' });

    let imageUrl = db.products[idx].image;
    if (req.file) {
      // Delete old image from Cloudinary
      if (db.products[idx].image) await deleteFromCloudinary(db.products[idx].image);
      if (cloudinary) {
        imageUrl = await uploadToCloudinary(req.file.buffer, 'products', null);
      } else {
        const dir = path.join(__dirname, 'uploads', 'products');
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        const ext = path.extname(req.file.originalname).toLowerCase();
        const filename = Date.now() + '-' + Math.round(Math.random()*1e9) + ext;
        fs.writeFileSync(path.join(dir, filename), req.file.buffer);
        imageUrl = '/uploads/products/' + filename;
      }
    }

    const { name, description, sku, category_id, price, old_price, stock, is_new, is_bestseller, is_active } = req.body;
    const updatedShipping = req.body.shipping_charge !== undefined ? (req.body.shipping_charge===''||req.body.shipping_charge===null?null:parseFloat(req.body.shipping_charge)) : db.products[idx].shipping_charge;
    db.products[idx] = { ...db.products[idx], name:sanitize(name)||db.products[idx].name, description:sanitize(description)??db.products[idx].description, sku:sanitize(sku)??db.products[idx].sku, category_id:category_id?parseInt(category_id):db.products[idx].category_id, price:price?parseFloat(price):db.products[idx].price, old_price:old_price!==undefined?(old_price?parseFloat(old_price):null):db.products[idx].old_price, stock:stock!==undefined?parseInt(stock):db.products[idx].stock, shipping_charge:updatedShipping, image:imageUrl, is_new:is_new==='1', is_bestseller:is_bestseller==='1', is_active:is_active!=='0'&&is_active!==false, updated_at:new Date().toISOString() };
    writeDB(db);
    res.json({ message:'Product updated', product:db.products[idx] });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.delete('/api/products/:id', adminMiddleware, async (req, res) => {
  try {
    const db=readDB(), idx=db.products.findIndex(p=>p.id===parseInt(req.params.id));
    if (idx===-1) return res.status(404).json({ error:'Product not found' });
    await deleteFromCloudinary(db.products[idx].image);
    db.products.splice(idx,1); writeDB(db);
    res.json({ message:'Product deleted' });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.delete('/api/products/:id/image', adminMiddleware, async (req, res) => {
  const db=readDB(), idx=db.products.findIndex(p=>p.id===parseInt(req.params.id));
  if (idx===-1) return res.status(404).json({ error:'Not found' });
  if (db.products[idx].image) { await deleteFromCloudinary(db.products[idx].image); db.products[idx].image=null; writeDB(db); }
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
    const db = readDB(), product = db.products.find(p => p.id===parseInt(req.params.id));
    if (!product) return res.status(404).json({ error:'Product not found' });
    const userOrders = db.orders.filter(o => o.user_id===req.user.id && o.status==='delivered');
    const boughtProduct = userOrders.some(o => (db.order_items||[]).some(i => i.order_id===o.id && i.product_id===product.id));
    if (!boughtProduct) return res.status(403).json({ error:'You can only review products you have purchased and received' });
    db.reviews = db.reviews || [];
    if (db.reviews.find(r => r.product_id===product.id && r.user_id===req.user.id)) return res.status(409).json({ error:'You have already reviewed this product' });
    const user = db.users.find(u => u.id===req.user.id);
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
app.post('/api/shipping/calculate', (req, res) => {
  try {
    const { items } = req.body;
    if (!items || !items.length) return res.json({ shipping: 0, free: true, message: 'Empty cart' });
    const db = readDB(), settings = db.settings;
    const subtotal = items.reduce((s, i) => { const p = db.products.find(p => p.id === i.product_id); return s + (p ? p.price * i.qty : 0); }, 0);
    const freeMin = settings.free_shipping_min || 999;
    const shipping = calculateShipping(items.map(i => { const p = db.products.find(p => p.id === i.product_id); return { product_id:i.product_id, qty:i.qty, price:p?.price||0 }; }), db.products, settings);
    res.json({ shipping, free: shipping === 0, subtotal, free_threshold:freeMin, amount_for_free:Math.max(0,freeMin-subtotal), default_charge:settings.default_shipping_charge||80, shipping_message:settings.shipping_message||('Free shipping on orders above Rs.'+freeMin) });
  } catch(e) { console.error(e); res.status(500).json({ shipping: 0, error: 'Could not calculate' }); }
});

app.post('/api/payment/create-order', authMiddleware, (req, res) => {
  try {
    if (!razorpay) return res.status(503).json({ error:'Payment gateway not configured. Please use COD.' });
    const { items, shipping_address } = req.body;
    if (!items?.length) return res.status(400).json({ error:'No items in cart' });
    const db = readDB(); let subtotal = 0; const validated = [];
    for (const item of items) {
      const p = db.products.find(p => p.id===item.product_id && p.is_active);
      if (!p) return res.status(400).json({ error:`Product not found: ${item.product_id}` });
      if (p.stock < item.qty) return res.status(400).json({ error:`Only ${p.stock} units available for: ${p.name}` });
      subtotal += p.price * item.qty;
      validated.push({ product_id:item.product_id, qty:item.qty, price:p.price, name:p.name });
    }
    const settings = db.settings, shipping = calculateShipping(validated, db.products, settings);
    const gstRate = parseFloat(db.settings.gst_rate)||18, gst = Math.round(subtotal*gstRate/100*100)/100;
    const grandTotal = subtotal+gst+shipping, amountPaise = Math.max(100, Math.round(grandTotal*100));
    razorpay.orders.create({ amount:amountPaise, currency:'INR', receipt:'PPP_'+Date.now(), notes:{ user_id:req.user.id } }, (err, order) => {
      if (err) { console.error('Razorpay error:', JSON.stringify(err)); return res.status(500).json({ error:'Could not create payment: '+(err.error?.description||err.message) }); }
      res.json({ razorpay_order_id:order.id, amount:order.amount, currency:order.currency, key_id:RAZORPAY_KEY_ID, subtotal, gst, shipping, total:grandTotal, validated_items:validated, shipping_address });
    });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.post('/api/payment/verify', authMiddleware, async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, items, shipping_address, notes } = req.body;
    if (!razorpay_order_id || !razorpay_payment_id) return res.status(400).json({ error: 'Missing payment details. Payment ID: '+(razorpay_payment_id||'unknown') });
    const dbCheck = readDB();
    const existingOrder = dbCheck.orders.find(o => o.razorpay_payment_id === razorpay_payment_id);
    if (existingOrder) return res.json({ success:true, message:'Order already confirmed!', order_id:existingOrder.id, order_number:existingOrder.order_number, total:existingOrder.total });
    let signatureValid = false;
    if (razorpay_signature && RAZORPAY_KEY_SECRET) {
      const expected = crypto.createHmac('sha256', RAZORPAY_KEY_SECRET).update(razorpay_order_id+'|'+razorpay_payment_id).digest('hex');
      signatureValid = (expected === razorpay_signature);
      console.log('Signature check:', signatureValid ? '✅ VALID' : '❌ MISMATCH', '| payment:', razorpay_payment_id);
    }
    if (!signatureValid) {
      if (!razorpay) return res.status(503).json({ error: 'Payment gateway not configured. Payment ID: '+razorpay_payment_id });
      try {
        const payment = await razorpay.payments.fetch(razorpay_payment_id);
        if (!payment || (payment.status !== 'captured' && payment.status !== 'authorized') || payment.order_id !== razorpay_order_id) {
          return res.status(400).json({ error: 'Payment not verified. Status: '+(payment?.status||'unknown')+'. Payment ID: '+razorpay_payment_id });
        }
        console.log('✅ Payment verified via Razorpay API');
      } catch(apiErr) {
        console.error('Razorpay API verify failed:', apiErr.message);
        return res.status(400).json({ error: 'Payment verification failed. Payment ID: '+razorpay_payment_id+'. Please WhatsApp us — we will confirm manually.' });
      }
    }
    const db = readDB(); let subtotal = 0; const resolvedItems = [];
    for (const item of items) {
      const p = db.products.find(p => p.id === item.product_id && p.is_active);
      if (!p) return res.status(400).json({ error: 'Product not found during order creation' });
      subtotal += p.price * item.qty;
      resolvedItems.push({ product_id:item.product_id, qty:item.qty, price:p.price, name:p.name, image:p.image?(p.image.startsWith('http')?p.image:BASE_URL+p.image):null });
    }
    const settings = db.settings, shipping = calculateShipping(resolvedItems, db.products, settings);
    const gst = Math.round(subtotal*0.18*100)/100, total = subtotal+gst+shipping;
    const order_number = 'PPP'+Date.now(), orderId = nextId(db.orders);
    const order = { id:orderId, order_number, user_id:req.user.id, subtotal, gst, shipping, total, shipping_address:JSON.stringify(shipping_address), payment_method:'online', payment_status:'paid', razorpay_order_id, razorpay_payment_id, status:'confirmed', tracking_number:null, tracking_url:null, notes:sanitize(notes)||null, cancel_reason:null, return_requested:false, created_at:new Date().toISOString(), updated_at:new Date().toISOString() };
    db.orders.push(order);
    resolvedItems.forEach(item => { db.order_items.push({ id:nextId(db.order_items), order_id:orderId, product_id:item.product_id, qty:item.qty, price:item.price }); const pi=db.products.findIndex(p=>p.id===item.product_id); if(pi!==-1) db.products[pi].stock -= item.qty; });
    db.payment_logs.push({ razorpay_order_id, razorpay_payment_id, amount:total, user_id:req.user.id, created_at:new Date().toISOString() });
    logOrderEvent(db, orderId, 'confirmed', 'Order confirmed — online payment received via Razorpay', 'system');
    writeDB(db);
    const user = db.users.find(u => u.id === req.user.id);
    if (user?.email) sendEmail(user.email, `Order Confirmed — ${order_number} | PrintersReports`, orderConfirmationEmail(order, user, resolvedItems));
    console.log('✅ Order created:', order_number, '| total: Rs.', total);
    res.json({ success:true, message:'Payment verified. Order confirmed!', order_id:orderId, order_number, total });
  } catch(e) { console.error('verify endpoint error:', e); res.status(500).json({ error:'Order creation failed: '+e.message }); }
});

app.post('/api/payment/recover', authMiddleware, async (req, res) => {
  try {
    const { razorpay_payment_id, items, shipping_address } = req.body;
    if (!razorpay_payment_id) return res.status(400).json({ error: 'Payment ID required' });
    const db = readDB();
    const existing = db.orders.find(o => o.razorpay_payment_id === razorpay_payment_id);
    if (existing) return res.json({ success:true, message:'Order already exists!', order_number:existing.order_number, order_id:existing.id });
    if (!razorpay) return res.status(503).json({ error: 'Payment gateway not configured' });
    const payment = await razorpay.payments.fetch(razorpay_payment_id);
    if (!payment || (payment.status !== 'captured' && payment.status !== 'authorized')) return res.status(400).json({ error: 'Payment not found or not captured. ID: '+razorpay_payment_id });
    let subtotal = 0; const resolvedItems = [];
    for (const item of (items||[])) {
      const p = db.products.find(p => p.id === item.product_id && p.is_active);
      if (!p) continue;
      subtotal += p.price * item.qty;
      resolvedItems.push({ product_id:item.product_id, qty:item.qty, price:p.price, name:p.name, image:p.image?(p.image.startsWith('http')?p.image:BASE_URL+p.image):null });
    }
    if (!resolvedItems.length) return res.status(400).json({ error: 'Could not recover items. Contact admin with payment ID: '+razorpay_payment_id });
    const settings = db.settings, shipping = calculateShipping(resolvedItems, db.products, settings);
    const gst = Math.round(subtotal*0.18*100)/100, total = subtotal+gst+shipping;
    const order_number = 'PPP'+Date.now(), orderId = nextId(db.orders);
    const order = { id:orderId, order_number, user_id:req.user.id, subtotal, gst, shipping, total, shipping_address:JSON.stringify(shipping_address||{}), payment_method:'online', payment_status:'paid', razorpay_order_id:payment.order_id, razorpay_payment_id, status:'confirmed', tracking_number:null, tracking_url:null, notes:'Order recovered after payment verification', cancel_reason:null, return_requested:false, created_at:new Date().toISOString(), updated_at:new Date().toISOString() };
    db.orders.push(order);
    resolvedItems.forEach(item => { db.order_items.push({ id:nextId(db.order_items), order_id:orderId, product_id:item.product_id, qty:item.qty, price:item.price }); const pi=db.products.findIndex(p=>p.id===item.product_id); if(pi!==-1) db.products[pi].stock-=item.qty; });
    logOrderEvent(db, orderId, 'confirmed', 'Order recovered — Razorpay payment '+razorpay_payment_id+' verified via API', 'system');
    writeDB(db);
    const user = db.users.find(u => u.id === req.user.id);
    if (user?.email) sendEmail(user.email, 'Order Confirmed — '+order_number+' | PrintersReports', orderConfirmationEmail(order, user, resolvedItems));
    res.json({ success:true, message:'Order recovered and confirmed!', order_number, order_id:orderId, total });
  } catch(e) { console.error('Recovery failed:', e); res.status(500).json({ error:'Recovery failed: '+e.message }); }
});

// ════════════════════════════════════════════════════════════════
//   ORDERS
// ════════════════════════════════════════════════════════════════
app.post('/api/orders/cod', authMiddleware, async (req, res) => {
  try {
    const { items, shipping_address, notes } = req.body;
    if (!items?.length) return res.status(400).json({ error:'No items in cart' });
    const db = readDB(); let subtotal = 0; const resolvedItems = [];
    for (const item of items) {
      const p = db.products.find(p=>p.id===item.product_id&&p.is_active);
      if (!p) return res.status(400).json({ error:`Product not found: ${item.product_id}` });
      if (p.stock < item.qty) return res.status(400).json({ error:`Only ${p.stock} units available for: ${p.name}` });
      subtotal += p.price * item.qty;
      resolvedItems.push({ product_id:item.product_id, qty:item.qty, price:p.price, name:p.name });
    }
    const settings = db.settings, shipping = calculateShipping(resolvedItems, db.products, settings);
    const gst = Math.round(subtotal*0.18*100)/100, total = subtotal+gst+shipping;
    const order_number = 'PPP'+Date.now(), orderId = nextId(db.orders);
    const order = { id:orderId, order_number, user_id:req.user.id, subtotal, gst, shipping, total, shipping_address:JSON.stringify(shipping_address), payment_method:'cod', payment_status:'pending', razorpay_order_id:null, razorpay_payment_id:null, status:'pending', tracking_number:null, tracking_url:null, notes:sanitize(notes)||null, cancel_reason:null, return_requested:false, created_at:new Date().toISOString(), updated_at:new Date().toISOString() };
    db.orders.push(order);
    resolvedItems.forEach(item => { db.order_items.push({ id:nextId(db.order_items), order_id:orderId, product_id:item.product_id, qty:item.qty, price:item.price }); const pi=db.products.findIndex(p=>p.id===item.product_id); if(pi!==-1) db.products[pi].stock-=item.qty; });
    logOrderEvent(db, orderId, 'pending', 'COD order placed — awaiting confirmation', 'system');
    writeDB(db);
    const user = db.users.find(u=>u.id===req.user.id);
    if (user?.email) sendEmail(user.email, `Order Placed — ${order_number} | PrintersReports`, orderConfirmationEmail(order, user, resolvedItems));
    res.json({ success:true, message:'COD order placed', order_id:orderId, order_number, total });
  } catch(e) { console.error(e); res.status(500).json({ error:'Order failed: '+e.message }); }
});

app.get('/api/orders', authMiddleware, (req, res) => {
  const db = readDB();
  const orders = db.orders.filter(o=>o.user_id===req.user.id).sort((a,b)=>new Date(b.created_at)-new Date(a.created_at)).map(o => {
    const ois = (db.order_items||[]).filter(i=>i.order_id===o.id);
    const items = ois.map(i => { const p=db.products.find(p=>p.id===i.product_id); const image_url = p?.image?(p.image.startsWith('http')?p.image:BASE_URL+p.image):null; return { product_id:i.product_id, name:p?.name||'Product', qty:i.qty, price:i.price, image_url }; });
    const events = (db.order_events||[]).filter(e=>e.order_id===o.id).sort((a,b)=>new Date(a.created_at)-new Date(b.created_at));
    return { ...o, items, events };
  });
  res.json(orders);
});

// IMPORTANT: track route MUST come before /:id
app.get('/api/orders/track/:order_number', (req, res) => {
  const db = readDB(), order = db.orders.find(o=>o.order_number===req.params.order_number);
  if (!order) return res.status(404).json({ error:'Order not found. Please check the order number and try again.' });
  const ois = (db.order_items||[]).filter(i=>i.order_id===order.id);
  const items = ois.map(i => { const p=db.products.find(p=>p.id===i.product_id); return (p?.name||'Product')+' x'+i.qty; }).join(', ');
  const events = (db.order_events||[]).filter(e=>e.order_id===order.id).sort((a,b)=>new Date(a.created_at)-new Date(b.created_at));
  res.json({ order_number:order.order_number, status:order.status, payment_status:order.payment_status, payment_method:order.payment_method, tracking_number:order.tracking_number, tracking_url:order.tracking_url, items, total:order.total, created_at:order.created_at, events });
});

app.get('/api/orders/:id', authMiddleware, (req, res) => {
  const db = readDB(), order = db.orders.find(o=>o.id===parseInt(req.params.id)&&(o.user_id===req.user.id||req.user.role==='admin'));
  if (!order) return res.status(404).json({ error:'Order not found' });
  const ois = (db.order_items||[]).filter(i=>i.order_id===order.id);
  const items = ois.map(i => { const p=db.products.find(p=>p.id===i.product_id); const image_url = p?.image?(p.image.startsWith('http')?p.image:BASE_URL+p.image):null; return { product_id:i.product_id, name:p?.name||'Product', qty:i.qty, price:i.price, image_url }; });
  const events = (db.order_events||[]).filter(e=>e.order_id===order.id).sort((a,b)=>new Date(a.created_at)-new Date(b.created_at));
  res.json({ ...order, items, events });
});

app.post('/api/orders/:id/cancel', authMiddleware, (req, res) => {
  try {
    const db = readDB(), idx = db.orders.findIndex(o=>o.id===parseInt(req.params.id)&&o.user_id===req.user.id);
    if (idx===-1) return res.status(404).json({ error:'Order not found' });
    const order = db.orders[idx];
    if (['delivered','cancelled'].includes(order.status)) return res.status(400).json({ error:'This order cannot be cancelled' });
    if (order.status === 'shipped') return res.status(400).json({ error:'Order is already shipped.' });
    const cancelHours = db.settings.cancel_window_hours || 24;
    if ((Date.now()-new Date(order.created_at).getTime())/(1000*60*60) > cancelHours) return res.status(400).json({ error:`Cancel window of ${cancelHours} hours has passed.` });
    const reason = sanitize(req.body.reason) || 'Cancelled by customer';
    db.orders[idx].status = 'cancelled'; db.orders[idx].cancel_reason = reason; db.orders[idx].updated_at = new Date().toISOString();
    const ois = (db.order_items||[]).filter(i=>i.order_id===order.id);
    ois.forEach(item => { const pi=db.products.findIndex(p=>p.id===item.product_id); if(pi!==-1) db.products[pi].stock+=item.qty; });
    logOrderEvent(db, order.id, 'cancelled', 'Order cancelled by customer: '+reason, 'customer');
    writeDB(db);
    const user = db.users.find(u=>u.id===req.user.id);
    if (user?.email) sendEmail(user.email, `Order Cancelled — ${order.order_number} | PrintersReports`, orderStatusEmail(order, user, 'cancelled', null));
    res.json({ success:true, message:'Order cancelled successfully.' });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.post('/api/orders/:id/return', authMiddleware, (req, res) => {
  try {
    const db = readDB(), idx = db.orders.findIndex(o=>o.id===parseInt(req.params.id)&&o.user_id===req.user.id);
    if (idx===-1) return res.status(404).json({ error:'Order not found' });
    const order = db.orders[idx];
    if (order.status !== 'delivered') return res.status(400).json({ error:'Return can only be requested for delivered orders' });
    if (order.return_requested) return res.status(400).json({ error:'Return already requested for this order' });
    const returnDays = db.settings.return_window_days || 7;
    if ((Date.now()-new Date(order.updated_at||order.created_at).getTime())/(1000*60*60*24) > returnDays) return res.status(400).json({ error:`Return window of ${returnDays} days has passed.` });
    const reason = sanitize(req.body.reason) || 'Return requested by customer';
    db.orders[idx].return_requested = true; db.orders[idx].return_reason = reason; db.orders[idx].return_status = 'requested'; db.orders[idx].updated_at = new Date().toISOString();
    logOrderEvent(db, order.id, 'return_requested', 'Return requested: '+reason, 'customer');
    writeDB(db);
    res.json({ success:true, message:'Return request submitted. Our team will contact you within 24-48 hours.' });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.put('/api/orders/:id/status', adminMiddleware, async (req, res) => {
  try {
    const db = readDB(), idx = db.orders.findIndex(o=>o.id===parseInt(req.params.id));
    if (idx===-1) return res.status(404).json({ error:'Order not found' });
    const { status, tracking_number, tracking_url, note } = req.body, old = db.orders[idx].status;
    db.orders[idx].status = status;
    db.orders[idx].tracking_number = tracking_number || db.orders[idx].tracking_number;
    db.orders[idx].tracking_url    = tracking_url    || db.orders[idx].tracking_url;
    db.orders[idx].updated_at = new Date().toISOString();
    if (status === 'delivered' && db.orders[idx].payment_method==='cod') db.orders[idx].payment_status = 'paid';
    logOrderEvent(db, db.orders[idx].id, status, note||('Status changed from '+old+' to '+status+' by admin'), 'admin');
    writeDB(db);
    const user = db.users.find(u=>u.id===db.orders[idx].user_id);
    if (user?.email) sendEmail(user.email, `Order ${status.charAt(0).toUpperCase()+status.slice(1)} — ${db.orders[idx].order_number} | PrintersReports`, orderStatusEmail(db.orders[idx], user, status, tracking_number));
    res.json({ message:'Order updated and customer notified' });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.get('/api/admin/orders', adminMiddleware, (req, res) => {
  const { status, page=1, limit=20, search } = req.query, db = readDB();
  let orders = [...db.orders].sort((a,b)=>new Date(b.created_at)-new Date(a.created_at));
  if (status) orders = orders.filter(o=>o.status===status);
  if (search) orders = orders.filter(o=>o.order_number.includes(search.toUpperCase())||(db.users.find(u=>u.id===o.user_id)?.name||'').toLowerCase().includes(search.toLowerCase()));
  orders = orders.map(o => { const u=db.users.find(u=>u.id===o.user_id); const ois=(db.order_items||[]).filter(i=>i.order_id===o.id); const items=ois.map(i=>db.products.find(p=>p.id===i.product_id)?.name||'Product').join(', '); return { ...o, customer_name:u?.name, customer_email:u?.email, customer_phone:u?.phone, items }; });
  const total = orders.length, offset = (parseInt(page)-1)*parseInt(limit);
  res.json({ orders:orders.slice(offset,offset+parseInt(limit)), total });
});

// ════════════════════════════════════════════════════════════════
//   WISHLIST
// ════════════════════════════════════════════════════════════════
app.get('/api/wishlist', authMiddleware, (req, res) => {
  const db = readDB(), list = (db.wishlists||[]).filter(w=>w.user_id===req.user.id);
  const items = list.map(w => { const p=db.products.find(p=>p.id===w.product_id&&p.is_active); if (!p) return null; const image_url = p.image?(p.image.startsWith('http')?p.image:BASE_URL+p.image):null; return { ...w, product:{ ...p, image_url } }; }).filter(Boolean);
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
  if (!db.users[idx].password) return res.status(400).json({ error:'Password cannot be changed — this account uses Google or Facebook login.' });
  if (!bcrypt.compareSync(current_password, db.users[idx].password)) return res.status(401).json({ error:'Current password is incorrect' });
  if (new_password.length < 8) return res.status(400).json({ error:'New password must be at least 8 characters' });
  db.users[idx].password = bcrypt.hashSync(new_password, 12); writeDB(db);
  res.json({ message:'Password changed successfully' });
});
app.get('/api/user/addresses', authMiddleware, (req, res) => { const u = readDB().users.find(u=>u.id===req.user.id); res.json(u?.addresses||[]); });
app.post('/api/user/addresses', authMiddleware, (req, res) => {
  const db=readDB(), idx=db.users.findIndex(u=>u.id===req.user.id);
  if (idx===-1) return res.status(404).json({ error:'Not found' });
  db.users[idx].addresses = db.users[idx].addresses||[];
  const addr = { id:nextId(db.users[idx].addresses.length?db.users[idx].addresses:[{id:0}]), ...req.body, created_at:new Date().toISOString() };
  if (req.body.is_default || !db.users[idx].addresses.length) { db.users[idx].addresses.forEach(a=>a.is_default=false); addr.is_default=true; }
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
  const db = readDB(), paidOrders = db.orders.filter(o=>o.payment_status==='paid');
  res.json({ orders:db.orders.length, revenue:paidOrders.reduce((s,o)=>s+o.total,0), products:db.products.filter(p=>p.is_active).length, users:db.users.filter(u=>u.role!=='admin').length, pending:db.orders.filter(o=>o.status==='pending').length, confirmed:db.orders.filter(o=>o.status==='confirmed').length, shipped:db.orders.filter(o=>o.status==='shipped').length, delivered:db.orders.filter(o=>o.status==='delivered').length, cancelled:db.orders.filter(o=>o.status==='cancelled').length, returns:db.orders.filter(o=>o.return_requested).length, cod_pending:db.orders.filter(o=>o.payment_method==='cod'&&o.payment_status==='pending').length });
});

// ════════════════════════════════════════════════════════════════
//   SMART SEARCH
// ════════════════════════════════════════════════════════════════
function trackSearch(query) {
  try {
    const db = readDB(); db.search_logs = db.search_logs || [];
    if (!query || query.length < 2) return;
    const q = query.toLowerCase().trim();
    const existing = db.search_logs.find(s => s.query === q);
    if (existing) { existing.count++; existing.last_searched = new Date().toISOString(); }
    else { db.search_logs.push({ query:q, count:1, last_searched:new Date().toISOString() }); }
    if (db.search_logs.length > 500) { db.search_logs.sort((a,b)=>b.count-a.count); db.search_logs = db.search_logs.slice(0,500); }
    writeDB(db);
  } catch(e) {}
}
app.get('/api/search/suggestions', (req, res) => {
  try {
    const q = sanitize(req.query.q||'').toLowerCase().trim(), db = readDB();
    if (q.length < 1) {
      const trending = (db.search_logs||[]).sort((a,b)=>b.count-a.count).slice(0,8).map(s=>s.query);
      const popular  = db.products.filter(p=>p.is_active&&p.is_bestseller).slice(0,4).map(p=>({ id:p.id, name:p.name, price:p.price, image_url:p.image?(p.image.startsWith('http')?p.image:BASE_URL+p.image):null, category:db.categories.find(c=>c.id===p.category_id)?.name||'' }));
      const recent   = db.products.filter(p=>p.is_active).sort((a,b)=>new Date(b.created_at)-new Date(a.created_at)).slice(0,4).map(p=>({ id:p.id, name:p.name, price:p.price, image_url:p.image?(p.image.startsWith('http')?p.image:BASE_URL+p.image):null, category:db.categories.find(c=>c.id===p.category_id)?.name||'' }));
      return res.json({ trending, popular, recent, products:[], categories:[] });
    }
    trackSearch(q);
    const products = db.products.filter(p=>{ if(!p.is_active)return false; const name=(p.name||'').toLowerCase(),sku=(p.sku||'').toLowerCase(),desc=(p.description||'').toLowerCase(); return name.includes(q)||sku.includes(q)||desc.includes(q)||q.split(' ').every(word=>name.includes(word)); }).slice(0,6).map(p=>({ id:p.id, name:p.name, price:p.price, old_price:p.old_price, sku:p.sku, image_url:p.image?(p.image.startsWith('http')?p.image:BASE_URL+p.image):null, category:db.categories.find(c=>c.id===p.category_id)?.name||'', stock:p.stock }));
    const categories = db.categories.filter(c=>c.name.toLowerCase().includes(q)).slice(0,3).map(c=>({ id:c.id, name:c.name, slug:c.slug }));
    const related = (db.search_logs||[]).filter(s=>s.query.includes(q)&&s.query!==q).sort((a,b)=>b.count-a.count).slice(0,5).map(s=>s.query);
    res.json({ products, categories, related, trending:[], popular:[], recent:[] });
  } catch(e) { console.error(e); res.status(500).json({ products:[], categories:[], related:[], trending:[] }); }
});
app.get('/api/search/trending', (req, res) => {
  try { const db=readDB(); res.json((db.search_logs||[]).sort((a,b)=>b.count-a.count).slice(0,10).map(s=>({ query:s.query, count:s.count }))); } catch(e) { res.json([]); }
});
app.post('/api/search/track', (req, res) => { trackSearch(sanitize(req.body.query||'')); res.json({ ok:true }); });

// ════════════════════════════════════════════════════════════════
//   ADMIN — FULL CONTROL
// ════════════════════════════════════════════════════════════════
app.delete('/api/admin/orders/:id', adminMiddleware, (req, res) => {
  try {
    const db=readDB(), idx=db.orders.findIndex(o=>o.id===parseInt(req.params.id));
    if (idx===-1) return res.status(404).json({ error:'Order not found' });
    const order = db.orders[idx];
    db.order_items  = (db.order_items||[]).filter(i=>i.order_id!==order.id);
    db.order_events = (db.order_events||[]).filter(e=>e.order_id!==order.id);
    db.orders.splice(idx,1); writeDB(db);
    res.json({ message:'Order #'+order.order_number+' deleted successfully' });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});
app.delete('/api/admin/orders', adminMiddleware, (req, res) => {
  try {
    const db=readDB(), count=db.orders.length;
    db.orders=[]; db.order_items=[]; db.order_events=[];
    writeDB(db); res.json({ message:count+' orders deleted successfully' });
  } catch(e) { res.status(500).json({ error:'Server error' }); }
});
app.put('/api/admin/orders/:id', adminMiddleware, (req, res) => {
  try {
    const db=readDB(), idx=db.orders.findIndex(o=>o.id===parseInt(req.params.id));
    if (idx===-1) return res.status(404).json({ error:'Order not found' });
    ['status','payment_status','payment_method','tracking_number','tracking_url','shipping_address','notes','cancel_reason','total','subtotal','gst'].forEach(f=>{ if(req.body[f]!==undefined) db.orders[idx][f]=req.body[f]; });
    db.orders[idx].updated_at = new Date().toISOString();
    if (req.body.note) logOrderEvent(db, db.orders[idx].id, db.orders[idx].status, 'Admin edited: '+req.body.note, 'admin');
    writeDB(db); res.json({ message:'Order updated', order:db.orders[idx] });
  } catch(e) { res.status(500).json({ error:'Server error' }); }
});
app.get('/api/admin/users', adminMiddleware, (req, res) => {
  try {
    const { page=1, limit=20, search } = req.query, db=readDB();
    let users = db.users.filter(u=>u.role!=='admin');
    if (search) { const q=search.toLowerCase(); users=users.filter(u=>(u.name||'').toLowerCase().includes(q)||(u.email||'').toLowerCase().includes(q)||(u.phone||'').includes(q)); }
    users = users.sort((a,b)=>new Date(b.created_at)-new Date(a.created_at));
    const result = users.map(u=>{ const { password, ...safe }=u; return { ...safe, order_count:db.orders.filter(o=>o.user_id===u.id).length, total_spent:db.orders.filter(o=>o.user_id===u.id&&o.payment_status==='paid').reduce((s,o)=>s+o.total,0) }; });
    const total=result.length, offset=(parseInt(page)-1)*parseInt(limit);
    res.json({ users:result.slice(offset,offset+parseInt(limit)), total });
  } catch(e) { res.status(500).json({ error:'Server error' }); }
});
app.put('/api/admin/users/:id', adminMiddleware, (req, res) => {
  try {
    const db=readDB(), idx=db.users.findIndex(u=>u.id===parseInt(req.params.id));
    if (idx===-1) return res.status(404).json({ error:'User not found' });
    if (db.users[idx].role==='admin') return res.status(403).json({ error:'Cannot edit admin account from here' });
    const { name, phone, email } = req.body;
    if (name)  db.users[idx].name  = sanitize(name);
    if (phone) db.users[idx].phone = sanitize(phone);
    if (email) { const taken=db.users.find(u=>u.email===email.toLowerCase()&&u.id!==db.users[idx].id); if(taken) return res.status(409).json({ error:'This email is already used by another account' }); db.users[idx].email=email.toLowerCase(); }
    if (req.body.new_password) { if(req.body.new_password.length<8) return res.status(400).json({ error:'Password must be at least 8 characters' }); db.users[idx].password=bcrypt.hashSync(req.body.new_password,12); }
    db.users[idx].updated_at = new Date().toISOString(); writeDB(db);
    const { password, ...safe } = db.users[idx]; res.json({ message:'Customer updated', user:safe });
  } catch(e) { res.status(500).json({ error:'Server error' }); }
});
app.delete('/api/admin/users/:id', adminMiddleware, (req, res) => {
  try {
    const db=readDB(), idx=db.users.findIndex(u=>u.id===parseInt(req.params.id));
    if (idx===-1) return res.status(404).json({ error:'User not found' });
    if (db.users[idx].role==='admin') return res.status(403).json({ error:'Cannot delete admin account' });
    const name=db.users[idx].name; db.users.splice(idx,1); writeDB(db);
    res.json({ message:'Customer "'+name+'" deleted' });
  } catch(e) { res.status(500).json({ error:'Server error' }); }
});
app.get('/api/admin/enquiries', adminMiddleware, (req, res) => { const db=readDB(); res.json((db.enquiries||[]).sort((a,b)=>new Date(b.created_at)-new Date(a.created_at))); });
app.delete('/api/admin/enquiries/:id', adminMiddleware, (req, res) => {
  const db=readDB(), idx=(db.enquiries||[]).findIndex(e=>e.id===parseInt(req.params.id));
  if (idx===-1) return res.status(404).json({ error:'Enquiry not found' });
  db.enquiries.splice(idx,1); writeDB(db); res.json({ message:'Enquiry deleted' });
});
app.put('/api/admin/enquiries/:id/read', adminMiddleware, (req, res) => {
  const db=readDB(), idx=(db.enquiries||[]).findIndex(e=>e.id===parseInt(req.params.id));
  if (idx===-1) return res.status(404).json({ error:'Not found' });
  db.enquiries[idx].is_read=true; writeDB(db); res.json({ message:'Marked as read' });
});
app.delete('/api/admin/search-logs', adminMiddleware, (req, res) => { const db=readDB(); db.search_logs=[]; writeDB(db); res.json({ message:'Search history cleared' }); });
app.get('/api/admin/export', adminMiddleware, (req, res) => {
  const db=readDB();
  const exportData = { exported_at:new Date().toISOString(), orders:db.orders, order_items:db.order_items, users:db.users.map(u=>{ const { password,...safe }=u; return safe; }), products:db.products, categories:db.categories, enquiries:db.enquiries };
  res.setHeader('Content-Disposition','attachment; filename="ppp-backup-'+Date.now()+'.json"');
  res.setHeader('Content-Type','application/json');
  res.json(exportData);
});

// ════════════════════════════════════════════════════════════════
//   ADMIN PROFILE
// ════════════════════════════════════════════════════════════════
app.get('/api/admin/profile', adminMiddleware, (req, res) => {
  const db=readDB(), user=db.users.find(u=>u.id===req.user.id&&u.role==='admin');
  if (!user) return res.status(404).json({ error:'Admin not found' });
  const { password, ...safe }=user; res.json(safe);
});
app.put('/api/admin/profile', adminMiddleware, (req, res) => {
  try {
    const db=readDB(), idx=db.users.findIndex(u=>u.id===req.user.id&&u.role==='admin');
    if (idx===-1) return res.status(404).json({ error:'Admin not found' });
    const { name, email, phone }=req.body;
    if (name&&name.trim())  db.users[idx].name  = sanitize(name.trim());
    if (phone&&phone.trim()) db.users[idx].phone = sanitize(phone.trim());
    if (email&&email.trim()) {
      const newEmail=email.trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail)) return res.status(400).json({ error:'Invalid email address' });
      const taken=db.users.find(u=>u.email===newEmail&&u.id!==req.user.id);
      if (taken) return res.status(409).json({ error:'This email is already used by another account' });
      db.users[idx].email=newEmail;
    }
    db.users[idx].updated_at=new Date().toISOString(); writeDB(db);
    const { password, ...safe }=db.users[idx];
    const token=jwt.sign({ id:db.users[idx].id, email:db.users[idx].email, role:'admin' }, JWT_SECRET, { expiresIn:'30d' });
    res.json({ message:'Profile updated successfully', user:safe, token });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});
app.put('/api/admin/password', adminMiddleware, (req, res) => {
  try {
    const { current_password, new_password, confirm_password }=req.body;
    if (!current_password||!new_password) return res.status(400).json({ error:'Current password and new password are required' });
    if (new_password.length<8) return res.status(400).json({ error:'New password must be at least 8 characters' });
    if (confirm_password&&new_password!==confirm_password) return res.status(400).json({ error:'New passwords do not match' });
    const db=readDB(), idx=db.users.findIndex(u=>u.id===req.user.id&&u.role==='admin');
    if (idx===-1) return res.status(404).json({ error:'Admin not found' });
    if (!db.users[idx].password) return res.status(400).json({ error:'Password cannot be changed — this account uses social login.' });
    if (!bcrypt.compareSync(current_password, db.users[idx].password)) return res.status(401).json({ error:'Current password is incorrect' });
    db.users[idx].password=bcrypt.hashSync(new_password,12); db.users[idx].updated_at=new Date().toISOString(); writeDB(db);
    res.json({ message:'Password changed successfully. Please login again with your new password.' });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

// ════════════════════════════════════════════════════════════════
//   CONTACT
// ════════════════════════════════════════════════════════════════
app.post('/api/contact', (req, res) => {
  const db=readDB(); const { name, email, phone, message }=req.body;
  if (!name||!message) return res.status(400).json({ error:'Name and message are required' });
  db.enquiries.push({ id:nextId(db.enquiries), name:sanitize(name), email:sanitize(email)||null, phone:sanitize(phone)||null, message:sanitize(message), is_read:false, created_at:new Date().toISOString() });
  writeDB(db);
  if (transporter) sendEmail(EMAIL_USER, 'New Contact Enquiry — PrintersReports', `<p>From: ${name} (${email||'no email'}) — ${phone||'no phone'}</p><p>${message}</p>`);
  res.json({ message:'Enquiry submitted. We will contact you within 24 hours.' });
});

// ════════════════════════════════════════════════════════════════
//   START
// ════════════════════════════════════════════════════════════════
setupDatabase().then(() => {
  app.listen(PORT, () => {
    console.log('');
    console.log('╔══════════════════════════════════════════════════╗');
    console.log('║   PrintersReports Production Backend             ║');
    console.log(`║   Running at: http://localhost:${PORT}               ║`);
    console.log(`║   Razorpay:   ${razorpay    ? 'CONFIGURED ✅' : 'NOT configured ⚠️ '}              ║`);
    console.log(`║   Email:      ${transporter ? 'CONFIGURED ✅' : 'NOT configured ⚠️ '}              ║`);
    console.log(`║   Database:   ${mongoCollection ? 'MongoDB Atlas ✅ (permanent)' : 'Local file ⚠️  (resets!)'}  ║`);
    console.log(`║   Images:     ${cloudinary  ? 'Cloudinary ✅ (permanent)' : 'Local disk ⚠️  (resets!)  '}   ║`);
    console.log('╚══════════════════════════════════════════════════╝');
    console.log('');
  });
}).catch(err => { console.error('Fatal startup error:', err); process.exit(1); });