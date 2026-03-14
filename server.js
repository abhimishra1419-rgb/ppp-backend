// PrinterPartsPoint Backend - database.json (no compilation needed)
// Run: npm install then npm run dev

const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');

const app        = express();
const PORT       = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'printerpartspoint_secret_2025';
const BASE_URL   = process.env.BASE_URL || ('http://localhost:' + PORT);
const DB_FILE    = path.join(__dirname, 'database.json');

app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Multer image upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads', 'products');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1e6) + ext);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = ['.jpg','.jpeg','.png','.webp','.gif'];
    ok.includes(path.extname(file.originalname).toLowerCase()) ? cb(null,true) : cb(new Error('Images only'));
  },
});

// DB helpers
const readDB  = ()     => JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
const writeDB = data   => fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
const nextId  = arr    => arr.length ? Math.max(...arr.map(r => r.id)) + 1 : 1;

// First-run setup
function setupDatabase() {
  if (fs.existsSync(DB_FILE)) { console.log('database.json loaded'); return; }
  const adminHash = bcrypt.hashSync('Admin@1234', 10);
  const now = new Date().toISOString();
  const db = {
    settings: {
      site_name: 'PrinterPartsPoint',
      tagline: "India's #1 Printer Spare Parts Store",
      hero_title: "India's #1 Source for Printer Spare Parts",
      hero_subtitle: 'Genuine & compatible parts for HP, Canon, Epson, Ricoh, Brother printers. Fast shipping across India.',
      hero_btn_primary: 'Shop Now',
      hero_btn_secondary: 'New Arrivals',
      announcement_bar: 'Free Shipping on orders above Rs.999 | All Prices Exclusive of 18% GST',
      whatsapp_number: '9990774445',
      whatsapp_banner_text: 'For any queries contact us on WhatsApp',
      gst_rate: 18,
      free_shipping_min: 999,
      show_new_arrivals: true,
      show_best_sellers: true,
      show_categories: true,
      footer_address: 'Karol Bagh, New Delhi - 110005',
      footer_email: 'support@printerpartspoint.in',
      working_hours: 'Mon-Sat: 10:00 AM - 7:00 PM',
      meta_title: 'PrinterPartsPoint - Printer Spare Parts India',
      meta_description: 'Buy genuine printer spare parts online in India.',
    },
    users: [
      { id:1, name:'Admin', email:'admin@printerpartspoint.in', phone:'9990774445',
        password: adminHash, role:'admin', created_at: now }
    ],
    categories: [
      { id:1, name:'Laser Printer Parts',       slug:'laser',    sort_order:1 },
      { id:2, name:'DMP Printer Parts',          slug:'dmp',      sort_order:2 },
      { id:3, name:'Inkjet Printer Parts',       slug:'inkjet',   sort_order:3 },
      { id:4, name:'Scanner Parts',             slug:'scanner',  sort_order:4 },
      { id:5, name:'Thermal/POS Printer Parts', slug:'thermal',  sort_order:5 },
      { id:6, name:'Toner Spare Parts',         slug:'toner',    sort_order:6 },
      { id:7, name:'Complete Printer',          slug:'complete', sort_order:7 },
      { id:8, name:'Drum Units',                slug:'drum',     sort_order:8 },
    ],
    products: [],
    orders: [],
    order_items: [],
    enquiries: [],
  };
  writeDB(db);
  console.log('database.json created - no demo products');
  console.log('Admin: admin@printerpartspoint.in / Admin@1234');
}
setupDatabase();

// Auth middleware
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Invalid token' }); }
}
function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    next();
  });
}

// SETTINGS - admin edits index page content
app.get('/api/settings', (req, res) => res.json(readDB().settings));
app.put('/api/settings', adminMiddleware, (req, res) => {
  const db = readDB();
  db.settings = { ...db.settings, ...req.body };
  writeDB(db);
  res.json({ message: 'Settings saved', settings: db.settings });
});

// AUTH
app.post('/api/auth/register', (req, res) => {
  try {
    const { name, email, phone, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, password required' });
    const db = readDB();
    if (db.users.find(u => u.email === email)) return res.status(409).json({ error: 'Email already registered' });
    const user = { id:nextId(db.users), name, email, phone:phone||null,
      password:bcrypt.hashSync(password,10), role:'customer', created_at:new Date().toISOString() };
    db.users.push(user); writeDB(db);
    const token = jwt.sign({ id:user.id, email, role:'customer' }, JWT_SECRET, { expiresIn:'7d' });
    res.json({ message:'Registered', token, user:{ id:user.id, name, email, role:'customer' } });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    const db = readDB();
    const user = db.users.find(u => u.email === email);
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error:'Invalid email or password' });
    const token = jwt.sign({ id:user.id, email:user.email, role:user.role }, JWT_SECRET, { expiresIn:'7d' });
    res.json({ token, user:{ id:user.id, name:user.name, email:user.email, role:user.role } });
  } catch(e) { res.status(500).json({ error:'Server error' }); }
});

// PRODUCTS - GET all
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
      const q = search.toLowerCase();
      list = list.filter(p => p.name.toLowerCase().includes(q) || (p.sku||'').toLowerCase().includes(q));
    }
    if (isNew === '1')      list = list.filter(p => p.is_new);
    if (bestseller === '1') list = list.filter(p => p.is_bestseller);
    if (sort === 'price_asc')  list.sort((a,b) => a.price - b.price);
    else if (sort === 'price_desc') list.sort((a,b) => b.price - a.price);
    else if (sort === 'name')  list.sort((a,b) => a.name.localeCompare(b.name));
    else list.sort((a,b) => new Date(b.created_at) - new Date(a.created_at));
    list = list.map(p => ({
      ...p,
      category_name: db.categories.find(c => c.id === p.category_id)?.name || '',
      image_url: p.image ? BASE_URL + p.image : null,
    }));
    const total = list.length, offset = (parseInt(page)-1)*parseInt(limit);
    res.json({ products: list.slice(offset, offset+parseInt(limit)), total, page:parseInt(page), limit:parseInt(limit) });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

// PRODUCTS - GET one
app.get('/api/products/:id', (req, res) => {
  const db = readDB();
  const p  = db.products.find(p => p.id === parseInt(req.params.id) && p.is_active);
  if (!p) return res.status(404).json({ error:'Product not found' });
  res.json({ ...p, category_name: db.categories.find(c=>c.id===p.category_id)?.name||'',
    image_url: p.image ? BASE_URL + p.image : null });
});

// PRODUCTS - ADD (admin, with image upload)
app.post('/api/products', adminMiddleware, upload.single('image'), (req, res) => {
  try {
    const db = readDB();
    const { name, description, sku, category_id, price, old_price, stock, is_new, is_bestseller } = req.body;
    if (!name || !price) return res.status(400).json({ error:'Name and price are required' });
    const prod = {
      id: nextId(db.products),
      name: name.trim(), description: description||'', sku: sku||'',
      category_id: category_id ? parseInt(category_id) : null,
      price: parseFloat(price),
      old_price: old_price ? parseFloat(old_price) : null,
      stock: parseInt(stock)||0,
      image: req.file ? '/uploads/products/' + req.file.filename : null,
      is_new: is_new === '1' || is_new === true,
      is_bestseller: is_bestseller === '1' || is_bestseller === true,
      is_active: true,
      created_at: new Date().toISOString(),
    };
    db.products.push(prod); writeDB(db);
    res.json({ message:'Product added', id:prod.id, product:prod });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

// PRODUCTS - EDIT (admin, optional new image)
app.put('/api/products/:id', adminMiddleware, upload.single('image'), (req, res) => {
  try {
    const db = readDB();
    const idx = db.products.findIndex(p => p.id === parseInt(req.params.id));
    if (idx === -1) return res.status(404).json({ error:'Product not found' });
    if (req.file && db.products[idx].image) {
      const old = path.join(__dirname, db.products[idx].image);
      if (fs.existsSync(old)) fs.unlinkSync(old);
    }
    const { name, description, sku, category_id, price, old_price, stock, is_new, is_bestseller, is_active } = req.body;
    db.products[idx] = {
      ...db.products[idx],
      name: name?.trim() || db.products[idx].name,
      description: description ?? db.products[idx].description,
      sku: sku ?? db.products[idx].sku,
      category_id: category_id ? parseInt(category_id) : db.products[idx].category_id,
      price: price ? parseFloat(price) : db.products[idx].price,
      old_price: old_price !== undefined ? (old_price ? parseFloat(old_price) : null) : db.products[idx].old_price,
      stock: stock !== undefined ? parseInt(stock) : db.products[idx].stock,
      image: req.file ? '/uploads/products/'+req.file.filename : db.products[idx].image,
      is_new: is_new === '1' || is_new === true,
      is_bestseller: is_bestseller === '1' || is_bestseller === true,
      is_active: is_active !== '0' && is_active !== false,
      updated_at: new Date().toISOString(),
    };
    writeDB(db);
    res.json({ message:'Product updated', product:db.products[idx] });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

// PRODUCTS - DELETE (admin, removes product + image file)
app.delete('/api/products/:id', adminMiddleware, (req, res) => {
  try {
    const db = readDB();
    const idx = db.products.findIndex(p => p.id === parseInt(req.params.id));
    if (idx === -1) return res.status(404).json({ error:'Product not found' });
    if (db.products[idx].image) {
      const imgPath = path.join(__dirname, db.products[idx].image);
      if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
    }
    db.products.splice(idx, 1); writeDB(db);
    res.json({ message:'Product deleted' });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

// DELETE product image only
app.delete('/api/products/:id/image', adminMiddleware, (req, res) => {
  const db = readDB();
  const idx = db.products.findIndex(p => p.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error:'Not found' });
  if (db.products[idx].image) {
    const p = path.join(__dirname, db.products[idx].image);
    if (fs.existsSync(p)) fs.unlinkSync(p);
    db.products[idx].image = null; writeDB(db);
  }
  res.json({ message:'Image removed' });
});

// CATEGORIES
app.get('/api/categories', (req, res) => res.json(readDB().categories.sort((a,b) => a.sort_order - b.sort_order)));
app.post('/api/categories', adminMiddleware, (req, res) => {
  const db = readDB(); const { name, slug } = req.body;
  if (!name || !slug) return res.status(400).json({ error:'Name and slug required' });
  if (db.categories.find(c => c.slug === slug)) return res.status(409).json({ error:'Slug exists' });
  const c = { id:nextId(db.categories), name, slug, sort_order:db.categories.length+1 };
  db.categories.push(c); writeDB(db); res.json({ id:c.id, message:'Added' });
});
app.put('/api/categories/:id', adminMiddleware, (req, res) => {
  const db = readDB(), idx = db.categories.findIndex(c => c.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error:'Not found' });
  db.categories[idx] = { ...db.categories[idx], ...req.body }; writeDB(db);
  res.json({ message:'Updated' });
});
app.delete('/api/categories/:id', adminMiddleware, (req, res) => {
  const db = readDB(), idx = db.categories.findIndex(c => c.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error:'Not found' });
  db.categories.splice(idx, 1); writeDB(db); res.json({ message:'Deleted' });
});

// ORDERS
app.post('/api/orders', authMiddleware, (req, res) => {
  try {
    const { items, shipping_address, payment_method, notes } = req.body;
    if (!items?.length) return res.status(400).json({ error:'No items' });
    const db = readDB(); let subtotal = 0; const resolved = [];
    for (const item of items) {
      const p = db.products.find(p => p.id === item.product_id && p.is_active);
      if (!p) return res.status(400).json({ error:'Product not found: '+item.product_id });
      if (p.stock < item.qty) return res.status(400).json({ error:'Not enough stock: '+p.name });
      subtotal += p.price * item.qty; resolved.push({ product_id:item.product_id, qty:item.qty, price:p.price });
    }
    const gst = Math.round(subtotal*0.18*100)/100, total = subtotal+gst;
    const order_number = 'PPP'+Date.now(), orderId = nextId(db.orders);
    db.orders.push({ id:orderId, order_number, user_id:req.user.id, subtotal, gst, total,
      shipping_address:JSON.stringify(shipping_address), payment_method:payment_method||'cod',
      payment_status:'pending', status:'pending', tracking_number:null, notes:notes||null,
      created_at:new Date().toISOString() });
    resolved.forEach(i => {
      db.order_items.push({ id:nextId(db.order_items), order_id:orderId, product_id:i.product_id, qty:i.qty, price:i.price });
      const pi = db.products.findIndex(p => p.id === i.product_id);
      db.products[pi].stock -= i.qty;
    });
    writeDB(db); res.json({ message:'Order placed', order_id:orderId, order_number, total });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});
app.get('/api/orders', authMiddleware, (req, res) => {
  const db = readDB();
  res.json(db.orders.filter(o => o.user_id===req.user.id)
    .sort((a,b) => new Date(b.created_at)-new Date(a.created_at))
    .map(o => { const items=db.order_items.filter(i=>i.order_id===o.id);
      return {...o, product_names:items.map(i=>db.products.find(p=>p.id===i.product_id)?.name||'').join(' | ')}; }));
});
app.get('/api/orders/track/:order_number', (req, res) => {
  const db = readDB(), o = db.orders.find(o => o.order_number===req.params.order_number);
  if (!o) return res.status(404).json({ error:'Order not found' });
  const items = db.order_items.filter(i=>i.order_id===o.id)
    .map(i=>{ const p=db.products.find(p=>p.id===i.product_id); return (p?.name||'Product')+' x'+i.qty; }).join(' | ');
  res.json({ ...o, items });
});
app.put('/api/orders/:id/status', adminMiddleware, (req, res) => {
  const db=readDB(), idx=db.orders.findIndex(o=>o.id===parseInt(req.params.id));
  if (idx===-1) return res.status(404).json({ error:'Not found' });
  db.orders[idx].status=req.body.status; db.orders[idx].tracking_number=req.body.tracking_number||null;
  writeDB(db); res.json({ message:'Updated' });
});
app.get('/api/admin/orders', adminMiddleware, (req, res) => {
  const { status, page=1, limit=20 } = req.query; const db=readDB();
  let orders = [...db.orders].sort((a,b)=>new Date(b.created_at)-new Date(a.created_at));
  if (status) orders=orders.filter(o=>o.status===status);
  orders=orders.map(o=>{ const u=db.users.find(u=>u.id===o.user_id); return {...o,customer_name:u?.name,customer_email:u?.email}; });
  const offset=(parseInt(page)-1)*parseInt(limit);
  res.json(orders.slice(offset, offset+parseInt(limit)));
});

// USER PROFILE
app.get('/api/user/profile', authMiddleware, (req, res) => {
  const u=readDB().users.find(u=>u.id===req.user.id);
  if (!u) return res.status(404).json({ error:'Not found' });
  const {password,...safe}=u; res.json(safe);
});
app.put('/api/user/profile', authMiddleware, (req, res) => {
  const db=readDB(), idx=db.users.findIndex(u=>u.id===req.user.id);
  if (idx===-1) return res.status(404).json({ error:'Not found' });
  if (req.body.name) db.users[idx].name=req.body.name;
  if (req.body.phone) db.users[idx].phone=req.body.phone;
  writeDB(db); res.json({ message:'Updated' });
});

// ADMIN STATS
app.get('/api/admin/stats', adminMiddleware, (req, res) => {
  const db=readDB();
  res.json({ orders:db.orders.length, revenue:db.orders.reduce((s,o)=>s+o.total,0),
    products:db.products.filter(p=>p.is_active).length, users:db.users.length,
    pending:db.orders.filter(o=>o.status==='pending').length });
});

// CONTACT
app.post('/api/contact', (req, res) => {
  const db=readDB();
  db.enquiries.push({ id:nextId(db.enquiries), name:req.body.name, email:req.body.email,
    phone:req.body.phone, message:req.body.message, is_read:false, created_at:new Date().toISOString() });
  writeDB(db); res.json({ message:'Enquiry submitted. We will contact you shortly.' });
});

app.listen(PORT, () => {
  console.log('');
  console.log('PrinterPartsPoint API running at http://localhost:'+PORT);
  console.log('Admin: admin@printerpartspoint.in / Admin@1234');
  console.log('Database: database.json (auto-created, no demo products)');
  console.log('');
});