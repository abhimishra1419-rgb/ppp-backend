# 🖨️ PrinterPartsPoint – Complete E-Commerce Website

A full-featured printer spare parts e-commerce website built with HTML/CSS/JS frontend,
Node.js + Express backend, and MySQL database.

---

## 📁 Project Structure

```
PrinterPartsPoint/
├── index.html               ← Homepage
├── products.html            ← All products with filters
├── productdetails.html      ← Single product detail
├── cart.html                ← Shopping cart
├── checkout.html            ← Checkout page
├── order.html               ← Order confirmation
├── track.html               ← Order tracking
├── login.html               ← Login page
├── register.html            ← Registration page
├── profile.html             ← User profile & orders
├── contact.html             ← Contact form & FAQ
├── admindashboard.html      ← Admin dashboard
├── adminorder.html          ← Manage orders
├── adminproduct.html        ← Manage products
├── adminsetting.html        ← Store settings
├── css/shared.css           ← Shared styles
├── js/auth.js               ← Auth context
├── js/cart.js               ← Cart context
├── backend/server.js        ← Node.js API
├── backend/package.json     ← Dependencies
├── backend/.env.example     ← Env template
└── database/schema.sql      ← MySQL setup
```

---

## STEP 1 – Install Required Tools

1. VS Code: https://code.visualstudio.com (install Live Server extension)
2. XAMPP:   https://www.apachefriends.org (for MySQL)
3. Node.js: https://nodejs.org (LTS version)

---

## STEP 2 – Setup Database

1. Open XAMPP → Start MySQL → click Admin → opens phpMyAdmin
2. Click SQL tab → paste contents of database/schema.sql → click Go
3. Database printerparts_db is created with all tables + sample data

Default Admin: admin@printerpartspoint.in / Admin@1234

---

## STEP 3 – Setup Backend

```bash
cd backend
copy .env.example .env
# Edit .env: set DB_PASS to your MySQL password (blank for XAMPP default)
npm install
npm run dev
```

Backend runs at: http://localhost:5000

---

## STEP 4 – Run Frontend

Open VS Code → right-click index.html → Open with Live Server
Opens at: http://127.0.0.1:5500

---

## All Pages

| Page | Purpose |
|------|---------|
| index.html | Homepage |
| products.html | Product listing with filters |
| productdetails.html | Product detail page |
| cart.html | Shopping cart |
| checkout.html | Checkout with payment |
| order.html | Order confirmation + tracking |
| track.html | Public order tracking |
| login.html | Login |
| register.html | 3-step registration |
| profile.html | User account |
| contact.html | Contact + FAQ |
| admindashboard.html | Admin dashboard |
| adminorder.html | Manage orders |
| adminproduct.html | Manage products |
| adminsetting.html | Store settings |

---

## Tech Stack

- Frontend: HTML5, CSS3, Vanilla JavaScript
- Backend:  Node.js + Express.js
- Database: MySQL
- Auth:     JWT + bcryptjs
