-- ═══════════════════════════════════════════════════════════
--   PrinterPartsPoint – MySQL Database Schema
--   Run this file once to set up all tables
-- ═══════════════════════════════════════════════════════════

CREATE DATABASE IF NOT EXISTS printerparts_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE printerparts_db;

-- ─── USERS ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(120) NOT NULL,
  email      VARCHAR(180) NOT NULL UNIQUE,
  phone      VARCHAR(20),
  password   VARCHAR(255) NOT NULL,
  role       ENUM('customer','admin') DEFAULT 'customer',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- ─── CATEGORIES ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS categories (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(100) NOT NULL,
  slug       VARCHAR(100) NOT NULL UNIQUE,
  icon       VARCHAR(10) DEFAULT '🖨️',
  sort_order INT DEFAULT 0
);

-- ─── PRODUCTS ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS products (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  name          VARCHAR(500) NOT NULL,
  description   TEXT,
  sku           VARCHAR(100),
  category_id   INT,
  price         DECIMAL(10,2) NOT NULL,
  old_price     DECIMAL(10,2),
  stock         INT DEFAULT 0,
  image         VARCHAR(300),
  is_new        TINYINT(1) DEFAULT 0,
  is_bestseller TINYINT(1) DEFAULT 0,
  is_active     TINYINT(1) DEFAULT 1,
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
);

-- ─── ORDERS ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS orders (
  id               INT AUTO_INCREMENT PRIMARY KEY,
  order_number     VARCHAR(30) NOT NULL UNIQUE,
  user_id          INT NOT NULL,
  subtotal         DECIMAL(10,2) NOT NULL,
  gst              DECIMAL(10,2) DEFAULT 0,
  total            DECIMAL(10,2) NOT NULL,
  shipping_address TEXT NOT NULL,
  payment_method   ENUM('cod','upi','card','netbanking') DEFAULT 'cod',
  payment_status   ENUM('pending','paid','failed','refunded') DEFAULT 'pending',
  status           ENUM('pending','confirmed','processing','shipped','delivered','cancelled') DEFAULT 'pending',
  tracking_number  VARCHAR(100),
  notes            TEXT,
  created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ─── ORDER ITEMS ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS order_items (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  order_id   INT NOT NULL,
  product_id INT NOT NULL,
  qty        INT NOT NULL DEFAULT 1,
  price      DECIMAL(10,2) NOT NULL,
  FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
  FOREIGN KEY (product_id) REFERENCES products(id)
);

-- ─── ENQUIRIES ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS enquiries (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(120),
  email      VARCHAR(180),
  phone      VARCHAR(20),
  message    TEXT,
  is_read    TINYINT(1) DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ═══════════════════════════════════════════════════════════
--   SEED DATA
-- ═══════════════════════════════════════════════════════════

-- Categories
INSERT INTO categories (name, slug, icon, sort_order) VALUES
  ('Laser Printer Parts',     'laser',    '🖨️', 1),
  ('DMP Printer Parts',       'dmp',      '⚙️', 2),
  ('Inkjet Printer Parts',    'inkjet',   '💧', 3),
  ('Scanner Parts',           'scanner',  '🔎', 4),
  ('Thermal/POS Printer Parts','thermal', '🧾', 5),
  ('Toner Spare Parts',       'toner',    '🖤', 6),
  ('Complete Printer',        'complete', '🖥️', 7),
  ('Drum Units',              'drum',     '🥁', 8)
ON DUPLICATE KEY UPDATE name=name;

-- Admin user (password: Admin@1234)
INSERT INTO users (name, email, phone, password, role) VALUES
  ('Admin', 'admin@printerpartspoint.in', '9990774445',
   '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhy', 'admin')
ON DUPLICATE KEY UPDATE email=email;

-- Sample Products
INSERT INTO products (name, description, sku, category_id, price, old_price, stock, is_new, is_bestseller) VALUES
  ('104A Drum Unit / W1104A For HP Neverstop Laser MFP 1200a / 1200W / 1000a (New Original)',
   'Genuine HP drum unit compatible with HP Neverstop Laser series. Original import quality.',
   'W1104A-DRUM', 1, 1949.00, 6274.00, 50, 1, 0),

  ('Pressure Roller For HP M252/M254/M255dw/M277n/M154/M181/LBP611/LBP643cdw (New Import) Foam Quality',
   'High quality pressure roller for HP Color LaserJet series.',
   'PR-HP-M252', 1, 649.00, 1500.00, 100, 1, 0),

  ('CF226A / CF226X 26A Toner Cartridge For HP LaserJet Pro M402/MFP M426 (Compatible)',
   'Compatible toner cartridge with high yield output. Great print quality.',
   'CF226A-TONER', 6, 899.00, 2200.00, 200, 0, 1),

  ('Fuser Assembly For HP LaserJet P2035/P2055 (RM1-6405) 110V Refurbished',
   'Professionally refurbished fuser unit. Tested and guaranteed.',
   'RM1-6405-FUSER', 1, 1299.00, 3500.00, 30, 0, 1),

  ('Ink Absorber Pad Kit For Epson L120/L130/L220/L360/L380 Full Set',
   'Complete ink absorber pad set for Epson EcoTank printers.',
   'EPSON-L-PAD', 3, 299.00, 799.00, 300, 0, 1),

  ('Transfer Belt (ITB) For HP Color LaserJet Pro M254/M280/M281 (RM2-6454)',
   'Original compatible transfer belt for HP Color series.',
   'RM2-6454-ITB', 1, 2499.00, 6000.00, 20, 1, 0),

  ('Scanner Glass Flatbed For Canon MF3010/MF211/MF212/MF215 (Original)',
   'Original glass replacement for Canon scanner flatbed.',
   'CANON-MF-GLASS', 4, 549.00, 1200.00, 40, 0, 1),

  ('Thermal Print Head For Zebra GK420D / GK420T 203DPI (New Compatible)',
   'New compatible thermal print head for Zebra label printers.',
   'ZEBRA-GK420-HEAD', 5, 3499.00, 8000.00, 15, 1, 0);
