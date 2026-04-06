const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const dbPath = process.env.DB_PATH || './database/marketplace.db';
const dbDir = path.dirname(dbPath);

if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new sqlite3.Database(dbPath);

function initDB() {
  db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      uuid TEXT UNIQUE NOT NULL,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      avatar TEXT DEFAULT NULL,
      bio TEXT DEFAULT NULL,
      phone TEXT DEFAULT NULL,
      balance REAL DEFAULT 0.00,
      is_verified INTEGER DEFAULT 0,
      is_banned INTEGER DEFAULT 0,
      ban_reason TEXT DEFAULT NULL,
      total_sales INTEGER DEFAULT 0,
      total_purchases INTEGER DEFAULT 0,
      rating REAL DEFAULT 0.0,
      rating_count INTEGER DEFAULT 0,
      last_login TEXT DEFAULT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    )`);

    // Categories table
    db.run(`CREATE TABLE IF NOT EXISTS categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      description TEXT,
      icon TEXT DEFAULT '🎮',
      parent_id INTEGER DEFAULT NULL,
      listing_count INTEGER DEFAULT 0,
      sort_order INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    )`);

    // Listings table
    db.run(`CREATE TABLE IF NOT EXISTS listings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      uuid TEXT UNIQUE NOT NULL,
      user_id INTEGER NOT NULL,
      category_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      price REAL NOT NULL,
      currency TEXT DEFAULT 'TRY',
      status TEXT DEFAULT 'active',
      delivery_type TEXT DEFAULT 'digital',
      images TEXT DEFAULT '[]',
      tags TEXT DEFAULT '[]',
      view_count INTEGER DEFAULT 0,
      favorite_count INTEGER DEFAULT 0,
      is_featured INTEGER DEFAULT 0,
      is_urgent INTEGER DEFAULT 0,
      approved INTEGER DEFAULT 1,
      rejection_reason TEXT DEFAULT NULL,
      expires_at TEXT DEFAULT NULL,
      sold_at TEXT DEFAULT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (category_id) REFERENCES categories(id)
    )`);

    // Messages table
    db.run(`CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      conversation_id TEXT NOT NULL,
      sender_id INTEGER NOT NULL,
      receiver_id INTEGER NOT NULL,
      listing_id INTEGER DEFAULT NULL,
      content TEXT NOT NULL,
      is_read INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (sender_id) REFERENCES users(id),
      FOREIGN KEY (receiver_id) REFERENCES users(id)
    )`);

    // Conversations table
    db.run(`CREATE TABLE IF NOT EXISTS conversations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      uuid TEXT UNIQUE NOT NULL,
      user1_id INTEGER NOT NULL,
      user2_id INTEGER NOT NULL,
      listing_id INTEGER DEFAULT NULL,
      last_message TEXT DEFAULT NULL,
      last_message_at TEXT DEFAULT NULL,
      user1_unread INTEGER DEFAULT 0,
      user2_unread INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user1_id) REFERENCES users(id),
      FOREIGN KEY (user2_id) REFERENCES users(id)
    )`);

    // Transactions / Payments table
    db.run(`CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      uuid TEXT UNIQUE NOT NULL,
      buyer_id INTEGER NOT NULL,
      seller_id INTEGER NOT NULL,
      listing_id INTEGER NOT NULL,
      amount REAL NOT NULL,
      platform_fee REAL DEFAULT 0.00,
      seller_amount REAL NOT NULL,
      status TEXT DEFAULT 'pending',
      payment_method TEXT DEFAULT 'balance',
      payment_ref TEXT DEFAULT NULL,
      notes TEXT DEFAULT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (buyer_id) REFERENCES users(id),
      FOREIGN KEY (seller_id) REFERENCES users(id),
      FOREIGN KEY (listing_id) REFERENCES listings(id)
    )`);

    // Favorites table
    db.run(`CREATE TABLE IF NOT EXISTS favorites (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      listing_id INTEGER NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      UNIQUE(user_id, listing_id),
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (listing_id) REFERENCES listings(id)
    )`);

    // Reviews table
    db.run(`CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      transaction_id INTEGER NOT NULL,
      reviewer_id INTEGER NOT NULL,
      reviewed_id INTEGER NOT NULL,
      rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
      comment TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      UNIQUE(transaction_id, reviewer_id),
      FOREIGN KEY (reviewer_id) REFERENCES users(id),
      FOREIGN KEY (reviewed_id) REFERENCES users(id)
    )`);

    // Notifications table
    db.run(`CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      link TEXT DEFAULT NULL,
      is_read INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    // Balance transactions table
    db.run(`CREATE TABLE IF NOT EXISTS balance_transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      amount REAL NOT NULL,
      balance_after REAL NOT NULL,
      description TEXT,
      ref_id TEXT DEFAULT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    // Site settings table
    db.run(`CREATE TABLE IF NOT EXISTS settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT UNIQUE NOT NULL,
      value TEXT,
      updated_at TEXT DEFAULT (datetime('now'))
    )`);

    // Seed default categories
    const categories = [
      { name: 'Oyun Hesapları', slug: 'oyun-hesaplari', icon: '🎮', desc: 'Her türlü oyun hesabı' },
      { name: 'Steam', slug: 'steam', icon: '🎮', desc: 'Steam hesapları ve oyunlar', parent: 'oyun-hesaplari' },
      { name: 'League of Legends', slug: 'league-of-legends', icon: '⚔️', desc: 'LoL hesapları', parent: 'oyun-hesaplari' },
      { name: 'Valorant', slug: 'valorant', icon: '🔫', desc: 'Valorant hesapları', parent: 'oyun-hesaplari' },
      { name: 'PUBG', slug: 'pubg', icon: '🪖', desc: 'PUBG hesapları', parent: 'oyun-hesaplari' },
      { name: 'Sosyal Medya', slug: 'sosyal-medya', icon: '📱', desc: 'Sosyal medya hesapları' },
      { name: 'Instagram', slug: 'instagram', icon: '📸', desc: 'Instagram hesapları', parent: 'sosyal-medya' },
      { name: 'TikTok', slug: 'tiktok', icon: '🎵', desc: 'TikTok hesapları', parent: 'sosyal-medya' },
      { name: 'YouTube', slug: 'youtube', icon: '▶️', desc: 'YouTube kanalları', parent: 'sosyal-medya' },
      { name: 'Dijital Ürünler', slug: 'dijital-urunler', icon: '💾', desc: 'Dijital ürünler ve lisanslar' },
      { name: 'Netflix & Streaming', slug: 'netflix-streaming', icon: '🎬', desc: 'Streaming hesapları', parent: 'dijital-urunler' },
      { name: 'Yazılım Lisansları', slug: 'yazilim-lisanslari', icon: '🔑', desc: 'Yazılım lisansları', parent: 'dijital-urunler' },
      { name: 'E-posta Hesapları', slug: 'eposta-hesaplari', icon: '📧', desc: 'E-posta hesapları' },
      { name: 'Kripto & NFT', slug: 'kripto-nft', icon: '₿', desc: 'Kripto para ve NFT' },
      { name: 'Diğer', slug: 'diger', icon: '📦', desc: 'Diğer dijital ürünler' },
    ];

    // Insert top-level categories first
    const topLevel = categories.filter(c => !c.parent);
    const stmt = db.prepare(`INSERT OR IGNORE INTO categories (name, slug, description, icon, parent_id, sort_order) VALUES (?, ?, ?, ?, NULL, ?)`);
    topLevel.forEach((cat, idx) => {
      stmt.run(cat.name, cat.slug, cat.desc, cat.icon, idx);
    });
    stmt.finalize();

    // Insert sub-categories
    setTimeout(() => {
      const subLevel = categories.filter(c => c.parent);
      subLevel.forEach((cat) => {
        db.get(`SELECT id FROM categories WHERE slug = ?`, [cat.parent], (err, row) => {
          if (row) {
            db.run(`INSERT OR IGNORE INTO categories (name, slug, description, icon, parent_id) VALUES (?, ?, ?, ?, ?)`,
              [cat.name, cat.slug, cat.desc, cat.icon, row.id]);
          }
        });
      });
    }, 500);

    // Seed default settings
    const defaultSettings = [
      ['site_name', 'HesapSat'],
      ['site_description', 'Türkiye\'nin en güvenilir dijital hesap ve ürün pazaryeri'],
      ['platform_fee', '5'],
      ['min_withdrawal', '50'],
      ['max_upload_size', '5'],
      ['listing_duration_days', '30'],
      ['maintenance_mode', '0'],
      ['registration_open', '1'],
      ['featured_price', '29.99'],
      ['urgent_price', '19.99'],
    ];

    const settingStmt = db.prepare(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`);
    defaultSettings.forEach(([key, value]) => settingStmt.run(key, value));
    settingStmt.finalize();

    // Seed admin user
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@hesapsat.net';
    const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123!';
    const { v4: uuidv4 } = require('uuid');

    db.get(`SELECT id FROM users WHERE email = ?`, [adminEmail], (err, row) => {
      if (!row) {
        const hashedPassword = bcrypt.hashSync(adminPassword, 10);
        db.run(
          `INSERT INTO users (uuid, username, email, password, role, is_verified) VALUES (?, ?, ?, ?, 'admin', 1)`,
          [uuidv4(), 'admin', adminEmail, hashedPassword],
          function (err) {
            if (!err) {
              // Seed demo listings
              seedDemoData(this.lastID);
            }
          }
        );
      }
    });

    // Seed demo user
    setTimeout(() => {
      db.get(`SELECT id FROM users WHERE email = ?`, ['demo@hesapsat.net'], (err, row) => {
        if (!row) {
          const hashedPassword = bcrypt.hashSync('Demo123!', 10);
          db.run(
            `INSERT INTO users (uuid, username, email, password, role, is_verified, balance) VALUES (?, ?, ?, ?, 'user', 1, 250.00)`,
            [uuidv4(), 'demo_kullanici', 'demo@hesapsat.net', hashedPassword]
          );
        }
      });
    }, 1000);
  });
}

function seedDemoData(adminId) {
  const { v4: uuidv4 } = require('uuid');
  const demoListings = [
    { title: 'League of Legends Diamond 1 Hesap', desc: 'Diamond 1 rank, 200+ skin, tüm şampiyonlar açık. Garanti ile satılır.', price: 1500, cat: 'league-of-legends' },
    { title: 'Steam 500 Oyunlu Hesap', desc: 'Steam hesabı 500+ oyun, 2000+ saat toplam oynama süresi. Temiz hesap.', price: 800, cat: 'steam' },
    { title: 'Instagram 50K Takipçili Hesap', desc: 'Organik takipçili, aktif Instagram hesabı. Türkiye bazlı takipçiler.', price: 2500, cat: 'instagram' },
    { title: 'Netflix 1 Yıllık Premium Hesap', desc: '4K Ultra HD, 4 ekran Netflix premium. 12 ay garantili.', price: 350, cat: 'netflix-streaming' },
    { title: 'Valorant Immortal Hesap', desc: 'Immortal rank, 30+ ajan açık, 15+ skin seti. Türk hesabı.', price: 950, cat: 'valorant' },
    { title: 'YouTube 10K Aboneli Kanal', desc: 'Oyun kategorisinde 10K abone, monetizasyon açık kanal.', price: 3500, cat: 'youtube' },
  ];

  setTimeout(() => {
    demoListings.forEach((listing) => {
      db.get(`SELECT id FROM categories WHERE slug = ?`, [listing.cat], (err, cat) => {
        if (cat) {
          db.run(
            `INSERT INTO listings (uuid, user_id, category_id, title, description, price, is_featured, approved) VALUES (?, ?, ?, ?, ?, ?, ?, 1)`,
            [uuidv4(), adminId, cat.id, listing.title, listing.desc, listing.price, Math.random() > 0.5 ? 1 : 0]
          );
        }
      });
    });
  }, 1500);
}

initDB();

module.exports = db;
