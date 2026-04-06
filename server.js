require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const helmet = require('helmet');
const morgan = require('morgan');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize database
const db = require('./database/init');

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://js.stripe.com"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'"],
      frameSrc: ["'self'", "https://js.stripe.com"],
    },
  },
}));

// Logging
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('dev'));
}

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static files
app.use(express.static(path.join(__dirname, 'public')));
const uploadDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Session
const SQLiteStore = require('connect-sqlite3')(session);
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: './database' }),
  secret: process.env.SESSION_SECRET || 'fallback_secret_change_in_production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
  }
}));

// Auth middleware (attach user to all requests)
const { optionalAuth } = require('./middleware/auth');
app.use(optionalAuth);

// Global template variables
app.use((req, res, next) => {
  res.locals.siteName = process.env.SITE_NAME || 'HesapSat';
  res.locals.currentPath = req.path;
  next();
});

// Routes
const authRoutes = require('./routes/auth');
const listingsRoutes = require('./routes/listings');
const messagesRoutes = require('./routes/messages');
const paymentsRoutes = require('./routes/payments');
const profileRoutes = require('./routes/profile');
const adminRoutes = require('./routes/admin');

app.use('/', authRoutes);
app.use('/ilanlar', listingsRoutes);
app.use('/mesajlar', messagesRoutes);
app.use('/odeme', paymentsRoutes);
app.use('/bakiye', paymentsRoutes);
app.use('/profil', profileRoutes);
app.use('/admin', adminRoutes);

// Home route
app.get('/', (req, res) => {
  // Featured listings
  db.all(`
    SELECT l.*, u.username, u.avatar, c.name as category_name, c.slug as category_slug
    FROM listings l JOIN users u ON l.user_id = u.id JOIN categories c ON l.category_id = c.id
    WHERE l.status = 'active' AND l.approved = 1 AND l.is_featured = 1
    ORDER BY l.created_at DESC LIMIT 6
  `, (err, featured) => {
    db.all(`
      SELECT l.*, u.username, u.avatar, c.name as category_name, c.slug as category_slug
      FROM listings l JOIN users u ON l.user_id = u.id JOIN categories c ON l.category_id = c.id
      WHERE l.status = 'active' AND l.approved = 1
      ORDER BY l.created_at DESC LIMIT 12
    `, (err2, recent) => {
      db.all(`SELECT * FROM categories WHERE parent_id IS NULL ORDER BY sort_order LIMIT 8`, (err3, categories) => {
        db.get(`SELECT COUNT(*) as count FROM users`, (err4, userCount) => {
          db.get(`SELECT COUNT(*) as count FROM listings WHERE status = 'active' AND approved = 1`, (err5, listingCount) => {
            db.get(`SELECT COUNT(*) as count FROM transactions WHERE status = 'completed'`, (err6, txCount) => {
              res.render('home', {
                title: 'HesapSat - Dijital Hesap ve Ürün Pazaryeri',
                featured: featured || [],
                recent: recent || [],
                categories: categories || [],
                stats: {
                  users: userCount ? userCount.count : 0,
                  listings: listingCount ? listingCount.count : 0,
                  transactions: txCount ? txCount.count : 0
                },
                success: req.query.success || null
              });
            });
          });
        });
      });
    });
  });
});

// Search route
app.get('/ara', (req, res) => {
  res.redirect(`/ilanlar?arama=${encodeURIComponent(req.query.q || '')}`);
});

// About / static pages
app.get('/hakkimizda', (req, res) => res.render('pages/about', { title: 'Hakkımızda' }));
app.get('/iletisim', (req, res) => res.render('pages/contact', { title: 'İletişim', success: null, error: null }));
app.get('/gizlilik', (req, res) => res.render('pages/privacy', { title: 'Gizlilik Politikası' }));
app.get('/kullanim-kosullari', (req, res) => res.render('pages/terms', { title: 'Kullanım Koşulları' }));

// POST /iletisim
app.post('/iletisim', (req, res) => {
  const { name, email, subject, message } = req.body;
  if (!name || !email || !message) {
    return res.render('pages/contact', { title: 'İletişim', error: 'Tüm alanları doldurunuz.', success: null });
  }
  // In production: send email via nodemailer or similar
  res.render('pages/contact', { title: 'İletişim', success: 'Mesajınız alındı. En kısa sürede dönüş yapacağız.', error: null });
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('error', {
    title: 'Sayfa Bulunamadı',
    message: 'Aradığınız sayfa bulunamadı.',
    user: req.user || null
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render('error', {
    title: 'Sunucu Hatası',
    message: process.env.NODE_ENV === 'production' ? 'Bir hata oluştu.' : err.message,
    user: req.user || null
  });
});

app.listen(PORT, () => {
  console.log(`\n🚀 HesapSat sunucusu başlatıldı!`);
  console.log(`📍 URL: http://localhost:${PORT}`);
  console.log(`👤 Admin: ${process.env.ADMIN_EMAIL || 'admin@hesapsat.net'} / ${process.env.ADMIN_PASSWORD || 'Admin123!'}`);
  console.log(`📦 Demo: demo@hesapsat.net / Demo123!\n`);
});

module.exports = app;
