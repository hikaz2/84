const express = require('express');
const router = express.Router();
const db = require('../database/init');
const { requireAuth } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/admin');

// All admin routes require auth + admin role
router.use(requireAuth, requireAdmin);

// GET /admin - Dashboard
router.get('/', (req, res) => {
  db.get(`SELECT COUNT(*) as total FROM users`, (err, users) => {
    db.get(`SELECT COUNT(*) as total FROM listings WHERE status != 'deleted'`, (err, listings) => {
      db.get(`SELECT COUNT(*) as total FROM transactions WHERE status = 'completed'`, (err, transactions) => {
        db.get(`SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE status = 'completed'`, (err, revenue) => {
          db.get(`SELECT COUNT(*) as total FROM listings WHERE approved = 0 AND status = 'active'`, (err, pending) => {
            db.all(`SELECT l.*, u.username, c.name as category_name FROM listings l JOIN users u ON l.user_id = u.id JOIN categories c ON l.category_id = c.id WHERE l.approved = 0 AND l.status = 'active' ORDER BY l.created_at DESC LIMIT 5`,
              (err, pendingListings) => {
              db.all(`SELECT * FROM users ORDER BY created_at DESC LIMIT 5`, (err, recentUsers) => {
                db.all(`SELECT t.*, b.username as buyer_name, s.username as seller_name, l.title as listing_title FROM transactions t JOIN users b ON t.buyer_id = b.id JOIN users s ON t.seller_id = s.id JOIN listings l ON t.listing_id = l.id ORDER BY t.created_at DESC LIMIT 5`,
                  (err, recentTx) => {
                  res.render('admin/dashboard', {
                    title: 'Yönetici Paneli',
                    stats: {
                      users: users ? users.total : 0,
                      listings: listings ? listings.total : 0,
                      transactions: transactions ? transactions.total : 0,
                      revenue: revenue ? revenue.total : 0,
                      pendingListings: pending ? pending.total : 0,
                    },
                    pendingListings: pendingListings || [],
                    recentUsers: recentUsers || [],
                    recentTx: recentTx || []
                  });
                });
              });
            });
          });
        });
      });
    });
  });
});

// GET /admin/kullanicilar - User management
router.get('/kullanicilar', (req, res) => {
  const { arama, rol, sayfa } = req.query;
  const page = parseInt(sayfa) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;

  let query = `SELECT * FROM users WHERE 1=1`;
  const params = [];

  if (arama) {
    query += ` AND (username LIKE ? OR email LIKE ?)`;
    params.push(`%${arama}%`, `%${arama}%`);
  }
  if (rol) {
    query += ` AND role = ?`;
    params.push(rol);
  }

  const countQuery = query.replace('SELECT *', 'SELECT COUNT(*) as total');
  db.get(countQuery, params, (err, countRow) => {
    const total = countRow ? countRow.total : 0;
    query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);
    db.all(query, params, (err, users) => {
      res.render('admin/users', {
        title: 'Kullanıcı Yönetimi',
        users: users || [],
        total,
        page,
        totalPages: Math.ceil(total / limit),
        arama, rol
      });
    });
  });
});

// POST /admin/kullanicilar/:id/ban - Ban user
router.post('/kullanicilar/:id/ban', (req, res) => {
  const { reason } = req.body;
  db.run(`UPDATE users SET is_banned = 1, ban_reason = ? WHERE id = ? AND role != 'admin'`,
    [reason || 'Kural ihlali', req.params.id], () => {
    res.redirect('/admin/kullanicilar?success=banned');
  });
});

// POST /admin/kullanicilar/:id/unban - Unban user
router.post('/kullanicilar/:id/unban', (req, res) => {
  db.run(`UPDATE users SET is_banned = 0, ban_reason = NULL WHERE id = ?`, [req.params.id], () => {
    res.redirect('/admin/kullanicilar?success=unbanned');
  });
});

// POST /admin/kullanicilar/:id/rol - Change user role
router.post('/kullanicilar/:id/rol', (req, res) => {
  const { role } = req.body;
  if (!['user', 'admin', 'moderator'].includes(role)) return res.redirect('/admin/kullanicilar');
  db.run(`UPDATE users SET role = ? WHERE id = ? AND id != ?`, [role, req.params.id, req.user.id], () => {
    res.redirect('/admin/kullanicilar?success=role_changed');
  });
});

// GET /admin/ilanlar - Listing management
router.get('/ilanlar', (req, res) => {
  const { arama, durum, sayfa } = req.query;
  const page = parseInt(sayfa) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;

  let query = `SELECT l.*, u.username, c.name as category_name FROM listings l JOIN users u ON l.user_id = u.id JOIN categories c ON l.category_id = c.id WHERE l.status != 'deleted'`;
  const params = [];

  if (arama) {
    query += ` AND (l.title LIKE ? OR u.username LIKE ?)`;
    params.push(`%${arama}%`, `%${arama}%`);
  }
  if (durum === 'pending') {
    query += ` AND l.approved = 0`;
  } else if (durum === 'active') {
    query += ` AND l.status = 'active' AND l.approved = 1`;
  } else if (durum === 'sold') {
    query += ` AND l.status = 'sold'`;
  }

  const countQuery = query.replace(/SELECT l\.\*.*FROM/, 'SELECT COUNT(*) as total FROM').replace(/ORDER BY.*$/, '');
  db.get(countQuery, params, (err, countRow) => {
    const total = countRow ? countRow.total : 0;
    query += ` ORDER BY l.created_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);
    db.all(query, params, (err, listings) => {
      res.render('admin/listings', {
        title: 'İlan Yönetimi',
        listings: listings || [],
        total, page,
        totalPages: Math.ceil(total / limit),
        arama, durum
      });
    });
  });
});

// POST /admin/ilanlar/:id/onayla - Approve listing
router.post('/ilanlar/:id/onayla', (req, res) => {
  db.get(`SELECT * FROM listings WHERE id = ?`, [req.params.id], (err, listing) => {
    if (listing) {
      db.run(`UPDATE listings SET approved = 1 WHERE id = ?`, [req.params.id]);
      db.run(`INSERT INTO notifications (user_id, type, title, message, link) VALUES (?, 'listing', 'İlan Onaylandı', ?, ?)`,
        [listing.user_id, `"${listing.title}" ilanınız onaylandı ve yayınlandı.`, `/ilanlar/${listing.uuid}`]);
    }
    res.redirect('/admin/ilanlar?durum=pending&success=approved');
  });
});

// POST /admin/ilanlar/:id/reddet - Reject listing
router.post('/ilanlar/:id/reddet', (req, res) => {
  const { reason } = req.body;
  db.get(`SELECT * FROM listings WHERE id = ?`, [req.params.id], (err, listing) => {
    if (listing) {
      db.run(`UPDATE listings SET approved = 0, rejection_reason = ?, status = 'rejected' WHERE id = ?`, [reason || 'Kurallara uymuyor', req.params.id]);
      db.run(`INSERT INTO notifications (user_id, type, title, message, link) VALUES (?, 'listing', 'İlan Reddedildi', ?, '/profil/ilanlarim')`,
        [listing.user_id, `"${listing.title}" ilanınız reddedildi. Sebep: ${reason || 'Kurallara uymuyor'}`]);
    }
    res.redirect('/admin/ilanlar?durum=pending&success=rejected');
  });
});

// POST /admin/ilanlar/:id/sil - Delete listing (admin)
router.post('/ilanlar/:id/sil', (req, res) => {
  db.run(`UPDATE listings SET status = 'deleted' WHERE id = ?`, [req.params.id], () => {
    res.redirect('/admin/ilanlar?success=deleted');
  });
});

// POST /admin/ilanlar/:id/one-cikan - Toggle featured
router.post('/ilanlar/:id/one-cikan', (req, res) => {
  db.run(`UPDATE listings SET is_featured = NOT is_featured WHERE id = ?`, [req.params.id], () => {
    res.redirect('/admin/ilanlar?success=featured_toggled');
  });
});

// GET /admin/islemler - Transaction management
router.get('/islemler', (req, res) => {
  const { sayfa } = req.query;
  const page = parseInt(sayfa) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;

  db.get(`SELECT COUNT(*) as total FROM transactions`, (err, countRow) => {
    const total = countRow ? countRow.total : 0;
    db.all(`
      SELECT t.*, b.username as buyer_name, s.username as seller_name, l.title as listing_title
      FROM transactions t JOIN users b ON t.buyer_id = b.id JOIN users s ON t.seller_id = s.id JOIN listings l ON t.listing_id = l.id
      ORDER BY t.created_at DESC LIMIT ? OFFSET ?
    `, [limit, offset], (err, transactions) => {
      res.render('admin/transactions', {
        title: 'İşlem Yönetimi',
        transactions: transactions || [],
        total, page,
        totalPages: Math.ceil(total / limit)
      });
    });
  });
});

// GET /admin/ayarlar - Site settings
router.get('/ayarlar', (req, res) => {
  db.all(`SELECT * FROM settings ORDER BY key`, (err, settings) => {
    const settingsMap = {};
    (settings || []).forEach(s => settingsMap[s.key] = s.value);
    res.render('admin/settings', {
      title: 'Site Ayarları',
      settings: settingsMap,
      success: req.query.success || null
    });
  });
});

// POST /admin/ayarlar - Save settings
router.post('/ayarlar', (req, res) => {
  const { site_name, site_description, platform_fee, min_withdrawal, listing_duration_days, maintenance_mode, registration_open } = req.body;
  const updates = [
    ['site_name', site_name],
    ['site_description', site_description],
    ['platform_fee', platform_fee],
    ['min_withdrawal', min_withdrawal],
    ['listing_duration_days', listing_duration_days],
    ['maintenance_mode', maintenance_mode ? '1' : '0'],
    ['registration_open', registration_open ? '1' : '0'],
  ];
  updates.forEach(([key, value]) => {
    db.run(`INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))`, [key, value]);
  });
  res.redirect('/admin/ayarlar?success=1');
});

module.exports = router;
