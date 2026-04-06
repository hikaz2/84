const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const db = require('../database/init');
const { requireAuth } = require('../middleware/auth');

// Multer for avatar upload
const uploadDir = path.join(__dirname, '../public/uploads/avatars');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `avatar_${req.user.id}_${Date.now()}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.webp'];
    if (allowed.includes(path.extname(file.originalname).toLowerCase())) cb(null, true);
    else cb(new Error('Sadece jpg/png/webp formatı desteklenmektedir.'));
  }
});

// GET /profil - My profile
router.get('/', requireAuth, (req, res) => {
  db.all(`
    SELECT l.*, c.name as category_name FROM listings l JOIN categories c ON l.category_id = c.id
    WHERE l.user_id = ? AND l.status != 'deleted' ORDER BY l.created_at DESC LIMIT 5
  `, [req.user.id], (err, listings) => {
    db.all(`
      SELECT t.*, l.title as listing_title, l.uuid as listing_uuid, u.username as other_username
      FROM transactions t JOIN listings l ON t.listing_id = l.id
      JOIN users u ON (CASE WHEN t.buyer_id = ? THEN t.seller_id ELSE t.buyer_id END) = u.id
      WHERE t.buyer_id = ? OR t.seller_id = ?
      ORDER BY t.created_at DESC LIMIT 5
    `, [req.user.id, req.user.id, req.user.id], (err, transactions) => {
      db.all(`SELECT bt.* FROM balance_transactions bt WHERE bt.user_id = ? ORDER BY bt.created_at DESC LIMIT 5`, [req.user.id], (err, balanceTx) => {
        res.render('profile/index', {
          title: 'Profilim',
          profileUser: req.user,
          listings: listings || [],
          transactions: transactions || [],
          balanceTx: balanceTx || []
        });
      });
    });
  });
});

// GET /profil/duzenle - Edit profile
router.get('/duzenle', requireAuth, (req, res) => {
  res.render('profile/edit', { title: 'Profili Düzenle', error: null, success: null });
});

// POST /profil/duzenle - Update profile
router.post('/duzenle', requireAuth, upload.single('avatar'), (req, res) => {
  const { bio, phone, current_password, new_password, new_password2 } = req.body;
  let avatarPath = req.user.avatar;

  if (req.file) {
    avatarPath = `/uploads/avatars/${req.file.filename}`;
  }

  // Password change
  if (new_password) {
    if (!current_password || !bcrypt.compareSync(current_password, req.user.password)) {
      return res.render('profile/edit', { title: 'Profili Düzenle', error: 'Mevcut şifre hatalı.', success: null });
    }
    if (new_password !== new_password2) {
      return res.render('profile/edit', { title: 'Profili Düzenle', error: 'Yeni şifreler eşleşmiyor.', success: null });
    }
    if (new_password.length < 6) {
      return res.render('profile/edit', { title: 'Profili Düzenle', error: 'Şifre en az 6 karakter olmalıdır.', success: null });
    }
    const hashedPassword = bcrypt.hashSync(new_password, 10);
    db.run(`UPDATE users SET bio=?, phone=?, avatar=?, password=?, updated_at=datetime('now') WHERE id=?`,
      [bio || null, phone || null, avatarPath, hashedPassword, req.user.id]);
  } else {
    db.run(`UPDATE users SET bio=?, phone=?, avatar=?, updated_at=datetime('now') WHERE id=?`,
      [bio || null, phone || null, avatarPath, req.user.id]);
  }

  res.render('profile/edit', { title: 'Profili Düzenle', error: null, success: 'Profiliniz güncellendi.' });
});

// GET /profil/ilanlarim - My listings
router.get('/ilanlarim', requireAuth, (req, res) => {
  db.all(`
    SELECT l.*, c.name as category_name FROM listings l JOIN categories c ON l.category_id = c.id
    WHERE l.user_id = ? AND l.status != 'deleted' ORDER BY l.created_at DESC
  `, [req.user.id], (err, listings) => {
    res.render('profile/my-listings', {
      title: 'İlanlarım',
      listings: (listings || []).map(l => ({ ...l, images: JSON.parse(l.images || '[]'), tags: JSON.parse(l.tags || '[]') })),
      success: req.query.success || null
    });
  });
});

// GET /profil/favorilerim - My favorites
router.get('/favorilerim', requireAuth, (req, res) => {
  db.all(`
    SELECT l.*, c.name as category_name, u.username
    FROM favorites f
    JOIN listings l ON f.listing_id = l.id
    JOIN categories c ON l.category_id = c.id
    JOIN users u ON l.user_id = u.id
    WHERE f.user_id = ? AND l.status = 'active'
    ORDER BY f.created_at DESC
  `, [req.user.id], (err, listings) => {
    res.render('profile/favorites', { title: 'Favorilerim', listings: listings || [] });
  });
});

// GET /profil/islemler - My transactions
router.get('/islemler', requireAuth, (req, res) => {
  db.all(`
    SELECT t.*, l.title as listing_title, l.uuid as listing_uuid,
           b.username as buyer_username, s.username as seller_username
    FROM transactions t
    JOIN listings l ON t.listing_id = l.id
    JOIN users b ON t.buyer_id = b.id
    JOIN users s ON t.seller_id = s.id
    WHERE t.buyer_id = ? OR t.seller_id = ?
    ORDER BY t.created_at DESC
  `, [req.user.id, req.user.id], (err, transactions) => {
    res.render('profile/transactions', {
      title: 'İşlemlerim',
      transactions: transactions || [],
      userId: req.user.id
    });
  });
});

// GET /profil/bildirimler - Notifications
router.get('/bildirimler', requireAuth, (req, res) => {
  db.all(`SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`, [req.user.id], (err, notifications) => {
    db.run(`UPDATE notifications SET is_read = 1 WHERE user_id = ?`, [req.user.id]);
    res.render('profile/notifications', { title: 'Bildirimlerim', notifications: notifications || [] });
  });
});

// GET /profil/:username - Public profile
router.get('/:username', (req, res) => {
  db.get(`SELECT id, username, avatar, bio, rating, rating_count, total_sales, created_at FROM users WHERE username = ? AND is_banned = 0`,
    [req.params.username], (err, profileUser) => {
    if (!profileUser) return res.status(404).render('error', { title: 'Kullanıcı Bulunamadı', message: 'Bu kullanıcı bulunamadı.', user: req.user || null });
    db.all(`
      SELECT l.*, c.name as category_name FROM listings l JOIN categories c ON l.category_id = c.id
      WHERE l.user_id = ? AND l.status = 'active' AND l.approved = 1 ORDER BY l.created_at DESC LIMIT 12
    `, [profileUser.id], (err, listings) => {
      db.all(`SELECT r.*, u.username as reviewer_username, u.avatar as reviewer_avatar FROM reviews r JOIN users u ON r.reviewer_id = u.id WHERE r.reviewed_id = ? ORDER BY r.created_at DESC LIMIT 10`,
        [profileUser.id], (err, reviews) => {
        res.render('profile/public', {
          title: profileUser.username,
          profileUser,
          listings: listings || [],
          reviews: reviews || [],
          isOwn: req.user && req.user.id === profileUser.id
        });
      });
    });
  });
});

module.exports = router;
