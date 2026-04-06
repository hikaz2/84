const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const db = require('../database/init');
const { requireAuth } = require('../middleware/auth');

// Multer setup for image uploads
const multer = require('multer');
const uploadDir = path.join(__dirname, '../public/uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${uuidv4()}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(new Error('Sadece resim dosyaları yüklenebilir.'));
  }
});

// GET /ilanlar - Browse listings
router.get('/', (req, res) => {
  const { kategori, arama, siralama, min_fiyat, max_fiyat, sayfa } = req.query;
  const page = parseInt(sayfa) || 1;
  const limit = 12;
  const offset = (page - 1) * limit;

  let query = `
    SELECT l.*, u.username, u.avatar, u.rating, c.name as category_name, c.slug as category_slug
    FROM listings l
    JOIN users u ON l.user_id = u.id
    JOIN categories c ON l.category_id = c.id
    WHERE l.status = 'active' AND l.approved = 1
  `;
  const params = [];

  if (kategori) {
    query += ` AND c.slug = ?`;
    params.push(kategori);
  }
  if (arama) {
    query += ` AND (l.title LIKE ? OR l.description LIKE ?)`;
    params.push(`%${arama}%`, `%${arama}%`);
  }
  if (min_fiyat) { query += ` AND l.price >= ?`; params.push(parseFloat(min_fiyat)); }
  if (max_fiyat) { query += ` AND l.price <= ?`; params.push(parseFloat(max_fiyat)); }

  const sortMap = {
    'yeni': 'l.created_at DESC',
    'eski': 'l.created_at ASC',
    'ucuz': 'l.price ASC',
    'pahali': 'l.price DESC',
    'populer': 'l.view_count DESC',
    'one_cikan': 'l.is_featured DESC, l.created_at DESC'
  };
  query += ` ORDER BY l.is_featured DESC, ${sortMap[siralama] || 'l.created_at DESC'}`;

  const countQuery = query.replace(/SELECT l\.\*.*FROM/, 'SELECT COUNT(*) as total FROM').replace(/ORDER BY.*$/, '');

  db.get(countQuery, params, (err, countRow) => {
    const total = countRow ? countRow.total : 0;
    const totalPages = Math.ceil(total / limit);

    query += ` LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    db.all(query, params, (err, listings) => {
      db.all(`SELECT * FROM categories WHERE parent_id IS NULL ORDER BY sort_order`, (err, categories) => {
        res.render('listings/index', {
          title: 'İlanlar',
          listings: listings || [],
          categories: categories || [],
          total, totalPages, page,
          kategori, arama, siralama, min_fiyat, max_fiyat
        });
      });
    });
  });
});

// GET /ilan/:id - View single listing
router.get('/:uuid', (req, res) => {
  const { uuid } = req.params;
  db.get(`
    SELECT l.*, u.username, u.avatar, u.rating, u.rating_count, u.total_sales, u.created_at as member_since,
           c.name as category_name, c.slug as category_slug
    FROM listings l
    JOIN users u ON l.user_id = u.id
    JOIN categories c ON l.category_id = c.id
    WHERE l.uuid = ? AND l.approved = 1
  `, [uuid], (err, listing) => {
    if (!listing) {
      return res.status(404).render('error', { title: 'İlan Bulunamadı', message: 'Aradığınız ilan bulunamadı veya kaldırılmış olabilir.', user: req.user || null });
    }

    // Increment view count
    db.run(`UPDATE listings SET view_count = view_count + 1 WHERE id = ?`, [listing.id]);

    // Check if favorited
    let isFavorited = false;
    const checkFav = (callback) => {
      if (req.user) {
        db.get(`SELECT id FROM favorites WHERE user_id = ? AND listing_id = ?`, [req.user.id, listing.id], (err, fav) => {
          isFavorited = !!fav;
          callback();
        });
      } else {
        callback();
      }
    };

    // Get similar listings
    checkFav(() => {
      db.all(`
        SELECT l.*, u.username, c.name as category_name
        FROM listings l JOIN users u ON l.user_id = u.id JOIN categories c ON l.category_id = c.id
        WHERE l.category_id = ? AND l.id != ? AND l.status = 'active' AND l.approved = 1
        ORDER BY l.created_at DESC LIMIT 4
      `, [listing.category_id, listing.id], (err, similar) => {
        db.all(`SELECT r.*, u.username, u.avatar FROM reviews r JOIN users u ON r.reviewer_id = u.id WHERE r.reviewed_id = ? ORDER BY r.created_at DESC LIMIT 5`,
          [listing.user_id], (err, reviews) => {
          res.render('listings/show', {
            title: listing.title,
            listing: { ...listing, images: JSON.parse(listing.images || '[]'), tags: JSON.parse(listing.tags || '[]') },
            similar: similar || [],
            reviews: reviews || [],
            isFavorited
          });
        });
      });
    });
  });
});

// GET /ilan-ekle - Create listing form
router.get('/yeni/ekle', requireAuth, (req, res) => {
  db.all(`SELECT * FROM categories ORDER BY sort_order, parent_id, name`, (err, categories) => {
    res.render('listings/create', { title: 'İlan Ekle', categories: categories || [], error: null });
  });
});

// POST /ilan-ekle - Create listing
router.post('/yeni/ekle', requireAuth, upload.array('images', 5), (req, res) => {
  const { title, description, price, category_id, delivery_type, tags, is_urgent } = req.body;

  if (!title || !description || !price || !category_id) {
    return res.render('listings/create', { title: 'İlan Ekle', categories: [], error: 'Tüm zorunlu alanları doldurunuz.' });
  }

  const images = req.files ? req.files.map(f => `/uploads/${f.filename}`) : [];
  const tagsArr = tags ? tags.split(',').map(t => t.trim()).filter(Boolean) : [];
  const listingUuid = uuidv4();

  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 30);

  db.run(
    `INSERT INTO listings (uuid, user_id, category_id, title, description, price, delivery_type, images, tags, is_urgent, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [listingUuid, req.user.id, category_id, title, description, parseFloat(price),
     delivery_type || 'digital', JSON.stringify(images), JSON.stringify(tagsArr),
     is_urgent ? 1 : 0, expiresAt.toISOString()],
    function (err) {
      if (err) {
        return res.render('listings/create', { title: 'İlan Ekle', categories: [], error: 'İlan oluşturulurken hata oluştu.' });
      }
      // Update category listing count
      db.run(`UPDATE categories SET listing_count = listing_count + 1 WHERE id = ?`, [category_id]);
      res.redirect(`/ilanlar/${listingUuid}?success=created`);
    }
  );
});

// GET /ilanlarim/duzenle/:uuid - Edit listing
router.get('/duzenle/:uuid', requireAuth, (req, res) => {
  db.get(`SELECT * FROM listings WHERE uuid = ? AND user_id = ?`, [req.params.uuid, req.user.id], (err, listing) => {
    if (!listing) return res.redirect('/profil/ilanlarim');
    db.all(`SELECT * FROM categories ORDER BY sort_order, parent_id, name`, (err, categories) => {
      res.render('listings/edit', {
        title: 'İlanı Düzenle',
        listing: { ...listing, images: JSON.parse(listing.images || '[]'), tags: JSON.parse(listing.tags || '[]') },
        categories: categories || [],
        error: null
      });
    });
  });
});

// POST /ilanlarim/duzenle/:uuid - Update listing
router.post('/duzenle/:uuid', requireAuth, upload.array('images', 5), (req, res) => {
  const { title, description, price, category_id, delivery_type, tags, is_urgent, status } = req.body;
  db.get(`SELECT * FROM listings WHERE uuid = ? AND user_id = ?`, [req.params.uuid, req.user.id], (err, listing) => {
    if (!listing) return res.redirect('/profil/ilanlarim');

    const existingImages = JSON.parse(listing.images || '[]');
    const newImages = req.files ? req.files.map(f => `/uploads/${f.filename}`) : [];
    const images = [...existingImages, ...newImages];
    const tagsArr = tags ? tags.split(',').map(t => t.trim()).filter(Boolean) : [];

    db.run(
      `UPDATE listings SET title=?, description=?, price=?, category_id=?, delivery_type=?, images=?, tags=?, is_urgent=?, status=?, updated_at=datetime('now') WHERE uuid=? AND user_id=?`,
      [title, description, parseFloat(price), category_id, delivery_type || 'digital',
       JSON.stringify(images), JSON.stringify(tagsArr), is_urgent ? 1 : 0, status || listing.status,
       req.params.uuid, req.user.id],
      (err) => {
        if (err) return res.redirect(`/ilanlar/duzenle/${req.params.uuid}?error=1`);
        res.redirect(`/ilanlar/${req.params.uuid}?success=updated`);
      }
    );
  });
});

// POST /ilanlar/sil/:uuid - Delete listing
router.post('/sil/:uuid', requireAuth, (req, res) => {
  db.get(`SELECT * FROM listings WHERE uuid = ? AND user_id = ?`, [req.params.uuid, req.user.id], (err, listing) => {
    if (!listing) return res.redirect('/profil/ilanlarim');
    db.run(`UPDATE listings SET status='deleted' WHERE uuid=?`, [req.params.uuid], () => {
      res.redirect('/profil/ilanlarim?success=deleted');
    });
  });
});

// POST /ilanlar/favori/:uuid - Toggle favorite
router.post('/favori/:uuid', requireAuth, (req, res) => {
  db.get(`SELECT id FROM listings WHERE uuid = ?`, [req.params.uuid], (err, listing) => {
    if (!listing) return res.json({ success: false });
    db.get(`SELECT id FROM favorites WHERE user_id = ? AND listing_id = ?`, [req.user.id, listing.id], (err, fav) => {
      if (fav) {
        db.run(`DELETE FROM favorites WHERE user_id = ? AND listing_id = ?`, [req.user.id, listing.id]);
        db.run(`UPDATE listings SET favorite_count = MAX(0, favorite_count - 1) WHERE id = ?`, [listing.id]);
        res.json({ success: true, favorited: false });
      } else {
        db.run(`INSERT INTO favorites (user_id, listing_id) VALUES (?, ?)`, [req.user.id, listing.id]);
        db.run(`UPDATE listings SET favorite_count = favorite_count + 1 WHERE id = ?`, [listing.id]);
        res.json({ success: true, favorited: true });
      }
    });
  });
});

module.exports = router;
