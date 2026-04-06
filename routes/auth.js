const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const db = require('../database/init');

// GET /giris - Login page
router.get('/giris', (req, res) => {
  if (req.user) return res.redirect('/');
  res.render('auth/login', {
    title: 'Giriş Yap',
    error: req.query.error || null,
    success: req.query.success || null
  });
});

// POST /giris - Handle login
router.post('/giris', (req, res) => {
  const { email, password, remember } = req.body;
  if (!email || !password) {
    return res.render('auth/login', { title: 'Giriş Yap', error: 'E-posta ve şifre gereklidir.', success: null });
  }

  db.get(`SELECT * FROM users WHERE email = ? OR username = ?`, [email, email], (err, user) => {
    if (err || !user) {
      return res.render('auth/login', { title: 'Giriş Yap', error: 'E-posta veya şifre hatalı.', success: null });
    }
    if (user.is_banned) {
      return res.render('auth/login', { title: 'Giriş Yap', error: `Hesabınız yasaklandı: ${user.ban_reason || 'Kural ihlali'}`, success: null });
    }
    if (!bcrypt.compareSync(password, user.password)) {
      return res.render('auth/login', { title: 'Giriş Yap', error: 'E-posta veya şifre hatalı.', success: null });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: remember ? '30d' : '1d' }
    );

    req.session.token = token;
    db.run(`UPDATE users SET last_login = datetime('now') WHERE id = ?`, [user.id]);

    const returnTo = req.session.returnTo || '/';
    delete req.session.returnTo;
    res.redirect(returnTo);
  });
});

// GET /kayit - Register page
router.get('/kayit', (req, res) => {
  if (req.user) return res.redirect('/');
  res.render('auth/register', { title: 'Kayıt Ol', error: null, success: null });
});

// POST /kayit - Handle registration
router.post('/kayit', (req, res) => {
  const { username, email, password, password2 } = req.body;

  if (!username || !email || !password || !password2) {
    return res.render('auth/register', { title: 'Kayıt Ol', error: 'Tüm alanları doldurunuz.', success: null });
  }
  if (password !== password2) {
    return res.render('auth/register', { title: 'Kayıt Ol', error: 'Şifreler eşleşmiyor.', success: null });
  }
  if (password.length < 6) {
    return res.render('auth/register', { title: 'Kayıt Ol', error: 'Şifre en az 6 karakter olmalıdır.', success: null });
  }
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return res.render('auth/register', { title: 'Kayıt Ol', error: 'Kullanıcı adı 3-20 karakter, sadece harf/rakam/alt çizgi içerebilir.', success: null });
  }

  db.get(`SELECT id FROM users WHERE email = ? OR username = ?`, [email, username], (err, existing) => {
    if (existing) {
      return res.render('auth/register', { title: 'Kayıt Ol', error: 'Bu e-posta veya kullanıcı adı zaten kullanılıyor.', success: null });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    db.run(
      `INSERT INTO users (uuid, username, email, password) VALUES (?, ?, ?, ?)`,
      [uuidv4(), username, email, hashedPassword],
      function (err) {
        if (err) {
          return res.render('auth/register', { title: 'Kayıt Ol', error: 'Kayıt sırasında bir hata oluştu.', success: null });
        }
        // Auto-login after register
        const userId = this.lastID;
        const token = jwt.sign(
          { id: userId, email, role: 'user' },
          process.env.JWT_SECRET || 'secret',
          { expiresIn: '1d' }
        );
        req.session.token = token;

        // Welcome notification
        db.run(`INSERT INTO notifications (user_id, type, title, message, link) VALUES (?, 'welcome', 'Hoş Geldiniz!', 'HesapSat ailesine hoş geldiniz. İlk ilanınızı oluşturmak için hazır mısınız?', '/ilan-ekle')`,
          [userId]);

        res.redirect('/?success=register');
      }
    );
  });
});

// GET /cikis - Logout
router.get('/cikis', (req, res) => {
  req.session.destroy();
  res.redirect('/?success=logout');
});

module.exports = router;
