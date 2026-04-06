const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const db = require('../database/init');
const { requireAuth } = require('../middleware/auth');

const PLATFORM_FEE_PERCENT = 5; // 5%

// GET /odeme/:listing_uuid - Payment page
router.get('/:listing_uuid', requireAuth, (req, res) => {
  db.get(`
    SELECT l.*, u.username as seller_username, u.id as seller_id
    FROM listings l JOIN users u ON l.user_id = u.id
    WHERE l.uuid = ? AND l.status = 'active' AND l.approved = 1
  `, [req.params.listing_uuid], (err, listing) => {
    if (!listing) return res.redirect('/ilanlar?error=not_found');
    if (listing.seller_id === req.user.id) return res.redirect(`/ilanlar/${listing.uuid}?error=own_listing`);

    const fee = parseFloat((listing.price * PLATFORM_FEE_PERCENT / 100).toFixed(2));
    const total = parseFloat((listing.price + fee).toFixed(2));

    res.render('payment/checkout', {
      title: 'Satın Al',
      listing: { ...listing, images: JSON.parse(listing.images || '[]') },
      fee, total,
      userBalance: req.user.balance,
      error: req.query.error || null
    });
  });
});

// POST /odeme/:listing_uuid/bakiye - Pay with balance
router.post('/:listing_uuid/bakiye', requireAuth, (req, res) => {
  db.get(`
    SELECT l.*, u.username as seller_username, u.id as seller_id, u.balance as seller_balance
    FROM listings l JOIN users u ON l.user_id = u.id
    WHERE l.uuid = ? AND l.status = 'active' AND l.approved = 1
  `, [req.params.listing_uuid], (err, listing) => {
    if (!listing) return res.redirect('/ilanlar?error=not_found');
    if (listing.seller_id === req.user.id) return res.redirect(`/ilanlar/${listing.uuid}?error=own_listing`);

    const fee = parseFloat((listing.price * PLATFORM_FEE_PERCENT / 100).toFixed(2));
    const total = parseFloat((listing.price + fee).toFixed(2));
    const sellerAmount = parseFloat((listing.price - fee).toFixed(2));

    if (req.user.balance < total) {
      return res.redirect(`/odeme/${listing.uuid}?error=insufficient_balance`);
    }

    const txUuid = uuidv4();

    // Deduct from buyer
    db.run(`UPDATE users SET balance = balance - ? WHERE id = ?`, [total, req.user.id]);
    db.run(`INSERT INTO balance_transactions (user_id, type, amount, balance_after, description, ref_id) VALUES (?, 'purchase', ?, ?, ?, ?)`,
      [req.user.id, -total, req.user.balance - total, `İlan satın alındı: ${listing.title}`, txUuid]);

    // Add to seller
    db.run(`UPDATE users SET balance = balance + ?, total_sales = total_sales + 1 WHERE id = ?`, [sellerAmount, listing.seller_id]);
    db.run(`INSERT INTO balance_transactions (user_id, type, amount, balance_after, description, ref_id) VALUES (?, 'sale', ?, ?, ?, ?)`,
      [listing.seller_id, sellerAmount, listing.seller_balance + sellerAmount, `İlan satıldı: ${listing.title}`, txUuid]);

    // Mark listing as sold
    db.run(`UPDATE listings SET status='sold', sold_at=datetime('now') WHERE id=?`, [listing.id]);
    db.run(`UPDATE users SET total_purchases = total_purchases + 1 WHERE id = ?`, [req.user.id]);

    // Create transaction record
    db.run(`INSERT INTO transactions (uuid, buyer_id, seller_id, listing_id, amount, platform_fee, seller_amount, status, payment_method) VALUES (?, ?, ?, ?, ?, ?, ?, 'completed', 'balance')`,
      [txUuid, req.user.id, listing.seller_id, listing.id, listing.price, fee, sellerAmount]);

    // Notifications
    db.run(`INSERT INTO notifications (user_id, type, title, message, link) VALUES (?, 'purchase', 'Satın Alma Başarılı', ?, ?)`,
      [req.user.id, `"${listing.title}" ilanını başarıyla satın aldınız.`, `/profil/islemler`]);
    db.run(`INSERT INTO notifications (user_id, type, title, message, link) VALUES (?, 'sale', 'İlanınız Satıldı!', ?, ?)`,
      [listing.seller_id, `"${listing.title}" ilanınız satıldı. Kazancınız: ₺${sellerAmount}`, `/profil/islemler`]);

    res.redirect(`/odeme/basarili/${txUuid}`);
  });
});

// GET /odeme/basarili/:txUuid - Success page
router.get('/basarili/:txUuid', requireAuth, (req, res) => {
  db.get(`
    SELECT t.*, l.title as listing_title, l.uuid as listing_uuid, u.username as seller_username
    FROM transactions t 
    JOIN listings l ON t.listing_id = l.id
    JOIN users u ON t.seller_id = u.id
    WHERE t.uuid = ? AND t.buyer_id = ?
  `, [req.params.txUuid, req.user.id], (err, tx) => {
    if (!tx) return res.redirect('/profil/islemler');
    res.render('payment/success', { title: 'Ödeme Başarılı', tx });
  });
});

// GET /bakiye - Balance top-up page
router.get('/bakiye/yukle', requireAuth, (req, res) => {
  res.render('payment/deposit', {
    title: 'Bakiye Yükle',
    error: req.query.error || null,
    success: req.query.success || null
  });
});

// POST /bakiye/yukle - Simulate balance top-up (demo)
router.post('/bakiye/yukle', requireAuth, (req, res) => {
  const { amount, card_number, card_name, expiry, cvv } = req.body;
  const parsedAmount = parseFloat(amount);

  if (!parsedAmount || parsedAmount < 10 || parsedAmount > 10000) {
    return res.render('payment/deposit', { title: 'Bakiye Yükle', error: 'Geçerli bir tutar giriniz (10₺ - 10.000₺).', success: null });
  }
  if (!card_number || !card_name || !expiry || !cvv) {
    return res.render('payment/deposit', { title: 'Bakiye Yükle', error: 'Kart bilgilerini eksiksiz giriniz.', success: null });
  }

  // Demo: simulate successful payment
  db.run(`UPDATE users SET balance = balance + ? WHERE id = ?`, [parsedAmount, req.user.id], () => {
    db.get(`SELECT balance FROM users WHERE id = ?`, [req.user.id], (err, row) => {
      db.run(`INSERT INTO balance_transactions (user_id, type, amount, balance_after, description) VALUES (?, 'deposit', ?, ?, 'Bakiye yükleme')`,
        [req.user.id, parsedAmount, row.balance]);
      db.run(`INSERT INTO notifications (user_id, type, title, message, link) VALUES (?, 'balance', 'Bakiye Yüklendi', ?, '/profil')`,
        [req.user.id, `₺${parsedAmount.toFixed(2)} bakiye hesabınıza yüklendi.`]);
      res.redirect('/bakiye/yukle?success=1');
    });
  });
});

module.exports = router;
