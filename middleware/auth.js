const jwt = require('jsonwebtoken');
const db = require('../database/init');

// Middleware: verify JWT token from session or cookie
function requireAuth(req, res, next) {
  const token = req.session && req.session.token;
  if (!token) {
    req.session.returnTo = req.originalUrl;
    return res.redirect('/giris?error=login_required');
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    db.get(`SELECT * FROM users WHERE id = ? AND is_banned = 0`, [decoded.id], (err, user) => {
      if (err || !user) {
        req.session.destroy();
        return res.redirect('/giris?error=session_expired');
      }
      req.user = user;
      res.locals.user = user;
      next();
    });
  } catch (err) {
    req.session.destroy();
    return res.redirect('/giris?error=session_expired');
  }
}

// Middleware: optionally attach user (no redirect)
function optionalAuth(req, res, next) {
  const token = req.session && req.session.token;
  if (!token) {
    res.locals.user = null;
    return next();
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    db.get(`SELECT * FROM users WHERE id = ? AND is_banned = 0`, [decoded.id], (err, user) => {
      req.user = user || null;
      res.locals.user = user || null;
      if (user) {
        // Get unread notification count
        db.get(`SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0`, [user.id], (err, row) => {
          res.locals.unreadNotifications = row ? row.count : 0;
        });
        // Get unread message count
        db.get(`SELECT (SELECT COALESCE(SUM(user1_unread),0) FROM conversations WHERE user1_id = ?)+(SELECT COALESCE(SUM(user2_unread),0) FROM conversations WHERE user2_id = ?) as count`,
          [user.id, user.id], (err, row) => {
          res.locals.unreadMessages = row ? row.count : 0;
          next();
        });
      } else {
        res.locals.unreadNotifications = 0;
        res.locals.unreadMessages = 0;
        next();
      }
    });
  } catch (err) {
    res.locals.user = null;
    res.locals.unreadNotifications = 0;
    res.locals.unreadMessages = 0;
    next();
  }
}

module.exports = { requireAuth, optionalAuth };
