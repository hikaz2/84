function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).render('error', {
      title: 'Erişim Reddedildi',
      message: 'Bu sayfaya erişim için yönetici yetkiniz bulunmamaktadır.',
      user: req.user || null
    });
  }
  next();
}

module.exports = { requireAdmin };
