// HesapHub - Main Application JavaScript

const KEYS = {
  users: 'hh_users',
  currentUser: 'hh_current_user',
  listings: 'hh_listings',
  favPrefix: 'hh_fav_'
};

// ===== MOCK DATA =====
const MOCK_LISTINGS = [
  { id: 1, title: '50K Takipçili Instagram Hesabı – Moda Nişi', category: 'instagram', price: 2500, description: '50 bin gerçek ve aktif takipçiye sahip moda odaklı Instagram hesabı. Son 6 ay içinde tamamen organik büyüme. Reklam anlaşmaları yapılmış, engagement yüksek hesap. Takipçilerin %80\'i Türkiye\'den.', stat: '50.000', statLabel: 'Takipçi', createdAt: '2024-01-15', seller: 'mehmet_k', featured: true, views: 234, emoji: '📸' },
  { id: 2, title: '100K Takipçili TikTok Hesabı – Komedi İçerik', category: 'tiktok', price: 4500, description: '100 bin takipçili aktif TikTok hesabı. Komedi ve eğlence içerikleri ile %8 engagement rate. Birçok viral video bulunmaktadır.', stat: '100.000', statLabel: 'Takipçi', createdAt: '2024-01-18', seller: 'ayse_y', featured: true, views: 567, emoji: '🎵' },
  { id: 3, title: 'YouTube Kanalı – 25K Abone – Teknoloji', category: 'youtube', price: 8000, description: '25 bin abone teknoloji YouTube kanalı. Aylık 50K+ görüntüleme. Monetization açık. AdSense hesabıyla birlikte satılık.', stat: '25.000', statLabel: 'Abone', createdAt: '2024-01-20', seller: 'ali_tech', featured: true, views: 890, emoji: '🎬' },
  { id: 4, title: 'Twitter/X Hesabı – 15K Takipçi – Kripto', category: 'twitter', price: 1800, description: 'Kripto ve finans alanında 15K takipçili Twitter/X hesabı. Yüksek etkileşim, güçlü topluluk bağlantıları.', stat: '15.000', statLabel: 'Takipçi', createdAt: '2024-01-22', seller: 'crypto_boy', featured: false, views: 123, emoji: '🐦' },
  { id: 5, title: 'Facebook Sayfası – 80K Beğeni – Yemek', category: 'facebook', price: 3200, description: 'Yemek tarifi odaklı Facebook sayfası. 80K beğeni, aktif topluluk. Reklam verilebilir, yüksek organik erişim.', stat: '80.000', statLabel: 'Beğeni', createdAt: '2024-01-25', seller: 'fatma_m', featured: false, views: 345, emoji: '📘' },
  { id: 6, title: 'Valorant Hesabı – Diamond Rank – 20+ Ajan', category: 'oyun', price: 950, description: 'Diamond rank Valorant hesabı. 20+ ajan kilidini açık, 500+ saat oynama süresi. Temiz geçmiş, ban yok.', stat: 'Diamond', statLabel: 'Rank', createdAt: '2024-01-28', seller: 'gamer_pro', featured: false, views: 456, emoji: '🎮' },
  { id: 7, title: 'E-ticaret Web Sitesi – Aylık 5K Ziyaretçi', category: 'web', price: 15000, description: 'Tam kurulu e-ticaret sitesi. Aylık ortalama 5000 organik ziyaretçi. WordPress + WooCommerce. Aylık 2000₺ reklam geliri.', stat: '5.000/ay', statLabel: 'Ziyaretçi', createdAt: '2024-01-30', seller: 'web_master', featured: true, views: 678, emoji: '💻' },
  { id: 8, title: 'Instagram Hesabı – 200K – Spor & Fitness', category: 'instagram', price: 9000, description: '200K takipçili spor ve fitness Instagram hesabı. %6 engagement rate. Birden fazla sponsor anlaşması yapılmış hesap.', stat: '200.000', statLabel: 'Takipçi', createdAt: '2024-02-01', seller: 'fit_life', featured: true, views: 1234, emoji: '📸' },
  { id: 9, title: 'League of Legends Hesabı – Platinum – TR', category: 'oyun', price: 750, description: 'Platinum hesap, 80+ şampiyon. TR sunucusu. Temiz geçmiş, iyi durumda.', stat: 'Platinum', statLabel: 'Rank', createdAt: '2024-02-03', seller: 'lol_seller', featured: false, views: 234, emoji: '🎮' },
  { id: 10, title: 'TikTok Hesabı – 500K Takipçi – Dans', category: 'tiktok', price: 22000, description: 'Yarım milyon takipçili TikTok hesabı. Dans ve eğlence içerikleri. Viral videolar mevcut. Çok sayıda sponsorlu içerik yapılmış.', stat: '500.000', statLabel: 'Takipçi', createdAt: '2024-02-05', seller: 'dance_queen', featured: true, views: 2345, emoji: '🎵' },
  { id: 11, title: 'Haber & Blog Web Sitesi – SEO Güçlü', category: 'web', price: 7500, description: 'Teknoloji haberleri blog sitesi. Google\'da ilk sayfada 50+ anahtar kelime. Aylık 20K organik trafik. Google AdSense aktif.', stat: '20.000/ay', statLabel: 'Ziyaretçi', createdAt: '2024-02-08', seller: 'seo_expert', featured: false, views: 456, emoji: '💻' },
  { id: 12, title: 'YouTube Kanalı – Gaming – 10K Abone', category: 'youtube', price: 3500, description: '10K abone gaming YouTube kanalı. Minecraft, Roblox içerikleri. Monetization yakın. Genç izleyici kitlesi.', stat: '10.000', statLabel: 'Abone', createdAt: '2024-02-10', seller: 'game_yt', featured: false, views: 567, emoji: '🎬' },
  { id: 13, title: 'Spotify Premium Hesabı – 5 Yıllık', category: 'diger', price: 450, description: '5 yıllık Spotify premium hesabı. Çok sayıda playlist oluşturulmuş. Hesap güvenli ve temiz geçmişe sahip.', stat: '5 Yıl', statLabel: 'Üyelik', createdAt: '2024-02-12', seller: 'music_lover', featured: false, views: 123, emoji: '📱' },
  { id: 14, title: 'Instagram Hesabı – 30K – Seyahat Nişi', category: 'instagram', price: 1200, description: '30K takipçili seyahat temalı Instagram hesabı. Organik büyüme, gerçek takipçiler. İyi fotoğraf kalitesi.', stat: '30.000', statLabel: 'Takipçi', createdAt: '2024-02-14', seller: 'travel_tr', featured: false, views: 234, emoji: '📸' },
  { id: 15, title: 'CS2 Hesabı – Global Elite – Prime', category: 'oyun', price: 2100, description: 'Global Elite CS2 hesabı. Prime status. Temiz geçmiş, ban yok. Çok sayıda güzel skin.', stat: 'Global Elite', statLabel: 'Rank', createdAt: '2024-02-15', seller: 'cs_pro', featured: true, views: 890, emoji: '🎮' }
];

const CAT_NAMES = {
  instagram: 'Instagram',
  tiktok: 'TikTok',
  youtube: 'YouTube',
  twitter: 'Twitter/X',
  facebook: 'Facebook',
  oyun: 'Oyun Hesabı',
  web: 'Web Sitesi',
  diger: 'Diğer'
};

// ===== STORAGE =====
function getListings() {
  const d = localStorage.getItem(KEYS.listings);
  return d ? JSON.parse(d) : MOCK_LISTINGS;
}
function saveListings(list) {
  localStorage.setItem(KEYS.listings, JSON.stringify(list));
}
function getListing(id) {
  return getListings().find(l => l.id == id) || null;
}
function addListing(data) {
  const user = getUser();
  if (!user) return { success: false, message: 'Giriş yapmanız gerekiyor.' };
  const list = getListings();
  const item = { id: Date.now(), ...data, seller: user.username, sellerId: user.id, createdAt: new Date().toISOString().split('T')[0], featured: false, views: 0 };
  list.unshift(item);
  saveListings(list);
  return { success: true, listing: item };
}
function incrementViews(id) {
  const list = getListings();
  const i = list.findIndex(l => l.id == id);
  if (i !== -1) { list[i].views = (list[i].views || 0) + 1; saveListings(list); }
}
function getUserListings(username) {
  return getListings().filter(l => l.seller === username);
}
function getFeatured(limit) {
  return getListings().filter(l => l.featured).slice(0, limit || 8);
}
function getRecent(limit) {
  return [...getListings()].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, limit || 8);
}
function getCatCounts() {
  const counts = {};
  getListings().forEach(l => { counts[l.category] = (counts[l.category] || 0) + 1; });
  return counts;
}

// ===== AUTH =====
function getUser() {
  const s = localStorage.getItem(KEYS.currentUser);
  return s ? JSON.parse(s) : null;
}
function isLoggedIn() { return !!getUser(); }
function getUsers() {
  const s = localStorage.getItem(KEYS.users);
  return s ? JSON.parse(s) : [];
}
function saveUsers(u) { localStorage.setItem(KEYS.users, JSON.stringify(u)); }

function login(id, pass) {
  const users = getUsers();
  const u = users.find(u => (u.email === id || u.username === id) && u.password === pass);
  if (u) {
    const { password: _, ...safe } = u;
    localStorage.setItem(KEYS.currentUser, JSON.stringify(safe));
    return { success: true, user: safe };
  }
  return { success: false, message: 'Kullanıcı adı/e-posta veya şifre hatalı.' };
}

function register(data) {
  const users = getUsers();
  if (users.some(u => u.email === data.email)) return { success: false, message: 'Bu e-posta adresi zaten kullanılıyor.' };
  if (users.some(u => u.username === data.username)) return { success: false, message: 'Bu kullanıcı adı zaten alınmış.' };
  const nu = { id: Date.now(), username: data.username, email: data.email, password: data.password, phone: data.phone || '', avatar: null, memberSince: new Date().toISOString(), rating: 5.0, ratingCount: 1 };
  users.push(nu);
  saveUsers(users);
  const { password: _, ...safe } = nu;
  localStorage.setItem(KEYS.currentUser, JSON.stringify(safe));
  return { success: true, user: safe };
}

function logout() {
  localStorage.removeItem(KEYS.currentUser);
  window.location.href = 'index.html';
}

function updateUser(updates) {
  const cur = getUser();
  if (!cur) return { success: false };
  const users = getUsers();
  const idx = users.findIndex(u => u.id === cur.id);
  if (idx === -1) return { success: false };
  if (updates.username && updates.username !== users[idx].username && users.some(u => u.username === updates.username && u.id !== cur.id))
    return { success: false, message: 'Bu kullanıcı adı zaten alınmış.' };
  if (updates.email && updates.email !== users[idx].email && users.some(u => u.email === updates.email && u.id !== cur.id))
    return { success: false, message: 'Bu e-posta adresi zaten kullanılıyor.' };
  users[idx] = { ...users[idx], ...updates };
  saveUsers(users);
  const { password: _, ...safe } = users[idx];
  localStorage.setItem(KEYS.currentUser, JSON.stringify(safe));
  return { success: true, user: safe };
}

function changePassword(cur, next) {
  const user = getUser();
  if (!user) return { success: false };
  const users = getUsers();
  const u = users.find(x => x.id === user.id);
  if (!u || u.password !== cur) return { success: false, message: 'Mevcut şifre hatalı.' };
  u.password = next;
  saveUsers(users);
  return { success: true };
}

// ===== FAVORITES =====
function getFavs() {
  const u = getUser();
  if (!u) return [];
  const d = localStorage.getItem(KEYS.favPrefix + u.id);
  return d ? JSON.parse(d) : [];
}
function isFav(id) { return getFavs().includes(id); }
function toggleFav(id) {
  const u = getUser();
  if (!u) { showToast('Favorilere eklemek için giriş yapın.', 'warning'); return false; }
  const favs = getFavs();
  const key = KEYS.favPrefix + u.id;
  const i = favs.indexOf(id);
  if (i === -1) { favs.push(id); localStorage.setItem(key, JSON.stringify(favs)); showToast('Favorilere eklendi! ❤️', 'success'); return true; }
  favs.splice(i, 1); localStorage.setItem(key, JSON.stringify(favs)); showToast('Favorilerden kaldırıldı.', 'warning'); return false;
}

// ===== NAV =====
function updateNav() {
  const u = getUser();
  const authBtns = document.getElementById('authButtons');
  const userMenu = document.getElementById('userMenu');
  const ilanVer = document.getElementById('ilanVerLink');
  if (u) {
    if (authBtns) authBtns.style.display = 'none';
    if (userMenu) { userMenu.style.display = 'flex'; const nm = document.getElementById('userMenuName'); const av = document.getElementById('userInitial'); if (nm) nm.textContent = u.username; if (av) av.textContent = u.username[0].toUpperCase(); }
    if (ilanVer) ilanVer.style.display = 'flex';
  } else {
    if (authBtns) authBtns.style.display = 'flex';
    if (userMenu) userMenu.style.display = 'none';
    if (ilanVer) ilanVer.style.display = 'none';
  }
}

function setActiveNav() {
  const page = window.location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.navbar-nav a').forEach(a => { if (a.getAttribute('href') === page || (!page && a.getAttribute('href') === 'index.html')) a.classList.add('active'); });
  document.querySelectorAll('.cat-link').forEach(a => { const p = new URLSearchParams(window.location.search).get('kategori'); const href = a.getAttribute('href'); if (p && href && href.includes('kategori=' + p)) a.classList.add('active'); else if (!p && href === 'ilanlar.html') a.classList.add('active'); });
}

function initDropdown() {
  const t = document.getElementById('userMenuToggle');
  const d = document.getElementById('userDropdown');
  if (t && d) { t.addEventListener('click', e => { e.stopPropagation(); d.classList.toggle('show'); }); document.addEventListener('click', () => d.classList.remove('show')); }
}

function initMobileNav() {
  const t = document.getElementById('navToggle');
  const m = document.getElementById('mobileMenu');
  if (t && m) t.addEventListener('click', () => m.classList.toggle('show'));
}

// ===== TOAST =====
function ensureToastContainer() {
  if (!document.getElementById('toastContainer')) {
    const c = document.createElement('div'); c.id = 'toastContainer'; c.className = 'toast-container'; document.body.appendChild(c);
  }
}
function showToast(msg, type, dur) {
  ensureToastContainer();
  const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
  const t = document.createElement('div');
  t.className = 'toast ' + (type || 'success');
  t.innerHTML = '<span>' + (icons[type] || '📢') + '</span> ' + msg;
  document.getElementById('toastContainer').appendChild(t);
  setTimeout(() => { t.style.animation = 'slideIn .3s ease reverse'; setTimeout(() => t.remove(), 300); }, dur || 3000);
}

// ===== LISTING CARD =====
function renderCard(l) {
  const f = isFav(l.id);
  const price = l.price ? l.price.toLocaleString('tr-TR') + ' ₺' : 'Fiyat sorununuz';
  return `<a href="ilan-detay.html?id=${l.id}" class="listing-card">
    <div class="listing-card-img">
      <span>${l.emoji || '📦'}</span>
      <span class="listing-card-badge">${l.featured ? '<span class="badge badge-warning">⭐ Öne Çıkan</span>' : ''}</span>
      <button class="listing-card-fav${f ? ' active' : ''}" onclick="handleFav(event,${l.id})" title="${f ? 'Favoriden kaldır' : 'Favorilere ekle'}">${f ? '❤️' : '🤍'}</button>
    </div>
    <div class="listing-card-body">
      <div class="listing-card-category">${l.emoji || ''} ${CAT_NAMES[l.category] || l.category}</div>
      <div class="listing-card-title">${l.title}</div>
      <div class="listing-card-desc">${l.description}</div>
      <div class="listing-card-footer">
        <div class="listing-card-price">${price}</div>
        <div class="listing-card-meta">👁 ${l.views || 0}</div>
      </div>
    </div>
  </a>`;
}

function handleFav(e, id) {
  e.preventDefault(); e.stopPropagation();
  const isNowFav = toggleFav(id);
  const btn = e.currentTarget;
  btn.textContent = isNowFav ? '❤️' : '🤍';
  isNowFav ? btn.classList.add('active') : btn.classList.remove('active');
}

// ===== SEARCH =====
function doSearch() {
  const q = document.getElementById('searchInput');
  if (q && q.value.trim()) window.location.href = 'ilanlar.html?q=' + encodeURIComponent(q.value.trim());
}

// ===== REQUIRE AUTH =====
function requireAuth() {
  if (!isLoggedIn()) { window.location.href = 'giris.html?redirect=' + encodeURIComponent(window.location.href); return false; }
  return true;
}

// ===== FORMAT =====
function fmtDate(d) { return new Date(d).toLocaleDateString('tr-TR', { year: 'numeric', month: 'long', day: 'numeric' }); }
function fmtPrice(p) { return Number(p).toLocaleString('tr-TR') + ' ₺'; }

// ===== INIT =====
document.addEventListener('DOMContentLoaded', () => {
  if (!localStorage.getItem(KEYS.listings)) saveListings(MOCK_LISTINGS);
  updateNav();
  setActiveNav();
  ensureToastContainer();
  initDropdown();
  initMobileNav();
  const si = document.getElementById('searchInput');
  if (si) si.addEventListener('keydown', e => { if (e.key === 'Enter') doSearch(); });
});
