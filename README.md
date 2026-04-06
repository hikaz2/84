# HesapSat - Dijital Hesap ve Ürün Pazaryeri

Hesapsat.net benzeri, tam özellikli dijital hesap ve ürün pazaryeri platformu. Node.js/Express, SQLite ve EJS ile geliştirilmiştir.

## 🚀 Özellikler

- **Kullanıcı Sistemi**: Kayıt, giriş, JWT kimlik doğrulama, profil yönetimi
- **İlan Yönetimi**: İlan oluşturma, düzenleme, silme, kategorilere göre filtreleme
- **Arama & Filtreleme**: Kategori, fiyat aralığı, anahtar kelime filtreleme
- **Ödeme Altyapısı**: Bakiye sistemi, bakiye yükleme, güvenli satın alma
- **Mesajlaşma**: Alıcı-satıcı gerçek zamanlı mesajlaşma sistemi
- **Yönetici Paneli**: Kullanıcı, ilan ve işlem yönetimi
- **Bildirimler**: Uygulama içi bildirim sistemi
- **Favoriler**: İlan favorileme
- **Değerlendirme**: Satıcı puanlama ve yorum sistemi
- **Kategoriler**: Oyun hesapları, sosyal medya, dijital ürünler vb.

## 📦 Kurulum

### Gereksinimler
- Node.js 18+
- npm 8+

### Kurulum Adımları

```bash
# 1. Bağımlılıkları yükle
npm install

# 2. Ortam değişkenlerini ayarla
cp .env.example .env
# .env dosyasını düzenle

# 3. Sunucuyu başlat
npm start
```

Tarayıcınızda `http://localhost:3000` adresini açın.

## 🔑 Demo Hesapları

| Rol | E-posta | Şifre |
|-----|---------|-------|
| Admin | admin@hesapsat.net | Admin123! |
| Kullanıcı | demo@hesapsat.net | Demo123! |

## 📁 Proje Yapısı

```
├── server.js              # Ana sunucu dosyası
├── .env.example           # Ortam değişkenleri örneği
├── package.json
├── database/
│   └── init.js            # Veritabanı başlatma ve seed
├── routes/
│   ├── auth.js            # Giriş/kayıt rotaları
│   ├── listings.js        # İlan rotaları
│   ├── messages.js        # Mesajlaşma rotaları
│   ├── payments.js        # Ödeme rotaları
│   ├── profile.js         # Profil rotaları
│   └── admin.js           # Yönetici rotaları
├── middleware/
│   ├── auth.js            # JWT doğrulama middleware
│   └── admin.js           # Admin yetki middleware
├── views/                 # EJS şablonları
│   ├── home.ejs
│   ├── partials/
│   ├── auth/
│   ├── listings/
│   ├── messages/
│   ├── payment/
│   ├── profile/
│   ├── admin/
│   └── pages/
└── public/
    ├── css/style.css
    ├── js/main.js
    └── uploads/           # Kullanıcı yüklemeleri
```

## 🛠️ Teknolojiler

- **Backend**: Node.js, Express.js
- **Veritabanı**: SQLite3
- **Şifreleme**: bcryptjs, jsonwebtoken
- **Şablon**: EJS
- **Güvenlik**: Helmet.js, express-session
- **Dosya Yükleme**: Multer v2
- **Stil**: Özel CSS (responsive tasarım)

## 🔒 Güvenlik

- Şifreler bcrypt ile hashlanır
- JWT ile oturum yönetimi
- Helmet.js ile HTTP güvenlik başlıkları
- SQL injection koruması (parametreli sorgular)
- Dosya yükleme doğrulama
- CSRF koruması (form tabanlı)

## ⚙️ Ortam Değişkenleri

| Değişken | Açıklama | Varsayılan |
|----------|----------|------------|
| PORT | Sunucu portu | 3000 |
| JWT_SECRET | JWT imzalama anahtarı | (değiştirin!) |
| SESSION_SECRET | Oturum anahtarı | (değiştirin!) |
| ADMIN_EMAIL | İlk admin e-postası | admin@hesapsat.net |
| ADMIN_PASSWORD | İlk admin şifresi | Admin123! |
| DB_PATH | Veritabanı yolu | ./database/marketplace.db |

## 📊 Kategoriler

- 🎮 Oyun Hesapları (Steam, LoL, Valorant, PUBG)
- 📱 Sosyal Medya (Instagram, TikTok, YouTube)
- 💾 Dijital Ürünler (Netflix, Yazılım Lisansları)
- 📧 E-posta Hesapları
- ₿ Kripto & NFT
- 📦 Diğer

## 🚧 Üretim Ortamı

Üretim ortamında mutlaka şu değişiklikleri yapın:
1. `.env` dosyasındaki `JWT_SECRET` ve `SESSION_SECRET` değerlerini değiştirin
2. `NODE_ENV=production` ayarlayın
3. Gerçek ödeme entegrasyonu için Stripe API anahtarlarını ekleyin
4. Reverse proxy (nginx) arkasında çalıştırın
