const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const bodyParser = require('body-parser');
const validator = require('validator');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));
app.use(express.static('public'));

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

async function initializeDatabase() {
  try {
    const connection = await pool.getConnection();
    
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS submissions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        referenceCode VARCHAR(50) UNIQUE NOT NULL,
        brand VARCHAR(100) NOT NULL,
        model VARCHAR(100) NOT NULL,
        year INT NOT NULL,
        mileage INT NOT NULL,
        bodyType VARCHAR(50) NOT NULL,
        color VARCHAR(50) NOT NULL,
        fuel VARCHAR(50) NOT NULL,
        transmission VARCHAR(50) NOT NULL,
        engineSize INT NOT NULL,
        horsepower INT NOT NULL,
        wheelDrive VARCHAR(50) NOT NULL,
        hasAccident VARCHAR(10) NOT NULL,
        paintCondition VARCHAR(50) NOT NULL,
        interiorCondition VARCHAR(50) NOT NULL,
        tireCondition VARCHAR(50) NOT NULL,
        defects TEXT,
        firstName VARCHAR(100) NOT NULL,
        lastName VARCHAR(100) NOT NULL,
        email VARCHAR(100) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        city VARCHAR(100) NOT NULL,
        district VARCHAR(100) NOT NULL,
        submittedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_email (email),
        INDEX idx_phone (phone),
        INDEX idx_referenceCode (referenceCode),
        INDEX idx_submittedAt (submittedAt)
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS admin_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        action VARCHAR(100) NOT NULL,
        details TEXT,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_createdAt (createdAt)
      )
    `);

    connection.release();
    console.log('✅ Veritabanı başarıyla başlatıldı');
  } catch (error) {
    console.error('❌ Veritabanı başlatma hatası:', error);
  }
}

app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Kullanıcı adı ve şifre gerekli' });
    }

    if (username !== process.env.ADMIN_USERNAME) {
      return res.status(401).json({ success: false, message: 'Hatalı kimlik bilgileri' });
    }

    const isPasswordValid = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);

    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Hatalı kimlik bilgileri' });
    }

    const connection = await pool.getConnection();
    await connection.execute('INSERT INTO admin_logs (action, details) VALUES (?, ?)', 
      ['login', `Admin giriş yaptı - ${new Date().toLocaleString()}`]
    );
    connection.release();

    return res.json({ 
      success: true, 
      message: 'Giriş başarılı',
      token: 'otosell_token_' + Date.now()
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ success: false, message: 'Sunucu hatası' });
  }
});

app.post('/api/submissions', async (req, res) => {
  try {
    const {
      brand, model, year, mileage, bodyType, color, fuel, transmission,
      engineSize, horsepower, wheelDrive, hasAccident, paintCondition,
      interiorCondition, tireCondition, defects,
      firstName, lastName, email, phone, city, district
    } = req.body;

    if (!validator.isEmail(email)) {
      return res.status(400).json({ success: false, message: 'Geçersiz email' });
    }

    if (!validator.isMobilePhone(phone.replace(/\s/g, ''), 'tr-TR')) {
      return res.status(400).json({ success: false, message: 'Geçersiz telefon numarası' });
    }

    if (!firstName || !lastName || !brand || !model) {
      return res.status(400).json({ success: false, message: 'Zorunlu alanlar eksik' });
    }

    const sanitizedData = {
      brand: validator.escape(brand),
      model: validator.escape(model),
      year: parseInt(year),
      mileage: parseInt(mileage),
      bodyType: validator.escape(bodyType),
      color: validator.escape(color),
      fuel: validator.escape(fuel),
      transmission: validator.escape(transmission),
      engineSize: parseInt(engineSize),
      horsepower: parseInt(horsepower),
      wheelDrive: validator.escape(wheelDrive),
      hasAccident: validator.escape(hasAccident),
      paintCondition: validator.escape(paintCondition),
      interiorCondition: validator.escape(interiorCondition),
      tireCondition: validator.escape(tireCondition),
      defects: defects ? validator.escape(defects) : null,
      firstName: validator.escape(firstName),
      lastName: validator.escape(lastName),
      email: validator.normalizeEmail(email),
      phone: validator.escape(phone),
      city: validator.escape(city),
      district: validator.escape(district),
      referenceCode: 'OS-' + Date.now()
    };

    const connection = await pool.getConnection();

    const [existingSubmission] = await connection.execute(
      'SELECT id FROM submissions WHERE email = ? AND phone = ? AND brand = ? AND submittedAt > DATE_SUB(NOW(), INTERVAL 1 HOUR)',
      [sanitizedData.email, sanitizedData.phone, sanitizedData.brand]
    );

    if (existingSubmission.length > 0) {
      connection.release();
      return res.status(400).json({ 
        success: false, 
        message: 'Bu email ve telefon ile 1 saat içinde zaten teklif gönderilmiş' 
      });
    }

    await connection.execute(
      `INSERT INTO submissions (referenceCode, brand, model, year, mileage, bodyType, color, fuel, transmission, engineSize, horsepower, wheelDrive, hasAccident, paintCondition, interiorCondition, tireCondition, defects, firstName, lastName, email, phone, city, district)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        sanitizedData.referenceCode, sanitizedData.brand, sanitizedData.model,
        sanitizedData.year, sanitizedData.mileage, sanitizedData.bodyType,
        sanitizedData.color, sanitizedData.fuel, sanitizedData.transmission,
        sanitizedData.engineSize, sanitizedData.horsepower, sanitizedData.wheelDrive,
        sanitizedData.hasAccident, sanitizedData.paintCondition,
        sanitizedData.interiorCondition, sanitizedData.tireCondition, sanitizedData.defects,
        sanitizedData.firstName, sanitizedData.lastName, sanitizedData.email,
        sanitizedData.phone, sanitizedData.city, sanitizedData.district
      ]
    );

    connection.release();

    return res.json({
      success: true,
      message: 'Teklif başarıyla gönderildi',
      referenceCode: sanitizedData.referenceCode,
      email: sanitizedData.email
    });
  } catch (error) {
    console.error('Submission error:', error);
    return res.status(500).json({ success: false, message: 'Sunucu hatası' });
  }
});

app.get('/api/admin/submissions', async (req, res) => {
  try {
    const token = req.headers.authorization;
    if (!token || !token.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'Yetkisiz erişim' });
    }

    const connection = await pool.getConnection();
    const [submissions] = await connection.execute(
      'SELECT * FROM submissions ORDER BY submittedAt DESC'
    );
    connection.release();

    return res.json({ success: true, data: submissions });
  } catch (error) {
    console.error('Get submissions error:', error);
    return res.status(500).json({ success: false, message: 'Sunucu hatası' });
  }
});

app.get('/api/admin/submissions/:id', async (req, res) => {
  try {
    const token = req.headers.authorization;
    if (!token || !token.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'Yetkisiz erişim' });
    }

    const connection = await pool.getConnection();
    const [submission] = await connection.execute(
      'SELECT * FROM submissions WHERE id = ?',
      [req.params.id]
    );
    connection.release();

    if (submission.length === 0) {
      return res.status(404).json({ success: false, message: 'Teklif bulunamadı' });
    }

    return res.json({ success: true, data: submission[0] });
  } catch (error) {
    console.error('Get submission error:', error);
    return res.status(500).json({ success: false, message: 'Sunucu hatası' });
  }
});

app.delete('/api/admin/submissions/:id', async (req, res) => {
  try {
    const token = req.headers.authorization;
    if (!token || !token.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'Yetkisiz erişim' });
    }

    const connection = await pool.getConnection();
    
    const [result] = await connection.execute(
      'DELETE FROM submissions WHERE id = ?',
      [req.params.id]
    );

    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ success: false, message: 'Teklif bulunamadı' });
    }

    await connection.execute('INSERT INTO admin_logs (action, details) VALUES (?, ?)', 
      ['delete', `ID: ${req.params.id} silinmiştir`]
    );

    connection.release();

    return res.json({ success: true, message: 'Teklif silindi' });
  } catch (error) {
    console.error('Delete error:', error);
    return res.status(500).json({ success: false, message: 'Sunucu hatası' });
  }
});

app.get('/api/admin/stats', async (req, res) => {
  try {
    const token = req.headers.authorization;
    if (!token || !token.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'Yetkisiz erişim' });
    }

    const connection = await pool.getConnection();
    
    const [total] = await connection.execute('SELECT COUNT(*) as count FROM submissions');
    const [today] = await connection.execute(
      'SELECT COUNT(*) as count FROM submissions WHERE DATE(submittedAt) = CURDATE()'
    );
    const [week] = await connection.execute(
      'SELECT COUNT(*) as count FROM submissions WHERE submittedAt >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)'
    );

    connection.release();

    return res.json({
      success: true,
      stats: {
        total: total[0].count,
        today: today[0].count,
        week: week[0].count
      }
    });
  } catch (error) {
    console.error('Stats error:', error);
    return res.status(500).json({ success: false, message: 'Sunucu hatası' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  await initializeDatabase();
  console.log(`✅ OTOSELL Server ${PORT} portunda çalışıyor`);
});
