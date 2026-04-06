// Main JavaScript for HesapSat

// ============ DROPDOWN ============
document.querySelectorAll('.dropdown').forEach(dropdown => {
  const toggle = dropdown.querySelector('[data-toggle="dropdown"]');
  if (toggle) {
    toggle.addEventListener('click', (e) => {
      e.stopPropagation();
      dropdown.classList.toggle('active');
    });
  }
});

document.addEventListener('click', () => {
  document.querySelectorAll('.dropdown').forEach(d => d.classList.remove('active'));
});

// ============ ALERTS AUTO-DISMISS ============
document.querySelectorAll('.alert-auto-dismiss').forEach(alert => {
  setTimeout(() => {
    alert.style.transition = 'opacity 0.5s';
    alert.style.opacity = '0';
    setTimeout(() => alert.remove(), 500);
  }, 5000);
});

// ============ IMAGE PREVIEW ============
const imageInputs = document.querySelectorAll('input[type="file"][name="images"]');
imageInputs.forEach(input => {
  input.addEventListener('change', function () {
    const preview = document.getElementById('imagePreview');
    if (!preview) return;
    preview.innerHTML = '';
    Array.from(this.files).forEach(file => {
      const reader = new FileReader();
      reader.onload = e => {
        const img = document.createElement('img');
        img.src = e.target.result;
        img.style.cssText = 'width:100px;height:75px;object-fit:cover;border-radius:8px;border:2px solid #e0e0e0;';
        preview.appendChild(img);
      };
      reader.readAsDataURL(file);
    });
  });
});

// ============ FAVORITE TOGGLE ============
document.querySelectorAll('.fav-btn').forEach(btn => {
  btn.addEventListener('click', async (e) => {
    e.preventDefault();
    e.stopPropagation();
    const uuid = btn.dataset.uuid;
    if (!uuid) return;
    try {
      const res = await fetch(`/ilanlar/favori/${uuid}`, { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        btn.classList.toggle('active', data.favorited);
        btn.innerHTML = data.favorited ? '❤️' : '🤍';
        showToast(data.favorited ? 'Favorilere eklendi!' : 'Favorilerden çıkarıldı!');
      }
    } catch (err) {
      window.location.href = '/giris';
    }
  });
});

// ============ IMAGE GALLERY ============
const mainImg = document.getElementById('mainImage');
document.querySelectorAll('.thumb-image').forEach(thumb => {
  thumb.addEventListener('click', function () {
    if (mainImg) mainImg.src = this.src;
    document.querySelectorAll('.thumb-image').forEach(t => t.classList.remove('active'));
    this.classList.add('active');
  });
});

// ============ PRICE FORMATTER ============
const priceInput = document.getElementById('priceInput');
if (priceInput) {
  priceInput.addEventListener('input', function () {
    const preview = document.getElementById('pricePreview');
    if (preview) {
      const val = parseFloat(this.value);
      preview.textContent = isNaN(val) ? '' : `₺${val.toLocaleString('tr-TR', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
    }
  });
}

// ============ TOAST NOTIFICATION ============
function showToast(message, type = 'success') {
  const toast = document.createElement('div');
  toast.style.cssText = `
    position: fixed;
    bottom: 24px;
    right: 24px;
    background: ${type === 'success' ? '#28a745' : '#dc3545'};
    color: white;
    padding: 12px 24px;
    border-radius: 8px;
    font-weight: 600;
    font-size: 0.9rem;
    z-index: 9999;
    box-shadow: 0 4px 20px rgba(0,0,0,0.2);
    transition: opacity 0.3s;
  `;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// ============ CONFIRM DELETE ============
document.querySelectorAll('.confirm-delete').forEach(btn => {
  btn.addEventListener('click', (e) => {
    if (!confirm('Bu işlemi geri alamazsınız. Emin misiniz?')) {
      e.preventDefault();
    }
  });
});

// ============ CHAR COUNT ============
document.querySelectorAll('[data-maxlength]').forEach(el => {
  const max = parseInt(el.dataset.maxlength);
  const counter = document.createElement('small');
  counter.className = 'text-muted';
  counter.style.float = 'right';
  el.parentNode.appendChild(counter);
  const update = () => { counter.textContent = `${el.value.length}/${max}`; };
  el.addEventListener('input', update);
  update();
});

// ============ MOBILE NAV ============
const mobileMenuBtn = document.getElementById('mobileMenuBtn');
const mobileMenu = document.getElementById('mobileMenu');
if (mobileMenuBtn && mobileMenu) {
  mobileMenuBtn.addEventListener('click', () => {
    mobileMenu.classList.toggle('open');
  });
}

// ============ SCROLL TO TOP ============
const scrollBtn = document.getElementById('scrollToTop');
if (scrollBtn) {
  window.addEventListener('scroll', () => {
    scrollBtn.style.display = window.scrollY > 500 ? 'flex' : 'none';
  });
  scrollBtn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
}

// ============ CARD NUMBER FORMATTING ============
const cardInput = document.getElementById('cardNumber');
if (cardInput) {
  cardInput.addEventListener('input', function () {
    this.value = this.value.replace(/\D/g, '').replace(/(.{4})/g, '$1 ').trim().slice(0, 19);
  });
}
const expiryInput = document.getElementById('cardExpiry');
if (expiryInput) {
  expiryInput.addEventListener('input', function () {
    this.value = this.value.replace(/\D/g, '').replace(/(\d{2})(\d)/, '$1/$2').slice(0, 5);
  });
}
