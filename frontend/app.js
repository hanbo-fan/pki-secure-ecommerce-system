// app.js
const API = 'http://localhost:8100';
let token = localStorage.getItem('token');
let currentUser = JSON.parse(localStorage.getItem('user') || 'null');
let allProducts = [];
let orderProduct = null;
let userPrivateKey = null;
let userCertId = null;
let pendingPrivateKey = null;
let authRole = 'customer', authMode = 'login';

// ── Initialize: check localStorage for existing session on page load ──
window.onload = () => {
  if (token && currentUser) {
    showDashboard();
  } else {
    showPage('landing');
  }
};

// ── PAGE CONTROL ──────────────────────────────────────────────────────────

// Switch the visible page by removing 'active' from all pages and adding it to the target
function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
}

// Restore session state and render the appropriate dashboard for the logged-in user
function showDashboard() {
  // Restore private key and cert ID from localStorage if not already in memory
  if (currentUser) {
    if (!userPrivateKey) {
        userPrivateKey = localStorage.getItem(`privateKey_${currentUser.username}`);
    }
    if (!userCertId) {
        userCertId = parseInt(localStorage.getItem(`certId_${currentUser.username}`)) || currentUser.cert_id || null;
    }
  }

  document.getElementById('nav').style.display = 'flex';
  document.getElementById('nav-username').textContent = currentUser.username;
  const badge = document.getElementById('nav-role-badge');
  badge.textContent = currentUser.role === 'merchant' ? 'Merchant' : 'Customer';
  badge.className = 'role-badge ' + currentUser.role;

  if (currentUser.role === 'merchant') {
    document.getElementById('merchant-sub').textContent =
      `Welcome back, ${currentUser.username} - manage your inventory`;
    showPage('merchant');
    loadMerchantProducts();
    loadStats();
    loadMerchantOrders();
  } else {
    document.getElementById('customer-sub').textContent =
      `Welcome, ${currentUser.username} - find something great`;
    showPage('customer');
    loadAllProducts();
    loadCustomerOrders();
  }
  checkCertStatus();
}

// Clear session data and return to the landing page
function logout() {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  token = null; currentUser = null;
  document.getElementById('nav').style.display = 'none';
  showPage('landing');
}

// ── AUTH MODAL ────────────────────────────────────────────────────────────

// Open the login/register modal and configure it for the given role and mode
function openAuth(role, mode) {
  authRole = role; authMode = mode;
  const modal = document.getElementById('auth-modal');
  const isReg = mode === 'register';

  document.getElementById('modal-tag').textContent = role === 'merchant' ? '🏪 Merchant' : '🛍️ Customer';
  document.getElementById('modal-tag').className = 'modal-tag ' + role;
  document.getElementById('modal-title').textContent = isReg ? 'Create Account' : 'Welcome Back';
  document.getElementById('btn-submit').textContent = isReg ? 'Register' : 'Log In';
  document.getElementById('btn-submit').className = 'btn-submit ' + role;
  document.getElementById('field-confirm').style.display = 'none';
  document.getElementById('field-confirm2').style.display = isReg ? 'block' : 'none';
  document.getElementById('label-username').textContent = 'Username';

  // Apply merchant colour theme to inputs
  document.querySelectorAll('.form-input').forEach(el => {
    el.classList.remove('merchant');
    if (role === 'merchant') el.classList.add('merchant');
  });

  const sw = document.getElementById('form-switch');
  if (isReg) {
    sw.innerHTML = `Already have an account? <a class="${role}" onclick="openAuth('${role}','login')">Log in</a>`;
    document.getElementById('field-key-login').style.display = 'none';
  } else {
    sw.innerHTML = `Don't have an account? <a class="${role}" onclick="openAuth('${role}','register')">Register</a>`;
    document.getElementById('field-key-login').style.display = 'block';
  }

  clearFormMessages();
  document.getElementById('auth-username').value = '';
  document.getElementById('auth-password').value = '';
  document.getElementById('auth-confirm').value = '';
  document.getElementById('login-captcha-input').value = '';
  clearKeyLogin();

  // Reset password field state and checkbox every time the modal opens
  const pwField = document.getElementById('auth-password');
  pwField.disabled = false;
  pwField.placeholder = 'Enter password';
  const cb = document.getElementById('use-key-login');
  if (cb) cb.checked = false;
  const uploadArea = document.getElementById('key-upload-area');
  if (uploadArea) uploadArea.style.display = 'none';

  // Load the appropriate captcha for the current mode
  loadCaptcha('login-session-id', 'login-captcha-img');
  modal.classList.add('active');
}

// Close the login/register modal
function closeAuth() {
  document.getElementById('auth-modal').classList.remove('active');
}

// Hide both the error and success message banners in the auth modal
function clearFormMessages() {
  document.getElementById('form-error').style.display = 'none';
  document.getElementById('form-success').style.display = 'none';
}

// Show an error message in the auth modal
function showFormError(msg) {
  const el = document.getElementById('form-error');
  el.textContent = msg;
  el.style.display = 'block';
  document.getElementById('form-success').style.display = 'none';
}

// Show a success message in the auth modal
function showFormSuccess(msg) {
  const el = document.getElementById('form-success');
  el.textContent = msg; el.style.display = 'block';
  document.getElementById('form-error').style.display = 'none';
}

// Validate inputs and route to the correct register or login handler
async function submitAuth() {
  clearFormMessages();
  const username = document.getElementById('auth-username').value.trim();
  const password = document.getElementById('auth-password').value;

  if (!username) { showFormError('Please enter your username.'); return; }
  if (!password && !pendingPrivateKey) {
    showFormError('Please enter your password or upload a private key.'); return;
  }

  // Disable button to prevent duplicate submissions
  const btn = document.getElementById('btn-submit');
  btn.disabled = true;
  btn.textContent = 'Processing…';

  // Disable remove button during submission to prevent mid-login key removal
  const removeBtn = document.getElementById('remove-key-btn');
  if (removeBtn) {
    removeBtn.style.pointerEvents = 'none';
    removeBtn.style.color = 'gray';
  }

  try {
    if (authMode === 'register') {
      const confirm = document.getElementById('auth-confirm').value;
      if (password !== confirm) { showFormError('Passwords do not match.'); return; }
      await doRegister(username, password, confirm);
    } else {
      if (pendingPrivateKey) {
        await doLoginWithKey(username, authRole, pendingPrivateKey);
      } else {
        await doLogin(username, password);
      }
    }
  } finally {
    // Always restore the button and remove-key link regardless of outcome
    btn.disabled = false;
    btn.textContent = authMode === 'register' ? 'Register' : 'Log In';
    const rb = document.getElementById('remove-key-btn');
    if (rb) {
      rb.style.pointerEvents = 'auto';
      rb.style.color = 'var(--danger)';
    }
  }
}

// Register a new account, then automatically generate a key pair and request a certificate
async function doRegister(username, password, confirm) {
  try {
    const sessionId = document.getElementById('login-session-id').value;
    const captcha = document.getElementById('login-captcha-input').value.trim();
    if (!captcha) { showFormError('Please enter the security code.'); return; }

    const res = await fetch(`${API}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username, password, confirm_password: confirm, role: authRole,
        session_id: sessionId, captcha
      })
    });
    const data = await res.json();
    if (!res.ok) {
      showFormError(data.detail || 'Registration failed.');
      loadCaptcha('login-session-id', 'login-captcha-img');
      return;
    }

    showFormSuccess('Account created! Generating security keys…');

    // Use the token returned directly from the register response
    const tempToken = data.token;
    if (!tempToken) {
      showFormSuccess('Account created! Redirecting to login…');
      setTimeout(() => openAuth(authRole, 'login'), 1200); return;
    }

    // Generate RSA key pair on the server
    const kpData = await generateKeypairLocally();

    // Request a certificate from the CA
    const certRes = await fetch(`${API}/auth/request-cert`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${tempToken}` },
      body: JSON.stringify({ public_key_pem: kpData.public_key_pem })
    });
    const certData = await certRes.json();
    if (!certRes.ok) {
      showFormError(certData.detail || 'Failed to obtain certificate.');
      return;
    }

    // Persist private key and cert ID in localStorage, then download the key file
    localStorage.setItem(`privateKey_${username}`, kpData.private_key_pem);
    localStorage.setItem(`certId_${username}`, certData.cert_id);
    downloadPrivateKey(username, kpData.private_key_pem);

    showFormSuccess('Account created! Redirecting to login…');
    setTimeout(() => openAuth(authRole, 'login'), 1200);
  } catch (e) {
    console.error('Registration error:', e);
    showFormError('Network error - is the server running?');
  }
}

// Log in with username and password, then restore private key from localStorage
async function doLogin(username, password) {
  try {
    const sessionId = document.getElementById('login-session-id').value;
    const captcha = document.getElementById('login-captcha-input').value.trim();
    if (!captcha) { showFormError('Please enter the security code.'); return; }

    const res = await fetch(`${API}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, role: authRole, session_id: sessionId, captcha })
    });
    const data = await res.json();
    if (!res.ok) {
      showFormError(data.detail || 'Login failed.');
      loadCaptcha('login-session-id', 'login-captcha-img');
      return;
    }
    token = data.token;
    currentUser = { account_id: data.account_id, username: data.username, role: data.role, cert_id: data.cert_id };
    localStorage.setItem('token', token);
    localStorage.setItem('user', JSON.stringify(currentUser));
    if (data.cert_id) {
      localStorage.setItem(`certId_${data.username}`, data.cert_id);
    } else {
      localStorage.removeItem(`certId_${data.username}`);
    }
    closeAuth();

    userPrivateKey = localStorage.getItem(`privateKey_${currentUser.username}`);
    userCertId = parseInt(localStorage.getItem(`certId_${currentUser.username}`)) || currentUser.cert_id;

    if (!userPrivateKey && currentUser.role === 'customer') {
      showImportKeyBanner();
    }

    clearKeyLogin();
    showDashboard();
    toast('Welcome, ' + currentUser.username, 'success');
  } catch { showFormError('Network error - is the server running?'); }
}

// Log in using a private key via challenge-response authentication
async function doLoginWithKey(username, role, privateKeyPem) {
  // Step 1: Request a challenge from the server
  const chalRes = await fetch(`${API}/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, role })
  });
  const chalData = await chalRes.json();
  if (!chalRes.ok) { showFormError(chalData.detail || 'Failed to get challenge'); return; }

  // Step 2: Sign the challenge with the private key
  let signature;
  try {
    signature = await signWithPrivateKey(privateKeyPem, chalData.challenge);
  } catch (e) {
    showFormError('Failed to sign challenge: ' + e.message); return;
  }

  // Step 3: Submit the signature for verification
  const sessionId = document.getElementById('login-session-id').value;
  const captcha = document.getElementById('login-captcha-input').value.trim();
  if (!captcha) { showFormError('Please enter the security code.'); return; }

  const res = await fetch(`${API}/auth/login-with-key`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, role, signature, session_id: sessionId, captcha })
  });
  const data = await res.json();
  if (!res.ok) {
    showFormError(data.detail || 'Login failed');
    loadCaptcha('login-session-id', 'login-captcha-img');
    return;
  }

  token = data.token;
  currentUser = { account_id: data.account_id, username: data.username, role: data.role };
  localStorage.setItem('token', token);
  localStorage.setItem('user', JSON.stringify(currentUser));

  // Restore private key into memory
  userPrivateKey = privateKeyPem;
  localStorage.setItem(`privateKey_${username}`, privateKeyPem);
  userCertId = parseInt(localStorage.getItem(`certId_${username}`));

  pendingPrivateKey = null;
  closeAuth();
  clearKeyLogin();
  showDashboard();
  toast('Welcome, ' + username, 'success');
}

// Handle .pem file upload for private-key login
function handleKeyLoginFile(event) {
  const file = event.target.files[0];
  if (!file) return;

  // Show loading state with disabled remove link while reading
  const filenameEl = document.getElementById('key-login-filename');
  filenameEl.innerHTML = `Loading ${esc(file.name)}…`;

  const reader = new FileReader();
  reader.onload = e => {
    pendingPrivateKey = e.target.result;
    // Show loaded state with active remove link
    filenameEl.innerHTML =
      `✓ ${esc(file.name)} loaded &nbsp;` +
      `<a id="remove-key-btn" onclick="clearKeyLogin()" ` +
      `style="cursor:pointer;color:var(--danger);text-decoration:underline;">Remove</a>`;
  };
  reader.readAsText(file);
}

// Clear the pending private key, reset the file input, uncheck the toggle, and re-enable password
function clearKeyLogin() {
  pendingPrivateKey = null;
  const filenameEl = document.getElementById('key-login-filename');
  if (filenameEl) filenameEl.textContent = '';
  const fileInput = document.getElementById('key-login-file');
  if (fileInput) fileInput.value = '';
  // Uncheck the toggle and hide the upload area
  const cb = document.getElementById('use-key-login');
  if (cb) cb.checked = false;
  const uploadArea = document.getElementById('key-upload-area');
  if (uploadArea) uploadArea.style.display = 'none';
  // Re-enable the password field
  const pw = document.getElementById('auth-password');
  if (pw) { pw.disabled = false; pw.placeholder = 'Enter password'; }
}

// Toggle between password login and private-key login modes
function toggleKeyLogin(checkbox) {
  const passwordField = document.getElementById('auth-password');
  const uploadArea = document.getElementById('key-upload-area');

  if (checkbox.checked) {
    // Key login mode: clear and disable password input, show file upload
    passwordField.value = '';
    passwordField.disabled = true;
    passwordField.placeholder = 'Not required for key login';
    uploadArea.style.display = 'block';
  } else {
    // Password login mode: re-enable password, hide upload, clear any loaded key
    passwordField.disabled = false;
    passwordField.placeholder = 'Enter password';
    uploadArea.style.display = 'none';
    pendingPrivateKey = null;
    const filenameEl = document.getElementById('key-login-filename');
    if (filenameEl) filenameEl.textContent = '';
    const fileInput = document.getElementById('key-login-file');
    if (fileInput) fileInput.value = '';
  }
}

// Trigger a browser download of the private key as a .pem file
function downloadPrivateKey(username, privateKeyPem) {
  const blob = new Blob([privateKeyPem], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${username}_private_key.pem`;
  a.click();
  URL.revokeObjectURL(url);
}

// Show a warning banner prompting the user to import their private key
function showImportKeyBanner() {
  const existing = document.getElementById('key-import-banner');
  if (existing) existing.remove();

  const banner = document.createElement('div');
  const dashboard = document.querySelector('#page-customer .dashboard');
  banner.id = 'key-import-banner';
  banner.style = 'background:rgba(255,179,71,.1);border:1px solid rgba(255,179,71,.4);color:#ffb347;padding:12px 16px;border-radius:10px;font-family:var(--mono);font-size:13px;margin-bottom:20px;';
  banner.innerHTML = `
    Private key not found in this browser.
    <label style="text-decoration:underline;cursor:pointer;">
      Import your .pem file
      <input type="file" accept=".pem" style="display:none" onchange="importPrivateKey(event)">
    </label>
    to enable purchasing.`;
  dashboard.prepend(banner);
}

// Read an imported .pem file and store the private key in memory and localStorage
function importPrivateKey(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    const pem = e.target.result;
    userPrivateKey = pem;
    localStorage.setItem(`privateKey_${currentUser.username}`, pem);
    const banner = document.getElementById('key-import-banner');
    if (banner) banner.remove();
    toast('Private key imported successfully.', 'success');
  };
  reader.readAsText(file);
}

// ── CAPTCHA ───────────────────────────────────────────────────────────────

// Generate a unique UUID to use as the captcha session identifier
function generateSessionId() {
  return crypto.randomUUID();
}

// Fetch a fresh captcha image from the server and update the img element
async function loadCaptcha(sessionIdElementId, imgElementId) {
  const sessionId = generateSessionId();
  document.getElementById(sessionIdElementId).value = sessionId;
  const res = await fetch(`${API}/auth/captcha?session_id=${sessionId}`);
  const data = await res.json();
  document.getElementById(imgElementId).src = data.image;
}

// Reload the captcha image (called when the user clicks the image)
function refreshCaptcha(sessionIdElementId, imgElementId) {
  loadCaptcha(sessionIdElementId, imgElementId);
}

// ── MERCHANT ──────────────────────────────────────────────────────────────

// Submit the add-product form and refresh the merchant's product list
async function addProduct() {
  const name = document.getElementById('p-name').value.trim();
  const price = parseFloat(document.getElementById('p-price').value);
  const stock = parseInt(document.getElementById('p-stock').value) || 0;
  const desc = document.getElementById('p-desc').value.trim();

  if (!name) { toast('Product name is required.', 'error'); return; }
  if (!price || price <= 0) { toast('Please enter a valid price.', 'error'); return; }

  const res = await apiFetch('/products', 'POST', { product_name: name, price, stock, description: desc });
  if (res) {
    toast('Product added successfully.', 'success');
    document.getElementById('p-name').value = '';
    document.getElementById('p-price').value = '';
    document.getElementById('p-stock').value = '';
    document.getElementById('p-desc').value = '';
    loadMerchantProducts();
    loadStats();
  }
}

// Fetch and render the merchant's own product list as a table
async function loadMerchantProducts() {
  const data = await apiFetch(`/products?merchant_id=${currentUser.account_id}`, 'GET');
  if (!data) return;
  const el = document.getElementById('merchant-products');
  if (!data.length) {
    el.innerHTML = '<div class="empty-state"><div class="empty-icon">📦</div>No products yet — add one above</div>';
    return;
  }
  el.innerHTML = `<table class="product-table">
    <thead><tr>
      <th>Name</th><th>Price</th><th>Stock</th><th>Description</th><th>Actions</th>
    </tr></thead>
    <tbody>
    ${data.map(p => `
      <tr>
        <td><strong>${esc(p.product_name)}</strong></td>
        <td class="price-tag">$${p.price.toFixed(2)}</td>
        <td>${p.stock}</td>
        <td style="color:var(--muted);max-width:200px">${esc(p.description || '—')}</td>
        <td style="display:flex;gap:8px">
          <button class="btn-sm btn-edit" onclick="openEdit(${p.product_id},'${esc(p.product_name)}',${p.price},${p.stock},'${esc(p.description || '')}')">Edit</button>
          <button class="btn-sm btn-danger" onclick="deleteProduct(${p.product_id})">Delete</button>
        </td>
      </tr>`).join('')}
    </tbody></table>`;
}

// Fetch and render all incoming orders for the merchant
async function loadMerchantOrders() {
  const data = await apiFetch('/merchant/orders', 'GET');
  if (!data) return;
  const el = document.getElementById('merchant-orders');
  if (!data.length) {
    el.innerHTML = '<div class="empty-state"><div class="empty-icon">📋</div>No orders yet.</div>';
    return;
  }
  el.innerHTML = `<table class="product-table">
    <thead><tr>
      <th>Order ID</th><th>Product</th><th>Customer</th><th>Qty</th><th>Total</th><th>Status</th><th>Date</th>
    </tr></thead>
    <tbody>
    ${data.map(o => `
      <tr>
        <td>#${o.order_id}</td>
        <td>${esc(o.product_name)}</td>
        <td>${esc(o.customer_name)}</td>
        <td>${o.quantity}</td>
        <td class="price-tag">$${o.total_amount.toFixed(2)}</td>
        <td><span style="color:${o.order_status === 'paid' ? 'var(--accent)' : 'var(--warn)'}">
          ${o.order_status}</span></td>
        <td style="color:var(--muted);font-size:12px">
          ${new Date(o.create_time * 1000).toLocaleDateString()}</td>
      </tr>`).join('')}
    </tbody></table>`;
}

// Fetch and display the merchant's product count and total stock
async function loadStats() {
  const data = await apiFetch('/merchant/stats', 'GET');
  if (!data) return;
  document.getElementById('stat-products').textContent = data.total_products;
  document.getElementById('stat-stock').textContent = data.total_stock;
}

// Confirm and delete a product by ID
async function deleteProduct(id) {
  if (!confirm('Delete this product?')) return;
  const res = await apiFetch(`/products/${id}`, 'DELETE');
  if (res) { toast('Product deleted.', 'success'); loadMerchantProducts(); loadStats(); }
}

// Populate and open the edit product modal
function openEdit(id, name, price, stock, desc) {
  document.getElementById('edit-id').value = id;
  document.getElementById('edit-name').value = name;
  document.getElementById('edit-price').value = price;
  document.getElementById('edit-stock').value = stock;
  document.getElementById('edit-desc').value = desc;
  document.getElementById('edit-modal').classList.add('active');
}

// Close the edit product modal
function closeEdit() { document.getElementById('edit-modal').classList.remove('active'); }

// Submit the edited product fields to the server
async function saveEdit() {
  const id = document.getElementById('edit-id').value;
  const body = {
    product_name: document.getElementById('edit-name').value.trim(),
    price: parseFloat(document.getElementById('edit-price').value),
    stock: parseInt(document.getElementById('edit-stock').value),
    description: document.getElementById('edit-desc').value.trim()
  };
  const res = await apiFetch(`/products/${id}`, 'PUT', body);
  if (res) { toast('Product updated.', 'success'); closeEdit(); loadMerchantProducts(); loadStats(); }
}

// ── CUSTOMER ──────────────────────────────────────────────────────────────

// Fetch all available products and render them as cards
async function loadAllProducts() {
  const data = await apiFetch('/products', 'GET');
  if (!data) return;
  allProducts = data;
  renderProducts(data);
}

// Fetch and render the customer's order history as a table
async function loadCustomerOrders() {
  const data = await apiFetch('/orders', 'GET');
  if (!data) return;
  const el = document.getElementById('customer-orders');
  if (!data.length) {
    el.innerHTML = '<div class="empty-state"><div class="empty-icon">📋</div>No orders yet.</div>';
    return;
  }
  el.innerHTML = `<table class="product-table">
    <thead><tr>
      <th>Order ID</th><th>Product</th><th>Qty</th><th>Total</th><th>Status</th><th>Date</th>
    </tr></thead>
    <tbody>
    ${data.map(o => `
      <tr>
        <td>#${o.order_id}</td>
        <td>${esc(o.product_name || String(o.product_id))}</td>
        <td>${o.quantity}</td>
        <td class="price-tag">$${o.total_amount.toFixed(2)}</td>
        <td><span style="color:${o.order_status === 'paid' ? 'var(--accent)' : 'var(--warn)'}">
          ${o.order_status}</span></td>
        <td style="color:var(--muted);font-size:12px">
          ${new Date(o.create_time * 1000).toLocaleDateString()}</td>
      </tr>`).join('')}
    </tbody></table>`;
}

// Filter the product grid by the search input value
function filterProducts() {
  const q = document.getElementById('search-input').value.toLowerCase();
  renderProducts(allProducts.filter(p => p.product_name.toLowerCase().includes(q)));
}

// Render an array of products as cards in the customer marketplace grid
function renderProducts(products) {
  const el = document.getElementById('customer-products');
  if (!products.length) {
    el.innerHTML = '<div class="empty-state" style="grid-column:1/-1"><div class="empty-icon">🔍</div>No products found.</div>';
    return;
  }
  el.innerHTML = products.map(p => `
    <div class="product-card">
      <div class="product-card-name">${esc(p.product_name)}</div>
      <div class="product-card-merchant">🏪 ${esc(p.merchant_name)}</div>
      <div class="product-card-desc">${esc(p.description || 'No description available.')}</div>
      <div class="product-card-footer">
        <div class="product-card-price">$${p.price.toFixed(2)}</div>
        <span class="stock-badge ${p.stock > 0 ? 'in-stock' : 'out-stock'}">
          ${p.stock > 0 ? 'In stock: ' + p.stock : 'Out of stock'}
        </span>
      </div>
      ${p.stock > 0 ? `<button class="btn-primary green" style="width:100%;margin-top:12px;" onclick='openOrder(${JSON.stringify(p)})'>Buy</button>` : ''}
    </div>`).join('');
}

// ── UTILS ─────────────────────────────────────────────────────────────────

function luhnCheck(cardNumber) {
  let sum = 0;
  let shouldDouble = false;
  for (let i = cardNumber.length - 1; i >= 0; i--) {
    let digit = parseInt(cardNumber[i]);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

// Centralised fetch wrapper that attaches the JWT token and handles errors
async function apiFetch(path, method = 'GET', body = null) {
  try {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }
    };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(API + path, opts);
    if (res.status === 401) { logout(); return null; }
    const data = await res.json();
    if (!res.ok) { toast(data.detail || 'Request failed.', 'error'); return null; }
    return data;
  } catch { toast('Network error.', 'error'); return null; }
}

// Escape special HTML characters to prevent XSS when inserting user data into innerHTML
function esc(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Display a temporary toast notification at the bottom-right of the screen
function toast(msg, type = 'success') {
  const c = document.getElementById('toasts');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span>${type === 'success' ? '✓' : '✕'}</span>${msg}`;
  c.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

// ── ORDER FLOW ────────────────────────────────────────────────────────────

// Open the order modal and pre-fill it with the selected product's details
function openOrder(product) {
  orderProduct = product;
  document.getElementById('order-error').style.display = 'none';
  document.getElementById('order-success').style.display = 'none';
  document.getElementById('order-step-1').style.display = 'block';
  document.getElementById('order-step-2').style.display = 'none';
  document.getElementById('order-qty').value = 1;
  document.getElementById('order-card').value = '';
  document.getElementById('order-product-summary').innerHTML =
    `<div style="text-align:center;font-size:16px;font-weight:800;margin-bottom:14px;">
     ${esc(product.product_name)}
   </div>
   <table style="width:100%;border-collapse:collapse;font-family:var(--mono);font-size:13px;">
     <tr style="border-bottom:1px solid var(--border);">
       <td style="padding:7px 0;color:var(--muted);">Merchant</td>
       <td style="padding:7px 0;text-align:right;">${esc(product.merchant_name)}</td>
     </tr>
     <tr style="border-bottom:1px solid var(--border);">
       <td style="padding:7px 0;color:var(--muted);">Unit price</td>
       <td style="padding:7px 0;text-align:right;color:var(--accent);">$${product.price.toFixed(2)}</td>
     </tr>
     <tr style="border-bottom:1px solid var(--border);">
       <td style="padding:7px 0;color:var(--muted);">Available stock</td>
       <td style="padding:7px 0;text-align:right;">${product.stock}</td>
     </tr>
     <tr>
       <td style="padding:7px 0;color:var(--muted);">Quantity</td>
       <td style="padding:7px 0;text-align:right;color:var(--accent);" id="order-summary-qty">1</td>
     </tr>
   </table>`;
  updateOrderTotal();
  document.getElementById('order-step-msg').innerHTML = '';
  loadCaptcha('order-session-id', 'order-captcha-img');
  document.getElementById('order-captcha-input').value = '';
  document.getElementById('order-modal').classList.add('active');
}

// Close the order modal and clear the progress log
function closeOrder() {
  document.getElementById('order-modal').classList.remove('active');
  document.getElementById('order-step-msg').innerHTML = '';
}

// Recalculate and display the order total when quantity changes
function updateOrderTotal() {
  if (!orderProduct) return;
  const qty = parseInt(document.getElementById('order-qty').value) || 1;
  const total = (orderProduct.price * qty).toFixed(2);
  document.getElementById('order-total').textContent = '$' + total;

  const qtyEl = document.getElementById('order-summary-qty');
  if (qtyEl) qtyEl.textContent = qty;
}

// Append a step message to the order progress log and switch to the processing view
function setOrderStep(msg) {
  document.getElementById('order-step-1').style.display = 'none';
  document.getElementById('order-step-2').style.display = 'block';
  const el = document.getElementById('order-step-msg');
  el.innerHTML += msg + '<br>';
}

// Execute the full order and payment flow: sign → submit order → encrypt → pay
async function submitOrder() {
  const qty = parseInt(document.getElementById('order-qty').value);
  const card = document.getElementById('order-card').value.trim();
  const sessionId = document.getElementById('order-session-id').value;
  const captcha = document.getElementById('order-captcha-input').value.trim();
  if (!captcha) { showOrderError('Please enter the security code.'); return; }

  // check quantity's validity
  if (!qty || qty < 1) { showOrderError('Please enter a valid quantity.'); return; }
  if (qty > orderProduct.stock) { showOrderError('Quantity exceeds available stock.'); return; }

  // check card number's validity
  if (!card || card.length !== 16 || !/^\d+$/.test(card)) {
    showOrderError('Please enter a valid 16-digit card number.'); return;
  }
  if (!luhnCheck(card)) {
    showOrderError('Invalid card number.'); return;
  }

  document.getElementById('order-error').style.display = 'none';

  // Step A: Verify private key and cert ID are available
  setOrderStep('Step 1/4 — Loading security credentials…');
  if (!userPrivateKey || !userCertId) {
    showOrderError('Security keys not found. Please log out and log in again.');
    resetOrderStep(); return;
  }
  setOrderStep('Credentials ready.');

  // Step B: Build and sign the order digest
  setOrderStep('Step 2/4 — Signing order with private key…');
  const totalAmount = parseFloat((orderProduct.price * qty).toFixed(2));
  const nonce = crypto.randomUUID();
  const orderDigest = JSON.stringify({
    nonce: nonce,
    product_id: orderProduct.product_id,
    quantity: qty,
    total_amount: totalAmount
  });
  //alert(orderDigest)

  let customerSignature;
  try {
    customerSignature = await signWithPrivateKey(userPrivateKey, orderDigest);
  } catch (e) {
    showOrderError('Failed to sign order: ' + e.message);
    resetOrderStep(); return;
  }

  // Step C: Submit the signed order to the merchant server
  setOrderStep('Step 3/4 — Submitting order to merchant…');
  const orderRes = await apiFetch('/orders', 'POST', {
    product_id: orderProduct.product_id,
    quantity: qty,
    nonce: nonce,
    customer_signature: customerSignature,
    customer_cert_id: userCertId,
    session_id: sessionId,
    captcha: captcha
  });
  if (!orderRes) {
    loadCaptcha('order-session-id', 'order-captcha-img');
    resetOrderStep(); return;
  }

  // Step D: Encrypt payment info and submit to the gateway
  setOrderStep('Step 4/4 — Encrypting payment info and submitting to gateway…');
  let gwKeyRes;
  try {
    gwKeyRes = await fetch('http://localhost:8102/gateway/public-key');
    gwKeyRes = await gwKeyRes.json();
  } catch (e) {
    showOrderError('Payment gateway unreachable.'); resetOrderStep(); return;
  }

  let encryptedPayment;
  try {
    const paymentInfo = JSON.stringify({ card_number: card, amount: totalAmount });
    encryptedPayment = await encryptWithPublicKey(gwKeyRes.public_key, paymentInfo);
  } catch (e) {
    showOrderError('Encryption failed: ' + e.message); resetOrderStep(); return;
  }

  // Sign the order ID separately for the gateway to verify the payment request
  const paymentDigest = JSON.stringify({
    amount: totalAmount,
    nonce: nonce,
    order_id: orderRes.order_id
  });  // no space
  const orderIdSignature = await signWithPrivateKey(userPrivateKey, paymentDigest);

  const payRes = await apiFetch('/payments/submit', 'POST', {
    order_id: orderRes.order_id,
    encrypted_payment_info: encryptedPayment,
    customer_signature: orderIdSignature,
    customer_cert_id: userCertId
  });
  if (!payRes) { resetOrderStep(); return; }

  // Show success message
  document.getElementById('order-step-msg').innerHTML +=
    '<span style="color:var(--accent)">Payment successful!</span><br>' +
    'Order ID: ' + orderRes.order_id;
  document.getElementById('order-success').textContent =
    'Order placed and payment confirmed!';
  document.getElementById('order-success').style.display = 'block';
  toast('Payment successful! Order #' + orderRes.order_id, 'success');
  setTimeout(() => { closeOrder(); loadAllProducts(); }, 3000);
  loadCustomerOrders();
}

// Display an error message inside the order modal
function showOrderError(msg) {
  const el = document.getElementById('order-error');
  el.textContent = msg;
  el.style.display = 'block';
}

// Restore the order modal to its initial input state, hiding the progress log
function resetOrderStep() {
  document.getElementById('order-step-1').style.display = 'block';
  document.getElementById('order-step-2').style.display = 'none';
  document.getElementById('order-step-msg').innerHTML = '';
}

// ── CRYPTO (Web Crypto API) ────────────────────────────────────────────────

// Sign data using RSA-PKCS1v15 SHA-256 with a PKCS8 PEM private key
async function signWithPrivateKey(privateKeyPem, data) {
  const pemBody = privateKeyPem
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s/g, '');

  const binaryDer = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    'pkcs8', binaryDer.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['sign']
  );
  const enc = new TextEncoder();
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(data));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Encrypt data using RSA-OAEP SHA-256 with a SubjectPublicKeyInfo PEM public key
async function encryptWithPublicKey(publicKeyPem, data) {
  const pemBody = publicKeyPem
    .replace('-----BEGIN PUBLIC KEY-----', '')
    .replace('-----END PUBLIC KEY-----', '')
    .replace(/\s/g, '');
  const binaryDer = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    'spki', binaryDer.buffer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false, ['encrypt']
  );
  const enc = new TextEncoder();
  const encrypted = await crypto.subtle.encrypt('RSA-OAEP', key, enc.encode(data));
  return Array.from(new Uint8Array(encrypted)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── CERTIFICATE MANAGEMENT ────────────────────────────────────────────────

// Revoke the current certificate and issue a new one after verifying captcha and password

// Generate RSA-2048 key pair locally in the browser, private key never leaves the client
async function generateKeypairLocally() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256'
    },
    true, ['sign', 'verify']
  );
  const privDer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  const pubDer = await crypto.subtle.exportKey('spki', keyPair.publicKey);

  const toB64Lines = buf =>
    btoa(String.fromCharCode(...new Uint8Array(buf))).match(/.{1,64}/g).join('\n');

  const privPem = `-----BEGIN PRIVATE KEY-----\n${toB64Lines(privDer)}\n-----END PRIVATE KEY-----`;
  const pubPem = `-----BEGIN PUBLIC KEY-----\n${toB64Lines(pubDer)}\n-----END PUBLIC KEY-----`;

  return { private_key_pem: privPem, public_key_pem: pubPem };
}

async function revokeAndReissue() {
  const password = document.getElementById('revoke-password').value;
  if (!password) {
    document.getElementById('revoke-error').textContent = 'Please enter your password.';
    document.getElementById('revoke-error').style.display = 'block';
    return;
  }
  const captcha = document.getElementById('revoke-captcha-input').value.trim();
  if (!captcha) {
    document.getElementById('revoke-error').textContent = 'Please enter the security code.';
    document.getElementById('revoke-error').style.display = 'block';
    //btn.disabled = false;
    //btn.textContent = 'Confirm Revocation';
    return;
  }

  // Disable button to prevent double-click
  const btn = document.querySelector('#revoke-modal .btn-submit');
  btn.disabled = true;
  btn.textContent = 'Processing…';

  document.getElementById('revoke-error').style.display = 'none';
  document.getElementById('revoke-success').style.display = 'none';

  try {
    const kpRes = await generateKeypairLocally();

    const sessionId = document.getElementById('revoke-session-id').value;
    const certRes = await apiFetch('/auth/revoke-and-reissue', 'POST', {
      password: password,
      new_public_key_pem: kpRes.public_key_pem,
      session_id: sessionId,
      captcha: captcha
    });
    if (!certRes) {
      loadCaptcha('revoke-session-id', 'revoke-captcha-img');
      btn.disabled = false; btn.textContent = 'Confirm Revocation'; return;
    }

    // Update in-memory and stored credentials
    localStorage.setItem(`privateKey_${currentUser.username}`, kpRes.private_key_pem);
    localStorage.setItem(`certId_${currentUser.username}`, certRes.cert_id);
    userPrivateKey = kpRes.private_key_pem;
    userCertId = certRes.cert_id;

    downloadPrivateKey(currentUser.username, kpRes.private_key_pem);

    document.getElementById('revoke-success').textContent =
      'Certificate re-issued. New private key downloaded.  Please re-import the new key on other browsers/devices.';
    document.getElementById('revoke-success').style.display = 'block';
    toast('Certificate revoked and re-issued successfully.', 'success');

    setTimeout(() => closeRevokeModal(), 2000);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Confirm Revocation';
  }
}

// Open the revoke-and-reissue modal and load a fresh captcha
function openRevokeModal() {
  document.getElementById('revoke-modal-tag').textContent =
    currentUser.role === 'merchant' ? '🏪 Merchant' : '🛍️ Customer';
  document.getElementById('revoke-password').value = '';
  document.getElementById('revoke-captcha-input').value = '';
  document.getElementById('revoke-error').style.display = 'none';
  document.getElementById('revoke-success').style.display = 'none';
  loadCaptcha('revoke-session-id', 'revoke-captcha-img');
  document.getElementById('revoke-modal').classList.add('active');
}

// Close the revoke certificate modal
function closeRevokeModal() {
  document.getElementById('revoke-modal').classList.remove('active');
}

// Fetch certificate expiry status from the server and update the dashboard stat card
async function checkCertStatus() {
  const elId = currentUser.role === 'merchant' ? 'stat-cert-days-merchant' : 'stat-cert-days-customer';
  const el = document.getElementById(elId);

  const data = await apiFetch('/auth/cert-status', 'GET');
  if (!data || data.status === 'no_cert' || data.status === 'ca_unreachable') return;

  if (data.status === 'expired') {
    el.textContent = 'Expired';
    el.style.color = 'var(--danger)';
  } else if (data.status === 'expiring_almost') {
    el.textContent = `${data.days_left} day`;
    el.style.color = 'var(--warn)';
  } else if (data.status === 'expiring_soon') {
    el.textContent = `${data.days_left} days`;
    el.style.color = 'var(--warn)';
  } else {
    el.textContent = `${data.days_left} days`;
    el.style.color = 'var(--accent)';
  }
}

// ── MODAL OVERLAY CLOSE LISTENERS ────────────────────────────────────────