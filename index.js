const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const path = require('path');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================================
// MIDDLEWARE & SECURITY
// ============================================================================

// Rate limiting to prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 30, // limit each IP to 30 API requests per minute
  message: 'Too many API requests, please try again later.',
});

// Middleware
app.use(limiter);
app.use(bodyParser.json({ limit: '1mb' }));
app.use(bodyParser.urlencoded({ limit: '1mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1d' }));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src https://cdnjs.cloudflare.com;");
  next();
});

// ============================================================================
// VALIDATION HELPERS
// ============================================================================

const isValidIP = (ip) => {
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipRegex.test(ip)) return false;
  const parts = ip.split('.');
  return parts.every(part => {
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255;
  });
};

const isValidURL = (input) => {
  try {
    const urlToTest = input.startsWith('http') ? input : `http://${input}`;
    new URL(urlToTest);
    return true;
  } catch (e) {
    return false;
  }
};

const extractDomain = (input) => {
  try {
    const url = new URL(input.startsWith('http') ? input : `http://${input}`);
    return url.hostname;
  } catch (e) {
    return input.replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
  }
};

const sanitizeInput = (input) => {
  if (typeof input !== 'string') return '';
  return input
    .trim()
    .slice(0, 500)
    .replace(/[<>"']/g, '')
    .toLowerCase();
};

const isValidType = (type) => {
  return ['url', 'domain', 'ip'].includes(type);
};

// ============================================================================
// DATA STORAGE
// ============================================================================

const listStore = {
  blocked: { urls: [], ips: [], domains: [] },
  allowed: { urls: [], ips: [], domains: [] },
  
  addItem(listType, itemType, value) {
    if (!this[listType] || !this[listType][itemType]) {
      throw new Error('Invalid list or item type');
    }
    const sanitized = sanitizeInput(value);
    if (!sanitized) throw new Error('Invalid input');
    if (itemType === 'ip' && !isValidIP(sanitized)) {
      throw new Error('Invalid IP address');
    }
    if ((itemType === 'url' || itemType === 'domain') && !isValidURL(sanitized)) {
      throw new Error('Invalid URL or domain');
    }
    if (this[listType][itemType].includes(sanitized)) {
      throw new Error('Item already exists');
    }
    if (this[listType][itemType].length >= 1000) {
      throw new Error('List size limit exceeded');
    }
    this[listType][itemType].push(sanitized);
    return true;
  },
  
  removeItem(listType, itemType, value) {
    if (!this[listType] || !this[listType][itemType]) {
      throw new Error('Invalid list or item type');
    }
    const sanitized = sanitizeInput(value);
    const index = this[listType][itemType].indexOf(sanitized);
    if (index > -1) {
      this[listType][itemType].splice(index, 1);
      return true;
    }
    return false;
  },
  
  getLists() {
    return JSON.parse(JSON.stringify(this));
  }
};

// ============================================================================
// ROUTES
// ============================================================================

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), uptime: process.uptime() });
});

app.post('/api/check-access', apiLimiter, async (req, res) => {
  try {
    const { input } = req.body;
    if (!input || typeof input !== 'string') {
      return res.status(400).json({ error: 'Invalid input' });
    }
    const sanitized = sanitizeInput(input);
    if (!sanitized) {
      return res.status(400).json({ error: 'Input cannot be empty' });
    }
    const isAllowed = await checkAccess(sanitized);
    res.json({
      input: sanitized,
      allowed: isAllowed,
      status: isAllowed ? 'ALLOWED' : 'BLOCKED',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Check access error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/allow', apiLimiter, (req, res) => {
  try {
    const { input, type = 'url' } = req.body;
    if (!input || typeof input !== 'string') {
      return res.status(400).json({ error: 'Invalid input' });
    }
    if (!isValidType(type)) {
      return res.status(400).json({ error: 'Invalid type' });
    }
    listStore.addItem('allowed', type, input);
    res.json({
      message: `${input} added to allowed list`,
      lists: listStore.getLists(),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Allow error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/block', apiLimiter, (req, res) => {
  try {
    const { input, type = 'url' } = req.body;
    if (!input || typeof input !== 'string') {
      return res.status(400).json({ error: 'Invalid input' });
    }
    if (!isValidType(type)) {
      return res.status(400).json({ error: 'Invalid type' });
    }
    listStore.addItem('blocked', type, input);
    res.json({
      message: `${input} added to blocked list`,
      lists: listStore.getLists(),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Block error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/unblock', apiLimiter, (req, res) => {
  try {
    const { input, type = 'url' } = req.body;
    if (!input || typeof input !== 'string') {
      return res.status(400).json({ error: 'Invalid input' });
    }
    if (!isValidType(type)) {
      return res.status(400).json({ error: 'Invalid type' });
    }
    const removed = listStore.removeItem('blocked', type, input);
    if (!removed) {
      return res.status(404).json({ error: 'Item not found' });
    }
    res.json({
      message: `${input} removed`,
      lists: listStore.getLists(),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Unblock error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/lists', apiLimiter, (req, res) => {
  res.json({
    lists: listStore.getLists(),
    timestamp: new Date().toISOString()
  });
});

// ============================================================================
// ACCESS CHECKING
// ============================================================================

async function checkAccess(input) {
  const isIP = isValidIP(input);
  const domain = extractDomain(input);
  const lists = listStore.getLists();
  
  if (lists.allowed.urls.includes(input) ||
      lists.allowed.domains.includes(domain) ||
      (isIP && lists.allowed.ips.includes(input))) {
    return true;
  }
  
  if (lists.blocked.urls.includes(input) ||
      lists.blocked.domains.includes(domain) ||
      (isIP && lists.blocked.ips.includes(input))) {
    return false;
  }
  
  try {
    const urlToCheck = input.startsWith('http') ? input : `http://${input}`;
    const response = await axios.head(urlToCheck, {
      timeout: 5000,
      maxRedirects: 5,
      validateStatus: () => true
    });
    return response.status >= 200 && response.status < 400;
  } catch (error) {
    return false;
  }
}

// ============================================================================
// ERROR HANDLING
// ============================================================================

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message
  });
});

// ============================================================================
// START SERVER
// ============================================================================

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🔥 Firewall Blocker running on port ${PORT}`);
  console.log(`📋 Access at http://localhost:${PORT}`);
  console.log(`🏥 Health check: http://localhost:${PORT}/health`);
});

process.on('SIGTERM', () => {
  console.log('Shutting down...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('Shutting down...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

module.exports = app;