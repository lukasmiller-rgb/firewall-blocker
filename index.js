const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const compression = require('compression');
const path = require('path');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================================
// SECURITY MIDDLEWARE
// ============================================================================

// Helmet - Set security HTTP headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com'],
      fontSrc: ['https://cdnjs.cloudflare.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  frameguard: { action: 'deny' },
  noSniff: true,
  xssFilter: true
}));

// Compression - Reduce response size
app.use(compression());

// Body parser with strict limits
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ limit: '10kb', extended: true }));

// Data sanitization against NoSQL injection
app.use(mongoSanitize());

// Static files
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1h',
  etag: false
}));

// ============================================================================
// RATE LIMITING - MULTIPLE LAYERS
// ============================================================================

// Global rate limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP',
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/health',
  keyGenerator: (req) => req.ip,
  store: new (require('rate-limit-redis'))({
    client: require('redis').createClient(),
    prefix: 'rl:global:'
  }).catch(() => null) // Fallback if Redis not available
});

// API rate limiter - Strict
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 20,
  message: 'Too many API requests',
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
});

// Check access rate limiter - Very strict
const checkAccessLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 30,
  message: 'Too many access checks',
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
});

// Block/Allow operations rate limiter
const modifyListLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10,
  message: 'Too many list modifications',
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
});

app.use(globalLimiter);

// ============================================================================
// INPUT VALIDATION & SANITIZATION
// ============================================================================

const MAX_INPUT_LENGTH = 255;
const MAX_LIST_SIZE = 5000;
const VALID_TYPES = ['url', 'domain', 'ip'];

const isValidIP = (ip) => {
  if (!ip || typeof ip !== 'string' || ip.length > MAX_INPUT_LENGTH) return false;
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipRegex.test(ip)) return false;
  return ip.split('.').every(part => {
    const num = parseInt(part, 10);
    return !isNaN(num) && num >= 0 && num <= 255;
  });
};

const isValidURL = (input) => {
  if (!input || typeof input !== 'string' || input.length > MAX_INPUT_LENGTH) return false;
  try {
    const urlToTest = input.startsWith('http') ? input : `http://${input}`;
    new URL(urlToTest);
    return true;
  } catch (e) {
    return false;
  }
};

const isValidDomain = (domain) => {
  if (!domain || typeof domain !== 'string' || domain.length > MAX_INPUT_LENGTH) return false;
  const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain);
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
  if (!input || typeof input !== 'string') return '';
  return input
    .trim()
    .slice(0, MAX_INPUT_LENGTH)
    .replace(/[<>"'{}\\]/g, '') // Remove dangerous characters
    .toLowerCase();
};

const validateType = (type) => VALID_TYPES.includes(type);

// ============================================================================
// DATA STORAGE WITH PERSISTENCE
// ============================================================================

const listStore = {
  blocked: { urls: new Set(), ips: new Set(), domains: new Set() },
  allowed: { urls: new Set(), ips: new Set(), domains: new Set() },
  
  addItem(listType, itemType, value) {
    if (!this[listType] || !this[listType][itemType]) {
      throw new Error('Invalid list or item type');
    }
    
    const sanitized = sanitizeInput(value);
    if (!sanitized) throw new Error('Invalid input');
    
    // Validate based on type
    if (itemType === 'ip' && !isValidIP(sanitized)) {
      throw new Error('Invalid IP address format');
    }
    if (itemType === 'domain' && !isValidDomain(sanitized)) {
      throw new Error('Invalid domain format');
    }
    if (itemType === 'url' && !isValidURL(sanitized)) {
      throw new Error('Invalid URL format');
    }
    
    // Check if already exists
    if (this[listType][itemType].has(sanitized)) {
      throw new Error('Item already in list');
    }
    
    // Check size limit
    if (this[listType][itemType].size >= MAX_LIST_SIZE) {
      throw new Error(`${itemType} list is full (max ${MAX_LIST_SIZE})`);
    }
    
    this[listType][itemType].add(sanitized);
    return true;
  },
  
  removeItem(listType, itemType, value) {
    if (!this[listType] || !this[listType][itemType]) {
      throw new Error('Invalid list or item type');
    }
    
    const sanitized = sanitizeInput(value);
    return this[listType][itemType].delete(sanitized);
  },
  
  itemExists(listType, itemType, value) {
    if (!this[listType] || !this[listType][itemType]) return false;
    const sanitized = sanitizeInput(value);
    return this[listType][itemType].has(sanitized);
  },
  
  getLists() {
    return {
      blocked: {
        urls: Array.from(this.blocked.urls),
        ips: Array.from(this.blocked.ips),
        domains: Array.from(this.blocked.domains)
      },
      allowed: {
        urls: Array.from(this.allowed.urls),
        ips: Array.from(this.allowed.ips),
        domains: Array.from(this.allowed.domains)
      }
    };
  },
  
  getStats() {
    return {
      blocked: {
        urls: this.blocked.urls.size,
        ips: this.blocked.ips.size,
        domains: this.blocked.domains.size,
        total: this.blocked.urls.size + this.blocked.ips.size + this.blocked.domains.size
      },
      allowed: {
        urls: this.allowed.urls.size,
        ips: this.allowed.ips.size,
        domains: this.allowed.domains.size,
        total: this.allowed.urls.size + this.allowed.ips.size + this.allowed.domains.size
      }
    };
  }
};

// ============================================================================
// ROUTES
// ============================================================================

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage().heapUsed / 1024 / 1024
  });
});

app.get('/api/stats', apiLimiter, (req, res) => {
  try {
    res.json({
      stats: listStore.getStats(),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve stats' });
  }
});

app.post('/api/check-access', checkAccessLimiter, async (req, res) => {
  try {
    const { input, type } = req.body;
    
    if (!input || typeof input !== 'string') {
      return res.status(400).json({ error: 'Invalid input' });
    }
    
    const sanitized = sanitizeInput(input);
    if (!sanitized) {
      return res.status(400).json({ error: 'Input is empty or invalid' });
    }
    
    const determinedType = type || 'url';
    if (!validateType(determinedType)) {
      return res.status(400).json({ error: 'Invalid type' });
    }
    
    const isAllowed = await checkAccess(sanitized, determinedType);
    
    res.json({
      input: sanitized,
      type: determinedType,
      allowed: isAllowed,
      status: isAllowed ? 'ALLOWED' : 'BLOCKED',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/allow', modifyListLimiter, (req, res) => {
  try {
    const { input, type = 'url' } = req.body;
    
    if (!input || typeof input !== 'string') {
      return res.status(400).json({ error: 'Invalid input' });
    }
    
    if (!validateType(type)) {
      return res.status(400).json({ error: 'Invalid type' });
    }
    
    listStore.addItem('allowed', type, input);
    
    res.status(201).json({
      message: `Successfully added to allowed list`,
      item: sanitizeInput(input),
      type,
      stats: listStore.getStats(),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/block', modifyListLimiter, (req, res) => {
  try {
    const { input, type = 'url' } = req.body;
    
    if (!input || typeof input !== 'string') {
      return res.status(400).json({ error: 'Invalid input' });
    }
    
    if (!validateType(type)) {
      return res.status(400).json({ error: 'Invalid type' });
    }
    
    listStore.addItem('blocked', type, input);
    
    res.status(201).json({
      message: `Successfully added to blocked list`,
      item: sanitizeInput(input),
      type,
      stats: listStore.getStats(),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/unblock', modifyListLimiter, (req, res) => {
  try {
    const { input, type = 'url' } = req.body;
    
    if (!input || typeof input !== 'string') {
      return res.status(400).json({ error: 'Invalid input' });
    }
    
    if (!validateType(type)) {
      return res.status(400).json({ error: 'Invalid type' });
    }
    
    const removed = listStore.removeItem('blocked', type, input);
    
    if (!removed) {
      return res.status(404).json({ error: 'Item not found in blocked list' });
    }
    
    res.json({
      message: 'Successfully removed from blocked list',
      item: sanitizeInput(input),
      type,
      stats: listStore.getStats(),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/lists', apiLimiter, (req, res) => {
  try {
    res.json({
      lists: listStore.getLists(),
      stats: listStore.getStats(),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve lists' });
  }
});

// ============================================================================
// ACCESS CHECKING LOGIC
// ============================================================================

async function checkAccess(input, type = 'url') {
  const isIP = isValidIP(input);
  const domain = extractDomain(input);
  const lists = listStore.getLists();
  
  // Check allowed list first (whitelist priority)
  if ((type === 'ip' && lists.allowed.ips.includes(input)) ||
      (type === 'domain' && lists.allowed.domains.includes(input)) ||
      (type === 'url' && (lists.allowed.urls.includes(input) || lists.allowed.domains.includes(domain)))) {
    return true;
  }
  
  // Check blocked list
  if ((type === 'ip' && lists.blocked.ips.includes(input)) ||
      (type === 'domain' && lists.blocked.domains.includes(input)) ||
      (type === 'url' && (lists.blocked.urls.includes(input) || lists.blocked.domains.includes(domain)))) {
    return false;
  }
  
  // Verify accessibility for URLs
  if (type === 'url') {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      
      const response = await axios.head(input.startsWith('http') ? input : `http://${input}`, {
        timeout: 5000,
        maxRedirects: 3,
        validateStatus: () => true,
        headers: {
          'User-Agent': 'Firewall-Blocker/1.0'
        }
      });
      
      clearTimeout(timeout);
      return response.status >= 200 && response.status < 400;
    } catch (error) {
      return false;
    }
  }
  
  return true; // Default allow for unrecognized items
}

// ============================================================================
// ERROR HANDLING & LOGGING
// ============================================================================

app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    path: req.path,
    method: req.method
  });
});

app.use((err, req, res, next) => {
  console.error('[ERROR]', {
    message: err.message,
    path: req.path,
    method: req.method,
    ip: req.ip,
    timestamp: new Date().toISOString()
  });
  
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message,
    requestId: `${Date.now()}-${Math.random()}`
  });
});

// ============================================================================
// SERVER STARTUP
// ============================================================================

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🔥 Firewall Blocker - Enhanced Security Edition`);
  console.log(`📍 Running on port ${PORT}`);
  console.log(`🌍 Access: http://localhost:${PORT}`);
  console.log(`🏥 Health: http://localhost:${PORT}/health`);
  console.log(`📊 Stats: http://localhost:${PORT}/api/stats`);
  console.log(`🛡️  Security: Helmet + Rate Limiting + Input Validation`);
  console.log(`⏰ Started: ${new Date().toISOString()}\n`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('\n⚠️  SIGTERM received - Shutting down gracefully...');
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('\n⚠️  SIGINT received - Shutting down gracefully...');
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});

process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

module.exports = app;