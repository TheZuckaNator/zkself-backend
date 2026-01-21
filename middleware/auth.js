const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { AppError } = require('./error');

// Protect routes - require authentication
const protect = async (req, res, next) => {
  let token;

  // Check for token in header
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  // Check for token in cookies (optional)
  if (!token && req.cookies?.token) {
    token = req.cookies.token;
  }

  if (!token) {
    return next(new AppError('Not authorized to access this route', 401, 'NO_TOKEN'));
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Get user from token
    const user = await User.findById(decoded.id);

    if (!user) {
      return next(new AppError('User not found', 401, 'USER_NOT_FOUND'));
    }

    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return next(new AppError('Token expired', 401, 'TOKEN_EXPIRED'));
    }
    return next(new AppError('Not authorized to access this route', 401, 'INVALID_TOKEN'));
  }
};

// Require KYC verification
const requireKyc = async (req, res, next) => {
  if (!req.user) {
    return next(new AppError('Authentication required', 401, 'NO_AUTH'));
  }

  if (req.user.kycStatus !== 'verified') {
    return next(new AppError('KYC verification required', 403, 'KYC_REQUIRED'));
  }

  if (!req.user.isKycValid()) {
    return next(new AppError('KYC has expired, please re-verify', 403, 'KYC_EXPIRED'));
  }

  next();
};

// Optional authentication (doesn't fail if no token)
const optionalAuth = async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return next();
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (user) {
      req.user = user;
    }
  } catch (error) {
    // Ignore errors for optional auth
  }

  next();
};

// Rate limiting helper (basic in-memory, use Redis in production)
const rateLimitStore = new Map();

const rateLimit = (maxRequests, windowMs) => {
  return (req, res, next) => {
    const key = req.user?.id || req.ip;
    const now = Date.now();
    const windowStart = now - windowMs;

    // Get or create request log
    let requestLog = rateLimitStore.get(key) || [];
    
    // Filter to only requests within window
    requestLog = requestLog.filter(timestamp => timestamp > windowStart);

    if (requestLog.length >= maxRequests) {
      const retryAfter = Math.ceil((requestLog[0] + windowMs - now) / 1000);
      res.set('Retry-After', retryAfter);
      return next(new AppError('Too many requests, please try again later', 429, 'RATE_LIMIT'));
    }

    // Add current request
    requestLog.push(now);
    rateLimitStore.set(key, requestLog);

    next();
  };
};

module.exports = {
  protect,
  requireKyc,
  optionalAuth,
  rateLimit
};
