const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { asyncHandler, AppError } = require('../middleware/error');
const { protect } = require('../middleware/auth');
const { authValidation } = require('../middleware/validation');

/**
 * @route   POST /api/auth/signup
 * @desc    Register a new user
 * @access  Public
 */
router.post('/signup', authValidation.signup, asyncHandler(async (req, res) => {
  const { email, password, username } = req.body;

  // Check if user exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    throw new AppError('Email already registered', 400, 'EMAIL_EXISTS');
  }

  // Create user
  const user = await User.create({
    email,
    password,
    username
  });

  // Generate tokens
  const token = user.generateAuthToken();
  const refreshToken = user.generateRefreshToken();
  await user.save();

  res.status(201).json({
    success: true,
    data: {
      user: user.toPublicJSON(),
      token,
      refreshToken
    }
  });
}));

/**
 * @route   POST /api/auth/login
 * @desc    Login user
 * @access  Public
 */
router.post('/login', authValidation.login, asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Find user with password
  const user = await User.findOne({ email }).select('+password');
  
  if (!user) {
    throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
  }

  // Check password
  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
  }

  // Update last login
  user.lastLogin = new Date();
  
  // Generate tokens
  const token = user.generateAuthToken();
  const refreshToken = user.generateRefreshToken();
  await user.save();

  res.json({
    success: true,
    data: {
      user: user.toPublicJSON(),
      token,
      refreshToken
    }
  });
}));

/**
 * @route   POST /api/auth/refresh
 * @desc    Refresh access token
 * @access  Public
 */
router.post('/refresh', asyncHandler(async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    throw new AppError('Refresh token required', 400, 'NO_REFRESH_TOKEN');
  }

  // Find user with this refresh token
  const user = await User.findOne({ refreshToken }).select('+refreshToken');
  
  if (!user) {
    throw new AppError('Invalid refresh token', 401, 'INVALID_REFRESH_TOKEN');
  }

  // Generate new tokens
  const newToken = user.generateAuthToken();
  const newRefreshToken = user.generateRefreshToken();
  await user.save();

  res.json({
    success: true,
    data: {
      token: newToken,
      refreshToken: newRefreshToken
    }
  });
}));

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user
 * @access  Private
 */
router.post('/logout', protect, asyncHandler(async (req, res) => {
  // Clear refresh token
  req.user.refreshToken = null;
  await req.user.save();

  res.json({
    success: true,
    message: 'Logged out successfully'
  });
}));

/**
 * @route   GET /api/auth/me
 * @desc    Get current user
 * @access  Private
 */
router.get('/me', protect, asyncHandler(async (req, res) => {
  res.json({
    success: true,
    data: {
      user: req.user.toPublicJSON()
    }
  });
}));

/**
 * @route   POST /api/auth/wallet
 * @desc    Connect wallet address
 * @access  Private
 */
router.post('/wallet', protect, asyncHandler(async (req, res) => {
  const { walletAddress } = req.body;

  if (!walletAddress || !/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
    throw new AppError('Invalid wallet address', 400, 'INVALID_WALLET');
  }

  // Check if wallet already connected to another account
  const existingUser = await User.findOne({ 
    walletAddress, 
    _id: { $ne: req.user._id } 
  });
  
  if (existingUser) {
    throw new AppError('Wallet already connected to another account', 400, 'WALLET_EXISTS');
  }

  req.user.walletAddress = walletAddress;
  await req.user.save();

  res.json({
    success: true,
    data: {
      user: req.user.toPublicJSON()
    }
  });
}));

/**
 * @route   DELETE /api/auth/wallet
 * @desc    Disconnect wallet address
 * @access  Private
 */
router.delete('/wallet', protect, asyncHandler(async (req, res) => {
  req.user.walletAddress = undefined;
  await req.user.save();

  res.json({
    success: true,
    data: {
      user: req.user.toPublicJSON()
    }
  });
}));

module.exports = router;
