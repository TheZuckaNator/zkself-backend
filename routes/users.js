const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Proof = require('../models/Proof');
const KycSession = require('../models/KycSession');
const { asyncHandler, AppError } = require('../middleware/error');
const { protect } = require('../middleware/auth');
const { userValidation } = require('../middleware/validation');

/**
 * @route   GET /api/users/profile
 * @desc    Get current user's profile
 * @access  Private
 */
router.get('/profile', protect, asyncHandler(async (req, res) => {
  res.json({
    success: true,
    data: { user: req.user.toPublicJSON() }
  });
}));

/**
 * @route   PUT /api/users/profile
 * @desc    Update current user's profile
 * @access  Private
 */
router.put('/profile', protect, userValidation.update, asyncHandler(async (req, res) => {
  const allowedUpdates = ['username', 'walletAddress', 'settings'];
  const updates = {};

  for (const field of allowedUpdates) {
    if (req.body[field] !== undefined) {
      updates[field] = req.body[field];
    }
  }

  // Check wallet uniqueness if being updated
  if (updates.walletAddress) {
    const existingUser = await User.findOne({
      walletAddress: updates.walletAddress,
      _id: { $ne: req.user._id }
    });
    if (existingUser) {
      throw new AppError('Wallet already connected to another account', 400, 'WALLET_EXISTS');
    }
  }

  Object.assign(req.user, updates);
  await req.user.save();

  res.json({
    success: true,
    data: { user: req.user.toPublicJSON() }
  });
}));

/**
 * @route   PUT /api/users/password
 * @desc    Change password
 * @access  Private
 */
router.put('/password', protect, userValidation.changePassword, asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  // Get user with password
  const user = await User.findById(req.user._id).select('+password');

  // Verify current password
  const isMatch = await user.comparePassword(currentPassword);
  if (!isMatch) {
    throw new AppError('Current password is incorrect', 401, 'INVALID_PASSWORD');
  }

  // Update password
  user.password = newPassword;
  await user.save();

  res.json({
    success: true,
    message: 'Password updated successfully'
  });
}));

/**
 * @route   GET /api/users/stats
 * @desc    Get user statistics
 * @access  Private
 */
router.get('/stats', protect, asyncHandler(async (req, res) => {
  const [proofStats, kycSessions] = await Promise.all([
    Proof.aggregate([
      { $match: { user: req.user._id } },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]),
    KycSession.countDocuments({ user: req.user._id })
  ]);

  const stats = {
    totalProofs: 0,
    activeProofs: 0,
    revokedProofs: 0,
    expiredProofs: 0,
    kycSessions: kycSessions
  };

  proofStats.forEach(stat => {
    stats.totalProofs += stat.count;
    if (stat._id === 'generated' || stat._id === 'verified') {
      stats.activeProofs += stat.count;
    } else if (stat._id === 'revoked') {
      stats.revokedProofs += stat.count;
    } else if (stat._id === 'expired') {
      stats.expiredProofs += stat.count;
    }
  });

  res.json({
    success: true,
    data: { stats }
  });
}));

/**
 * @route   PUT /api/users/settings
 * @desc    Update user settings
 * @access  Private
 */
router.put('/settings', protect, asyncHandler(async (req, res) => {
  const allowedSettings = ['twoFactorEnabled', 'emailNotifications', 'darkMode'];
  const updates = {};

  for (const setting of allowedSettings) {
    if (req.body[setting] !== undefined) {
      updates[`settings.${setting}`] = req.body[setting];
    }
  }

  await User.findByIdAndUpdate(req.user._id, { $set: updates });
  
  const updatedUser = await User.findById(req.user._id);

  res.json({
    success: true,
    data: { settings: updatedUser.settings }
  });
}));

/**
 * @route   DELETE /api/users/account
 * @desc    Delete user account
 * @access  Private
 */
router.delete('/account', protect, asyncHandler(async (req, res) => {
  const { password } = req.body;

  if (!password) {
    throw new AppError('Password required to delete account', 400, 'PASSWORD_REQUIRED');
  }

  // Verify password
  const user = await User.findById(req.user._id).select('+password');
  const isMatch = await user.comparePassword(password);
  
  if (!isMatch) {
    throw new AppError('Password is incorrect', 401, 'INVALID_PASSWORD');
  }

  // Delete user's proofs (mark as deleted, not hard delete)
  await Proof.updateMany(
    { user: req.user._id },
    { $set: { status: 'revoked' } }
  );

  // Delete user
  await User.findByIdAndDelete(req.user._id);

  res.json({
    success: true,
    message: 'Account deleted successfully'
  });
}));

module.exports = router;
