const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false
  },
  walletAddress: {
    type: String,
    sparse: true,
    unique: true,
    match: [/^0x[a-fA-F0-9]{40}$/, 'Invalid wallet address']
  },
  username: {
    type: String,
    trim: true,
    maxlength: [50, 'Username cannot exceed 50 characters']
  },
  zkIdentityCommitment: {
    type: String,
    description: 'Poseidon hash commitment of user identity (used in ZK proofs)'
  },
  kycStatus: {
    type: String,
    enum: ['none', 'pending', 'verified', 'rejected', 'expired'],
    default: 'none'
  },
  kycVerifiedAt: {
    type: Date
  },
  kycExpiresAt: {
    type: Date
  },
  // Encrypted/hashed KYC data (never stored in plaintext)
  kycDataHash: {
    type: String,
    description: 'Hash of KYC data for commitment verification'
  },
  // Privacy attributes (derived from KYC, stored as commitments)
  privacyAttributes: {
    isAdult: { type: Boolean, default: false },
    isHuman: { type: Boolean, default: false },
    countryCode: { type: String }, // ISO 3166-1 alpha-2
    isNotSanctioned: { type: Boolean, default: false }
  },
  settings: {
    twoFactorEnabled: { type: Boolean, default: false },
    emailNotifications: { type: Boolean, default: true },
    darkMode: { type: Boolean, default: true }
  },
  lastLogin: {
    type: Date
  },
  refreshToken: {
    type: String,
    select: false
  }
}, {
  timestamps: true
});

// Index for faster queries
UserSchema.index({ email: 1 });
UserSchema.index({ walletAddress: 1 });
UserSchema.index({ zkIdentityCommitment: 1 });

// Hash password before saving
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    return next();
  }
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Compare password method
UserSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Generate JWT token
UserSchema.methods.generateAuthToken = function() {
  return jwt.sign(
    { 
      id: this._id, 
      email: this.email,
      kycStatus: this.kycStatus 
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE || '7d' }
  );
};

// Generate refresh token
UserSchema.methods.generateRefreshToken = function() {
  const refreshToken = jwt.sign(
    { id: this._id },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );
  this.refreshToken = refreshToken;
  return refreshToken;
};

// Check if KYC is valid
UserSchema.methods.isKycValid = function() {
  if (this.kycStatus !== 'verified') return false;
  if (this.kycExpiresAt && new Date() > this.kycExpiresAt) return false;
  return true;
};

// Get public profile (safe to expose)
UserSchema.methods.toPublicJSON = function() {
  return {
    id: this._id,
    email: this.email,
    username: this.username,
    walletAddress: this.walletAddress,
    kycStatus: this.kycStatus,
    kycVerifiedAt: this.kycVerifiedAt,
    privacyAttributes: {
      isAdult: this.privacyAttributes?.isAdult || false,
      isHuman: this.privacyAttributes?.isHuman || false,
      isNotSanctioned: this.privacyAttributes?.isNotSanctioned || false
    },
    settings: this.settings,
    createdAt: this.createdAt
  };
};

module.exports = mongoose.model('User', UserSchema);
