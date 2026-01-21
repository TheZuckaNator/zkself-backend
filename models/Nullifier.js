const mongoose = require('mongoose');

const NullifierSchema = new mongoose.Schema({
  // The nullifier hash itself
  nullifierHash: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  // External nullifier (context identifier)
  externalNullifier: {
    type: String,
    required: true,
    description: 'Context-specific identifier (e.g., airdrop contract, DAO vote ID)'
  },
  // What type of action this nullifier prevents double-spending on
  actionType: {
    type: String,
    enum: [
      'airdrop_claim',
      'dao_vote',
      'age_verification',
      'humanity_check',
      'country_check',
      'custom'
    ],
    required: true
  },
  // Reference to the proof that created this nullifier
  proof: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Proof'
  },
  // User who used this nullifier (optional, for analytics)
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  // Context details
  context: {
    contractAddress: String,
    chainId: Number,
    applicationName: String,
    additionalData: mongoose.Schema.Types.Mixed
  },
  // Verification details
  verification: {
    verified: { type: Boolean, default: false },
    verifiedAt: Date,
    txHash: String,
    blockNumber: Number
  },
  // Expiry (optional - some nullifiers may expire)
  expiresAt: {
    type: Date,
    default: null // null = never expires
  }
}, {
  timestamps: true
});

// Compound index for checking if a nullifier exists for a specific context
NullifierSchema.index({ externalNullifier: 1, nullifierHash: 1 }, { unique: true });
NullifierSchema.index({ actionType: 1, externalNullifier: 1 });

// Static method to check if nullifier is already used
NullifierSchema.statics.isNullifierUsed = async function(nullifierHash, externalNullifier) {
  const existing = await this.findOne({ 
    nullifierHash, 
    externalNullifier 
  });
  return !!existing;
};

// Static method to register a new nullifier
NullifierSchema.statics.registerNullifier = async function(data) {
  const {
    nullifierHash,
    externalNullifier,
    actionType,
    proof,
    user,
    context
  } = data;

  // Check if already exists
  const existing = await this.findOne({ nullifierHash, externalNullifier });
  if (existing) {
    throw new Error('Nullifier already used for this context');
  }

  return this.create({
    nullifierHash,
    externalNullifier,
    actionType,
    proof,
    user,
    context
  });
};

// Method to mark as verified on-chain
NullifierSchema.methods.markVerified = async function(txHash, blockNumber) {
  this.verification = {
    verified: true,
    verifiedAt: new Date(),
    txHash,
    blockNumber
  };
  return this.save();
};

module.exports = mongoose.model('Nullifier', NullifierSchema);
