const mongoose = require('mongoose');

const ProofSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  // Proof type
  proofType: {
    type: String,
    enum: [
      'age_over_18',
      'age_over_21',
      'not_sanctioned',
      'is_human',
      'unique_person',
      'country_allowed',
      'custom'
    ],
    required: true
  },
  // Proof name for display
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  description: {
    type: String,
    maxlength: 500
  },
  // ZK Proof data
  zkProof: {
    pi_a: [String],
    pi_b: [[String]],
    pi_c: [String],
    protocol: { type: String, default: 'groth16' },
    curve: { type: String, default: 'bn128' }
  },
  // Public signals (what gets verified on-chain)
  publicSignals: [{
    type: String
  }],
  // Nullifier to prevent double-use
  nullifierHash: {
    type: String,
    required: false,  // Changed from true - gets set after proof generation
    description: 'Prevents proof reuse for same context'
  },
  // External nullifier (context-specific)
  externalNullifier: {
    type: String,
    description: 'Context identifier (e.g., airdrop ID, DAO vote ID)'
  },
  // Verification status
  status: {
    type: String,
    enum: ['generating', 'generated', 'verified', 'failed', 'expired', 'revoked'],
    default: 'generating'
  },
  // On-chain verification
  onChainVerification: {
    verified: { type: Boolean, default: false },
    txHash: String,
    chainId: Number,
    verifierContract: String,
    verifiedAt: Date,
    blockNumber: Number
  },
  // Usage tracking
  usageCount: {
    type: Number,
    default: 0
  },
  maxUsage: {
    type: Number,
    default: 1, // Single use by default
    description: 'Maximum times this proof can be used (0 = unlimited)'
  },
  lastUsedAt: {
    type: Date
  },
  usageHistory: [{
    usedAt: { type: Date, default: Date.now },
    context: String,
    verifierAddress: String,
    success: Boolean
  }],
  // Validity
  validFrom: {
    type: Date,
    default: Date.now
  },
  validUntil: {
    type: Date,
    default: () => new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year
  },
  // Metadata
  metadata: {
    generationTime: Number, // milliseconds
    circuitName: String,
    witnessHash: String
  },
  // Tags for organization
  tags: [{
    type: String,
    trim: true
  }],
  // Sharing settings
  isPublic: {
    type: Boolean,
    default: false
  },
  sharedWith: [{
    type: String, // Wallet addresses
    match: /^0x[a-fA-F0-9]{40}$/
  }]
}, {
  timestamps: true
});

// Indexes
ProofSchema.index({ user: 1, proofType: 1 });
ProofSchema.index({ nullifierHash: 1 }, { unique: true, sparse: true }); // Added sparse: true for null values
ProofSchema.index({ status: 1 });
ProofSchema.index({ validUntil: 1 });

// Check if proof is valid
ProofSchema.methods.isValid = function() {
  const now = new Date();
  
  if (this.status !== 'generated' && this.status !== 'verified') {
    return { valid: false, reason: 'Proof status is ' + this.status };
  }
  
  if (now < this.validFrom) {
    return { valid: false, reason: 'Proof not yet valid' };
  }
  
  if (now > this.validUntil) {
    return { valid: false, reason: 'Proof has expired' };
  }
  
  if (this.maxUsage > 0 && this.usageCount >= this.maxUsage) {
    return { valid: false, reason: 'Proof usage limit reached' };
  }
  
  return { valid: true };
};

// Record usage
ProofSchema.methods.recordUsage = async function(context = '', verifierAddress = '', success = true) {
  this.usageCount += 1;
  this.lastUsedAt = new Date();
  this.usageHistory.push({
    context,
    verifierAddress,
    success
  });
  return this.save();
};

// Get proof for verification (public data only)
ProofSchema.methods.toVerificationJSON = function() {
  return {
    proofType: this.proofType,
    zkProof: this.zkProof,
    publicSignals: this.publicSignals,
    nullifierHash: this.nullifierHash,
    validUntil: this.validUntil
  };
};

// Get proof summary for listing
ProofSchema.methods.toSummaryJSON = function() {
  return {
    id: this._id,
    proofType: this.proofType,
    name: this.name,
    description: this.description,
    status: this.status,
    usageCount: this.usageCount,
    maxUsage: this.maxUsage,
    validUntil: this.validUntil,
    onChainVerified: this.onChainVerification?.verified || false,
    createdAt: this.createdAt
  };
};

module.exports = mongoose.model('Proof', ProofSchema);