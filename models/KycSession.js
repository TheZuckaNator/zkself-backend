const mongoose = require('mongoose');

const KycSessionSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  // Synapse Analytics session tracking
  synapseSessionId: {
    type: String,
    description: 'Session ID from Synapse Analytics'
  },
  synapseApplicationId: {
    type: String,
    description: 'Application ID from Synapse'
  },
  status: {
    type: String,
    enum: [
      'initiated',      // Session created
      'document_uploaded', // Document submitted
      'liveness_pending',  // Awaiting liveness check
      'processing',     // Being verified by Synapse
      'manual_review',  // Needs manual review
      'approved',       // Verification passed
      'rejected',       // Verification failed
      'expired'         // Session timed out
    ],
    default: 'initiated'
  },
  // Document verification
  documentType: {
    type: String,
    enum: ['passport', 'id_card', 'drivers_license', 'residence_permit'],
  },
  documentCountry: {
    type: String,
    description: 'ISO 3166-1 alpha-2 country code'
  },
  documentVerified: {
    type: Boolean,
    default: false
  },
  // Liveness check
  livenessCompleted: {
    type: Boolean,
    default: false
  },
  livenessScore: {
    type: Number,
    min: 0,
    max: 100
  },
  // Extracted data (encrypted references, not actual data)
  extractedDataRef: {
    type: String,
    description: 'Reference to encrypted KYC data storage'
  },
  // Verification results (hashed for ZK proof generation)
  verificationResults: {
    ageVerified: { type: Boolean },
    dateOfBirth: { type: Date, select: false }, // Hidden from queries
    countryCode: { type: String },
    isNotSanctioned: { type: Boolean },
    humanVerified: { type: Boolean }
  },
  // ZK commitment generated from this session
  zkCommitment: {
    type: String,
    description: 'Poseidon hash commitment for ZK proofs'
  },
  // Rejection/error details
  rejectionReason: {
    type: String
  },
  errorDetails: {
    type: mongoose.Schema.Types.Mixed
  },
  // Webhook tracking
  webhookEvents: [{
    eventType: String,
    receivedAt: { type: Date, default: Date.now },
    payload: mongoose.Schema.Types.Mixed
  }],
  // Timestamps
  initiatedAt: {
    type: Date,
    default: Date.now
  },
  completedAt: {
    type: Date
  },
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + 30 * 60 * 1000) // 30 minutes
  },
  // IP and device info for fraud prevention
  ipAddress: {
    type: String
  },
  userAgent: {
    type: String
  }
}, {
  timestamps: true
});

// Indexes
KycSessionSchema.index({ user: 1, status: 1 });
KycSessionSchema.index({ synapseSessionId: 1 });
KycSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // TTL index

// Check if session is expired
KycSessionSchema.methods.isExpired = function() {
  return new Date() > this.expiresAt;
};

// Update status with timestamp
KycSessionSchema.methods.updateStatus = async function(newStatus, additionalData = {}) {
  this.status = newStatus;
  
  if (['approved', 'rejected', 'expired'].includes(newStatus)) {
    this.completedAt = new Date();
  }
  
  Object.assign(this, additionalData);
  return this.save();
};

// Add webhook event
KycSessionSchema.methods.addWebhookEvent = async function(eventType, payload) {
  this.webhookEvents.push({
    eventType,
    payload,
    receivedAt: new Date()
  });
  return this.save();
};

module.exports = mongoose.model('KycSession', KycSessionSchema);
