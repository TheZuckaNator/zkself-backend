const express = require('express');
const router = express.Router();
const Proof = require('../models/Proof');
const Nullifier = require('../models/Nullifier');
const { asyncHandler, AppError } = require('../middleware/error');
const { protect, requireKyc, rateLimit } = require('../middleware/auth');
const { proofValidation } = require('../middleware/validation');
const zkProofService = require('../services/zkproof');

/**
 * @route   GET /api/proofs
 * @desc    List all proofs for current user
 * @access  Private
 */
router.get('/', protect, proofValidation.list, asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * limit;

  const filter = { user: req.user._id };
  if (req.query.proofType) filter.proofType = req.query.proofType;
  if (req.query.status) filter.status = req.query.status;

  const [proofs, total] = await Promise.all([
    Proof.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .select('-zkProof'),
    Proof.countDocuments(filter)
  ]);

  res.json({
    success: true,
    data: {
      proofs: proofs.map(p => p.toSummaryJSON()),
      pagination: { page, limit, total, pages: Math.ceil(total / limit) }
    }
  });
}));

/**
 * @route   GET /api/proofs/types
 * @desc    Get available proof types
 * @access  Private
 */
router.get('/types', protect, asyncHandler(async (req, res) => {
  const proofTypes = zkProofService.getProofTypes();
  
  const typesWithAvailability = proofTypes.map(type => ({
    ...type,
    available: req.user.kycStatus === 'verified' && 
               zkProofService.canGenerateProof(type.type, req.user.privacyAttributes)
  }));

  res.json({
    success: true,
    data: { proofTypes: typesWithAvailability }
  });
}));

/**
 * @route   GET /api/proofs/:id
 * @desc    Get single proof by ID
 * @access  Private
 */
router.get('/:id', protect, proofValidation.getById, asyncHandler(async (req, res) => {
  const proof = await Proof.findOne({
    _id: req.params.id,
    user: req.user._id
  });

  if (!proof) {
    throw new AppError('Proof not found', 404, 'PROOF_NOT_FOUND');
  }

  res.json({
    success: true,
    data: { proof }
  });
}));

/**
 * @route   POST /api/proofs/generate
 * @desc    Generate a new ZK proof
 * @access  Private (KYC required)
 */
router.post('/generate',
  protect,
  requireKyc,
  rateLimit(10, 60 * 60 * 1000),
  proofValidation.generate,
  asyncHandler(async (req, res) => {
    const { proofType, name, description, externalNullifier, maxUsage, validDays } = req.body;

    if (!zkProofService.canGenerateProof(proofType, req.user.privacyAttributes)) {
      throw new AppError(
        `Cannot generate ${proofType} proof. Required verification not met.`,
        400,
        'PROOF_NOT_AVAILABLE'
      );
    }

    const userData = {
      verificationHash: req.user.kycDataHash,
      verifiedAt: req.user.kycVerifiedAt,
      ...req.user.privacyAttributes,
      age: req.user.privacyAttributes?.isAdult ? 25 : 17
    };

    const proofRecord = await Proof.create({
      user: req.user._id,
      proofType,
      name,
      description,
      status: 'generating',
      externalNullifier: externalNullifier || null,
      maxUsage: maxUsage || 1,
      validUntil: new Date(Date.now() + (validDays || 365) * 24 * 60 * 60 * 1000)
    });

    try {
      const proofResult = await zkProofService.generateProof(proofType, userData, {
        externalNullifier
      });

      proofRecord.zkProof = proofResult.zkProof;
      proofRecord.publicSignals = proofResult.publicSignals;
      proofRecord.nullifierHash = proofResult.nullifierHash;
      proofRecord.externalNullifier = proofResult.externalNullifier;
      proofRecord.metadata = proofResult.metadata;
      proofRecord.status = 'generated';
      await proofRecord.save();

      await Nullifier.registerNullifier({
        nullifierHash: proofResult.nullifierHash,
        externalNullifier: proofResult.externalNullifier,
        actionType: mapProofTypeToAction(proofType),
        proof: proofRecord._id,
        user: req.user._id
      });

      res.status(201).json({
        success: true,
        data: {
          proof: proofRecord.toSummaryJSON(),
          message: 'Proof generated successfully'
        }
      });

    } catch (error) {
      proofRecord.status = 'failed';
      await proofRecord.save();
      throw error;
    }
  })
);

/**
 * @route   POST /api/proofs/verify
 * @desc    Verify a ZK proof
 * @access  Public
 */
router.post('/verify', proofValidation.verify, asyncHandler(async (req, res) => {
  const { proofType, zkProof, publicSignals, nullifierHash, externalNullifier } = req.body;

  const nullifierUsed = await Nullifier.isNullifierUsed(nullifierHash, externalNullifier);
  if (nullifierUsed) {
    return res.json({
      success: true,
      data: {
        valid: false,
        reason: 'Nullifier already used for this context'
      }
    });
  }

  const verificationResult = await zkProofService.verifyProof(proofType, zkProof, publicSignals);

  res.json({
    success: true,
    data: {
      valid: verificationResult.valid,
      proofType: verificationResult.proofType,
      publicSignals: verificationResult.publicSignals,
      error: verificationResult.error
    }
  });
}));

/**
 * @route   PUT /api/proofs/:id
 * @desc    Update proof metadata
 * @access  Private
 */
router.put('/:id', protect, proofValidation.update, asyncHandler(async (req, res) => {
  const proof = await Proof.findOne({
    _id: req.params.id,
    user: req.user._id
  });

  if (!proof) {
    throw new AppError('Proof not found', 404, 'PROOF_NOT_FOUND');
  }

  const allowedUpdates = ['name', 'description', 'tags', 'isPublic'];
  const updates = {};
  
  for (const field of allowedUpdates) {
    if (req.body[field] !== undefined) {
      updates[field] = req.body[field];
    }
  }

  Object.assign(proof, updates);
  await proof.save();

  res.json({
    success: true,
    data: {
      proof: proof.toSummaryJSON(),
      message: 'Proof updated successfully'
    }
  });
}));

/**
 * @route   DELETE /api/proofs/:id
 * @desc    Delete/revoke a proof
 * @access  Private
 */
router.delete('/:id', protect, proofValidation.delete, asyncHandler(async (req, res) => {
  const proof = await Proof.findOne({
    _id: req.params.id,
    user: req.user._id
  });

  if (!proof) {
    throw new AppError('Proof not found', 404, 'PROOF_NOT_FOUND');
  }

  proof.status = 'revoked';
  await proof.save();

  res.json({
    success: true,
    data: { message: 'Proof revoked successfully' }
  });
}));

/**
 * @route   POST /api/proofs/:id/use
 * @desc    Record proof usage
 * @access  Private
 */
router.post('/:id/use', protect, asyncHandler(async (req, res) => {
  const proof = await Proof.findOne({
    _id: req.params.id,
    user: req.user._id
  });

  if (!proof) {
    throw new AppError('Proof not found', 404, 'PROOF_NOT_FOUND');
  }

  const validity = proof.isValid();
  if (!validity.valid) {
    throw new AppError(validity.reason, 400, 'PROOF_INVALID');
  }

  await proof.recordUsage(req.body.context, req.body.verifierAddress, true);

  res.json({
    success: true,
    data: { proof: proof.toSummaryJSON(), message: 'Usage recorded' }
  });
}));

/**
 * @route   GET /api/proofs/:id/export
 * @desc    Export proof for external verification
 * @access  Private
 */
router.get('/:id/export', protect, asyncHandler(async (req, res) => {
  const proof = await Proof.findOne({
    _id: req.params.id,
    user: req.user._id
  });

  if (!proof) {
    throw new AppError('Proof not found', 404, 'PROOF_NOT_FOUND');
  }

  const validity = proof.isValid();
  if (!validity.valid) {
    throw new AppError(validity.reason, 400, 'PROOF_INVALID');
  }

  res.json({
    success: true,
    data: {
      exportData: proof.toVerificationJSON(),
      exportedAt: new Date().toISOString()
    }
  });
}));

function mapProofTypeToAction(proofType) {
  const mapping = {
    'age_over_18': 'age_verification',
    'age_over_21': 'age_verification',
    'not_sanctioned': 'country_check',
    'is_human': 'humanity_check',
    'unique_person': 'airdrop_claim',
    'country_allowed': 'country_check'
  };
  return mapping[proofType] || 'custom';
}

module.exports = router;
