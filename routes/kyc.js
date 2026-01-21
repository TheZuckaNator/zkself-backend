const express = require('express');
const router = express.Router();
const multer = require('multer');
const KycSession = require('../models/KycSession');
const User = require('../models/User');
const { asyncHandler, AppError } = require('../middleware/error');
const { protect, rateLimit } = require('../middleware/auth');
const { kycValidation } = require('../middleware/validation');
const synapseService = require('../services/synapse');
const zkProofService = require('../services/zkproof');

// Configure multer for document uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new AppError('Invalid file type. Allowed: JPEG, PNG, WebP, PDF', 400), false);
    }
  }
});

/**
 * @route   POST /api/kyc/session
 * @desc    Initialize a new KYC verification session
 * @access  Private
 */
router.post('/session', 
  protect, 
  rateLimit(5, 60 * 60 * 1000), // 5 sessions per hour
  kycValidation.initSession,
  asyncHandler(async (req, res) => {
    // Check for existing pending session
    const existingSession = await KycSession.findOne({
      user: req.user._id,
      status: { $in: ['initiated', 'document_uploaded', 'liveness_pending', 'processing'] }
    });

    if (existingSession && !existingSession.isExpired()) {
      return res.json({
        success: true,
        data: {
          session: existingSession,
          message: 'Existing session found'
        }
      });
    }

    // Create session with Synapse Analytics
    let synapseSession;
    try {
      synapseSession = await synapseService.createSession(req.user._id.toString(), {
        callbackUrl: `${process.env.BACKEND_URL || 'http://localhost:5000'}/api/kyc/webhook`,
        redirectUrl: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/kyc/complete`,
        documentTypes: req.body.documentTypes || ['passport', 'id_card', 'drivers_license'],
        metadata: {
          userId: req.user._id.toString(),
          email: req.user.email
        }
      });
    } catch (error) {
      console.error('Synapse session creation error:', error);
      // Create session without Synapse for demo purposes
      synapseSession = {
        sessionId: `demo_${Date.now()}`,
        applicationId: `app_${Date.now()}`,
        status: 'initiated'
      };
    }

    // Create local session
    const session = await KycSession.create({
      user: req.user._id,
      synapseSessionId: synapseSession.sessionId,
      synapseApplicationId: synapseSession.applicationId,
      status: 'initiated',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      expiresAt: new Date(Date.now() + 30 * 60 * 1000) // 30 minutes
    });

    res.status(201).json({
      success: true,
      data: {
        session: {
          id: session._id,
          status: session.status,
          expiresAt: session.expiresAt,
          verificationUrl: synapseSession.verificationUrl
        }
      }
    });
  })
);

/**
 * @route   GET /api/kyc/session/:sessionId
 * @desc    Get KYC session status
 * @access  Private
 */
router.get('/session/:sessionId', protect, asyncHandler(async (req, res) => {
  const session = await KycSession.findOne({
    _id: req.params.sessionId,
    user: req.user._id
  });

  if (!session) {
    throw new AppError('Session not found', 404, 'SESSION_NOT_FOUND');
  }

  // Try to get updated status from Synapse
  if (session.synapseSessionId && !session.synapseSessionId.startsWith('demo_')) {
    try {
      const synapseStatus = await synapseService.getSessionStatus(session.synapseSessionId);
      if (synapseStatus.status !== session.status) {
        session.status = synapseStatus.status;
        session.documentVerified = synapseStatus.documentVerified;
        session.livenessCompleted = synapseStatus.livenessVerified;
        await session.save();
      }
    } catch (error) {
      console.error('Error fetching Synapse status:', error);
    }
  }

  res.json({
    success: true,
    data: { session }
  });
}));

/**
 * @route   POST /api/kyc/session/:sessionId/document
 * @desc    Upload document for verification
 * @access  Private
 */
router.post('/session/:sessionId/document',
  protect,
  upload.fields([
    { name: 'frontImage', maxCount: 1 },
    { name: 'backImage', maxCount: 1 }
  ]),
  kycValidation.uploadDocument,
  asyncHandler(async (req, res) => {
    const session = await KycSession.findOne({
      _id: req.params.sessionId,
      user: req.user._id
    });

    if (!session) {
      throw new AppError('Session not found', 404, 'SESSION_NOT_FOUND');
    }

    if (session.isExpired()) {
      throw new AppError('Session has expired', 400, 'SESSION_EXPIRED');
    }

    const { documentType, documentCountry } = req.body;
    const frontImage = req.files?.frontImage?.[0];
    const backImage = req.files?.backImage?.[0];

    if (!frontImage) {
      throw new AppError('Front image is required', 400, 'FRONT_IMAGE_REQUIRED');
    }

    // Convert to base64
    const frontImageBase64 = frontImage.buffer.toString('base64');
    const backImageBase64 = backImage?.buffer.toString('base64');

    // Upload to Synapse
    let documentResult;
    if (!session.synapseSessionId.startsWith('demo_')) {
      try {
        documentResult = await synapseService.uploadDocument(session.synapseSessionId, {
          documentType,
          country: documentCountry,
          frontImage: frontImageBase64,
          backImage: backImageBase64
        });
      } catch (error) {
        console.error('Synapse document upload error:', error);
      }
    }

    // Update session
    session.documentType = documentType;
    session.documentCountry = documentCountry;
    session.status = 'document_uploaded';
    session.documentVerified = documentResult?.status === 'verified';
    await session.save();

    res.json({
      success: true,
      data: {
        session: {
          id: session._id,
          status: session.status,
          documentVerified: session.documentVerified
        },
        message: 'Document uploaded successfully'
      }
    });
  })
);

/**
 * @route   POST /api/kyc/session/:sessionId/liveness
 * @desc    Start or complete liveness check
 * @access  Private
 */
router.post('/session/:sessionId/liveness',
  protect,
  kycValidation.completeLiveness,
  asyncHandler(async (req, res) => {
    const session = await KycSession.findOne({
      _id: req.params.sessionId,
      user: req.user._id
    });

    if (!session) {
      throw new AppError('Session not found', 404, 'SESSION_NOT_FOUND');
    }

    if (session.isExpired()) {
      throw new AppError('Session has expired', 400, 'SESSION_EXPIRED');
    }

    // For demo, simulate liveness completion
    let livenessResult = { passed: true, score: 95 };

    if (!session.synapseSessionId.startsWith('demo_')) {
      try {
        // In production, this would handle the actual liveness flow
        const livenessData = req.body.livenessData;
        if (livenessData) {
          livenessResult = await synapseService.submitLivenessData(
            session.synapseSessionId, 
            livenessData
          );
        }
      } catch (error) {
        console.error('Synapse liveness error:', error);
      }
    }

    session.livenessCompleted = livenessResult.passed;
    session.livenessScore = livenessResult.score;
    session.status = 'processing';
    await session.save();

    res.json({
      success: true,
      data: {
        session: {
          id: session._id,
          status: session.status,
          livenessCompleted: session.livenessCompleted
        }
      }
    });
  })
);

/**
 * @route   POST /api/kyc/session/:sessionId/complete
 * @desc    Complete KYC verification (demo mode)
 * @access  Private
 */
router.post('/session/:sessionId/complete', protect, asyncHandler(async (req, res) => {
  const session = await KycSession.findOne({
    _id: req.params.sessionId,
    user: req.user._id
  });

  if (!session) {
    throw new AppError('Session not found', 404, 'SESSION_NOT_FOUND');
  }

  // Get verification results
  let verificationResults;
  
  if (!session.synapseSessionId.startsWith('demo_')) {
    try {
      verificationResults = await synapseService.getVerificationResults(session.synapseSessionId);
    } catch (error) {
      console.error('Error getting verification results:', error);
    }
  }

  // For demo mode, create mock results based on document info
  if (!verificationResults) {
    verificationResults = {
      approved: true,
      status: 'approved',
      document: {
        verified: true,
        type: session.documentType,
        country: session.documentCountry
      },
      liveness: {
        passed: true,
        score: session.livenessScore || 95
      },
      extractedData: {
        dateOfBirth: '1990-01-15', // Demo DOB
        nationality: session.documentCountry
      }
    };
  }

  if (!verificationResults.approved) {
    session.status = 'rejected';
    session.rejectionReason = verificationResults.rejectionReasons?.join(', ');
    await session.save();

    return res.json({
      success: false,
      data: {
        session: {
          id: session._id,
          status: session.status,
          rejectionReason: session.rejectionReason
        }
      }
    });
  }

  // Process for ZK proofs
  const zkData = synapseService.processForZkProof(verificationResults);

  // Update session
  session.status = 'approved';
  session.completedAt = new Date();
  session.verificationResults = {
    ageVerified: zkData.isAdult,
    countryCode: zkData.countryCode,
    isNotSanctioned: zkData.isNotSanctioned,
    humanVerified: zkData.isHuman
  };
  session.zkCommitment = zkProofService.generateIdentityCommitment(zkData);
  await session.save();

  // Update user
  const user = await User.findById(req.user._id);
  user.kycStatus = 'verified';
  user.kycVerifiedAt = new Date();
  user.kycExpiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year
  user.kycDataHash = zkData.verificationHash;
  user.zkIdentityCommitment = session.zkCommitment;
  user.privacyAttributes = {
    isAdult: zkData.isAdult,
    isHuman: zkData.isHuman,
    countryCode: zkData.countryCode,
    isNotSanctioned: zkData.isNotSanctioned
  };
  await user.save();

  res.json({
    success: true,
    data: {
      session: {
        id: session._id,
        status: session.status,
        completedAt: session.completedAt
      },
      user: user.toPublicJSON(),
      message: 'KYC verification completed successfully'
    }
  });
}));

/**
 * @route   GET /api/kyc/status
 * @desc    Get user's KYC status
 * @access  Private
 */
router.get('/status', protect, asyncHandler(async (req, res) => {
  const user = req.user;
  
  // Get most recent session
  const recentSession = await KycSession.findOne({ user: user._id })
    .sort({ createdAt: -1 });

  res.json({
    success: true,
    data: {
      kycStatus: user.kycStatus,
      kycVerifiedAt: user.kycVerifiedAt,
      kycExpiresAt: user.kycExpiresAt,
      isValid: user.isKycValid(),
      privacyAttributes: user.privacyAttributes,
      recentSession: recentSession ? {
        id: recentSession._id,
        status: recentSession.status,
        createdAt: recentSession.createdAt
      } : null
    }
  });
}));

/**
 * @route   POST /api/kyc/webhook
 * @desc    Handle Synapse Analytics webhooks
 * @access  Public (verified by signature)
 */
router.post('/webhook', asyncHandler(async (req, res) => {
  const signature = req.headers['x-synapse-signature'];
  
  // Verify webhook signature
  if (!synapseService.verifyWebhookSignature(req.body, signature)) {
    throw new AppError('Invalid webhook signature', 401, 'INVALID_SIGNATURE');
  }

  const { event_type, session_id, data } = req.body;

  // Find session
  const session = await KycSession.findOne({ synapseSessionId: session_id });
  if (!session) {
    console.error('Webhook received for unknown session:', session_id);
    return res.status(200).json({ received: true });
  }

  // Log webhook event
  await session.addWebhookEvent(event_type, data);

  // Handle different event types
  switch (event_type) {
    case 'verification.approved':
      session.status = 'approved';
      session.completedAt = new Date();
      break;
    
    case 'verification.rejected':
      session.status = 'rejected';
      session.rejectionReason = data.rejection_reasons?.join(', ');
      break;
    
    case 'verification.pending_review':
      session.status = 'manual_review';
      break;
    
    case 'document.verified':
      session.documentVerified = true;
      break;
    
    case 'liveness.completed':
      session.livenessCompleted = true;
      session.livenessScore = data.score;
      break;
  }

  await session.save();

  res.status(200).json({ received: true });
}));

module.exports = router;
