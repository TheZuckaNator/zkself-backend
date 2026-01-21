const { body, param, query, validationResult } = require('express-validator');
const { AppError } = require('./error');

// Validation result handler
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const messages = errors.array().map(err => err.msg);
    return next(new AppError(messages.join(', '), 400, 'VALIDATION_ERROR'));
  }
  next();
};

// Auth validations
const authValidation = {
  signup: [
    body('email')
      .isEmail()
      .withMessage('Please provide a valid email')
      .normalizeEmail(),
    body('password')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters')
      .matches(/\d/)
      .withMessage('Password must contain a number')
      .matches(/[a-zA-Z]/)
      .withMessage('Password must contain a letter'),
    body('username')
      .optional()
      .isLength({ min: 2, max: 50 })
      .withMessage('Username must be 2-50 characters')
      .trim(),
    validate
  ],
  
  login: [
    body('email')
      .isEmail()
      .withMessage('Please provide a valid email')
      .normalizeEmail(),
    body('password')
      .notEmpty()
      .withMessage('Password is required'),
    validate
  ],
  
  walletConnect: [
    body('walletAddress')
      .matches(/^0x[a-fA-F0-9]{40}$/)
      .withMessage('Invalid wallet address'),
    body('signature')
      .notEmpty()
      .withMessage('Signature is required'),
    body('message')
      .notEmpty()
      .withMessage('Message is required'),
    validate
  ]
};

// KYC validations
const kycValidation = {
  initSession: [
    body('documentType')
      .optional()
      .isIn(['passport', 'id_card', 'drivers_license', 'residence_permit'])
      .withMessage('Invalid document type'),
    validate
  ],
  
  uploadDocument: [
    param('sessionId')
      .isMongoId()
      .withMessage('Invalid session ID'),
    body('documentType')
      .isIn(['passport', 'id_card', 'drivers_license', 'residence_permit'])
      .withMessage('Invalid document type'),
    body('documentCountry')
      .isLength({ min: 2, max: 2 })
      .withMessage('Country code must be 2 characters (ISO 3166-1 alpha-2)')
      .toUpperCase(),
    validate
  ],
  
  completeLiveness: [
    param('sessionId')
      .isMongoId()
      .withMessage('Invalid session ID'),
    validate
  ]
};

// Proof validations
const proofValidation = {
  generate: [
    body('proofType')
      .isIn(['age_over_18', 'age_over_21', 'not_sanctioned', 'is_human', 'unique_person', 'country_allowed', 'custom'])
      .withMessage('Invalid proof type'),
    body('name')
      .isLength({ min: 1, max: 100 })
      .withMessage('Proof name must be 1-100 characters')
      .trim(),
    body('description')
      .optional()
      .isLength({ max: 500 })
      .withMessage('Description cannot exceed 500 characters')
      .trim(),
    body('externalNullifier')
      .optional()
      .isString()
      .withMessage('External nullifier must be a string'),
    body('maxUsage')
      .optional()
      .isInt({ min: 0, max: 1000 })
      .withMessage('Max usage must be between 0 and 1000'),
    body('validDays')
      .optional()
      .isInt({ min: 1, max: 365 })
      .withMessage('Valid days must be between 1 and 365'),
    validate
  ],
  
  verify: [
    body('proofType')
      .isIn(['age_over_18', 'age_over_21', 'not_sanctioned', 'is_human', 'unique_person', 'country_allowed', 'custom'])
      .withMessage('Invalid proof type'),
    body('zkProof')
      .isObject()
      .withMessage('ZK proof must be an object'),
    body('publicSignals')
      .isArray()
      .withMessage('Public signals must be an array'),
    body('nullifierHash')
      .isString()
      .withMessage('Nullifier hash is required'),
    validate
  ],
  
  getById: [
    param('id')
      .isMongoId()
      .withMessage('Invalid proof ID'),
    validate
  ],
  
  list: [
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('Page must be a positive integer'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('Limit must be between 1 and 100'),
    query('proofType')
      .optional()
      .isIn(['age_over_18', 'age_over_21', 'not_sanctioned', 'is_human', 'unique_person', 'country_allowed', 'custom'])
      .withMessage('Invalid proof type'),
    query('status')
      .optional()
      .isIn(['generating', 'generated', 'verified', 'failed', 'expired', 'revoked'])
      .withMessage('Invalid status'),
    validate
  ],
  
  update: [
    param('id')
      .isMongoId()
      .withMessage('Invalid proof ID'),
    body('name')
      .optional()
      .isLength({ min: 1, max: 100 })
      .withMessage('Proof name must be 1-100 characters')
      .trim(),
    body('description')
      .optional()
      .isLength({ max: 500 })
      .withMessage('Description cannot exceed 500 characters')
      .trim(),
    body('tags')
      .optional()
      .isArray()
      .withMessage('Tags must be an array'),
    body('isPublic')
      .optional()
      .isBoolean()
      .withMessage('isPublic must be a boolean'),
    validate
  ],
  
  delete: [
    param('id')
      .isMongoId()
      .withMessage('Invalid proof ID'),
    validate
  ]
};

// User validations
const userValidation = {
  update: [
    body('username')
      .optional()
      .isLength({ min: 2, max: 50 })
      .withMessage('Username must be 2-50 characters')
      .trim(),
    body('walletAddress')
      .optional()
      .matches(/^0x[a-fA-F0-9]{40}$/)
      .withMessage('Invalid wallet address'),
    body('settings')
      .optional()
      .isObject()
      .withMessage('Settings must be an object'),
    validate
  ],
  
  changePassword: [
    body('currentPassword')
      .notEmpty()
      .withMessage('Current password is required'),
    body('newPassword')
      .isLength({ min: 8 })
      .withMessage('New password must be at least 8 characters')
      .matches(/\d/)
      .withMessage('New password must contain a number')
      .matches(/[a-zA-Z]/)
      .withMessage('New password must contain a letter'),
    validate
  ]
};

module.exports = {
  validate,
  authValidation,
  kycValidation,
  proofValidation,
  userValidation
};
