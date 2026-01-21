const axios = require('axios');
const crypto = require('crypto');
const { AppError } = require('../middleware/error');

/**
 * Synapse Analytics KYC Service
 * Integrates with Synapse Analytics eKYC API for document verification and liveness checks
 */
class SynapseService {
  constructor() {
    this.apiKey = process.env.SYNAPSE_API_KEY;
    this.baseUrl = process.env.SYNAPSE_BASE_URL || 'https://api.synapse-analytics.io/v1';
    this.webhookSecret = process.env.SYNAPSE_WEBHOOK_SECRET;
    
    // Create axios instance with default config
    this.client = axios.create({
      baseURL: this.baseUrl,
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json',
        'X-API-Key': this.apiKey
      },
      timeout: 30000 // 30 second timeout
    });

    // Add response interceptor for error handling
    this.client.interceptors.response.use(
      response => response,
      error => this.handleApiError(error)
    );
  }

  /**
   * Handle API errors consistently
   */
  handleApiError(error) {
    const status = error.response?.status;
    const data = error.response?.data;
    
    let message = 'Synapse Analytics API error';
    let code = 'SYNAPSE_API_ERROR';

    if (status === 401) {
      message = 'Invalid API credentials';
      code = 'SYNAPSE_AUTH_ERROR';
    } else if (status === 403) {
      message = 'API access forbidden';
      code = 'SYNAPSE_FORBIDDEN';
    } else if (status === 404) {
      message = 'Session not found';
      code = 'SYNAPSE_NOT_FOUND';
    } else if (status === 429) {
      message = 'API rate limit exceeded';
      code = 'SYNAPSE_RATE_LIMIT';
    } else if (data?.message) {
      message = data.message;
    }

    const err = new Error(message);
    err.code = code;
    err.statusCode = status || 502;
    err.originalError = error;
    throw err;
  }

  /**
   * Create a new KYC verification session
   */
  async createSession(userId, options = {}) {
    try {
      const response = await this.client.post('/sessions', {
        external_user_id: userId,
        callback_url: options.callbackUrl,
        document_types: options.documentTypes || ['passport', 'id_card', 'drivers_license'],
        liveness_required: options.livenessRequired !== false,
        language: options.language || 'en',
        redirect_url: options.redirectUrl,
        metadata: options.metadata || {}
      });

      return {
        sessionId: response.data.session_id,
        applicationId: response.data.application_id,
        status: response.data.status,
        verificationUrl: response.data.verification_url,
        expiresAt: response.data.expires_at
      };
    } catch (error) {
      console.error('Synapse createSession error:', error);
      throw error;
    }
  }

  /**
   * Get session status
   */
  async getSessionStatus(sessionId) {
    try {
      const response = await this.client.get(`/sessions/${sessionId}`);
      
      return {
        sessionId: response.data.session_id,
        status: this.mapStatus(response.data.status),
        documentVerified: response.data.document_verified,
        livenessVerified: response.data.liveness_verified,
        verificationResults: response.data.verification_results,
        createdAt: response.data.created_at,
        updatedAt: response.data.updated_at
      };
    } catch (error) {
      console.error('Synapse getSessionStatus error:', error);
      throw error;
    }
  }

  /**
   * Upload document for verification
   */
  async uploadDocument(sessionId, documentData) {
    try {
      const response = await this.client.post(`/sessions/${sessionId}/documents`, {
        document_type: documentData.documentType,
        country: documentData.country,
        front_image: documentData.frontImage, // Base64
        back_image: documentData.backImage,   // Base64 (optional for passport)
        metadata: documentData.metadata || {}
      });

      return {
        documentId: response.data.document_id,
        status: response.data.status,
        extractedData: response.data.extracted_data,
        validationResults: response.data.validation_results
      };
    } catch (error) {
      console.error('Synapse uploadDocument error:', error);
      throw error;
    }
  }

  /**
   * Start liveness check
   */
  async startLivenessCheck(sessionId) {
    try {
      const response = await this.client.post(`/sessions/${sessionId}/liveness`, {
        check_type: 'active', // active liveness check
        challenges: ['blink', 'turn_head', 'smile']
      });

      return {
        livenessId: response.data.liveness_id,
        challenges: response.data.challenges,
        verificationUrl: response.data.verification_url
      };
    } catch (error) {
      console.error('Synapse startLivenessCheck error:', error);
      throw error;
    }
  }

  /**
   * Submit liveness video/frames
   */
  async submitLivenessData(sessionId, livenessData) {
    try {
      const response = await this.client.post(`/sessions/${sessionId}/liveness/submit`, {
        video: livenessData.video,     // Base64 encoded video
        frames: livenessData.frames,   // Array of base64 frames
        challenge_responses: livenessData.challengeResponses
      });

      return {
        livenessId: response.data.liveness_id,
        passed: response.data.passed,
        score: response.data.score,
        details: response.data.details
      };
    } catch (error) {
      console.error('Synapse submitLivenessData error:', error);
      throw error;
    }
  }

  /**
   * Get verification results
   */
  async getVerificationResults(sessionId) {
    try {
      const response = await this.client.get(`/sessions/${sessionId}/results`);
      
      const results = response.data;
      
      return {
        approved: results.status === 'approved',
        status: this.mapStatus(results.status),
        document: {
          verified: results.document?.verified,
          type: results.document?.type,
          country: results.document?.country,
          expiryDate: results.document?.expiry_date
        },
        liveness: {
          passed: results.liveness?.passed,
          score: results.liveness?.score
        },
        extractedData: {
          // Only include what we need for ZK proofs
          dateOfBirth: results.extracted_data?.date_of_birth,
          nationality: results.extracted_data?.nationality,
          documentNumber: results.extracted_data?.document_number
        },
        riskIndicators: results.risk_indicators || [],
        rejectionReasons: results.rejection_reasons || []
      };
    } catch (error) {
      console.error('Synapse getVerificationResults error:', error);
      throw error;
    }
  }

  /**
   * Verify webhook signature
   */
  verifyWebhookSignature(payload, signature) {
    if (!this.webhookSecret) {
      console.warn('Webhook secret not configured');
      return true; // Skip verification if no secret
    }

    const expectedSignature = crypto
      .createHmac('sha256', this.webhookSecret)
      .update(JSON.stringify(payload))
      .digest('hex');

    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  }

  /**
   * Map Synapse status to our internal status
   */
  mapStatus(synapseStatus) {
    const statusMap = {
      'pending': 'processing',
      'in_progress': 'processing',
      'awaiting_input': 'document_uploaded',
      'manual_review': 'manual_review',
      'approved': 'approved',
      'rejected': 'rejected',
      'expired': 'expired'
    };
    return statusMap[synapseStatus] || 'processing';
  }

  /**
   * Calculate age from date of birth
   */
  calculateAge(dateOfBirth) {
    const dob = new Date(dateOfBirth);
    const now = new Date();
    let age = now.getFullYear() - dob.getFullYear();
    const monthDiff = now.getMonth() - dob.getMonth();
    
    if (monthDiff < 0 || (monthDiff === 0 && now.getDate() < dob.getDate())) {
      age--;
    }
    
    return age;
  }

  /**
   * Check if country is sanctioned
   */
  isCountrySanctioned(countryCode) {
    // OFAC sanctioned countries (example list - update as needed)
    const sanctionedCountries = [
      'CU', // Cuba
      'IR', // Iran
      'KP', // North Korea
      'SY', // Syria
      'RU', // Russia (partial)
      'BY'  // Belarus
    ];
    return sanctionedCountries.includes(countryCode?.toUpperCase());
  }

  /**
   * Process verification results for ZK proof generation
   */
  processForZkProof(verificationResults) {
    const { extractedData, document } = verificationResults;
    
    const age = extractedData?.dateOfBirth 
      ? this.calculateAge(extractedData.dateOfBirth) 
      : null;
    
    const countryCode = document?.country || extractedData?.nationality;
    
    return {
      isAdult: age !== null && age >= 18,
      isOver21: age !== null && age >= 21,
      isHuman: verificationResults.liveness?.passed !== false,
      countryCode: countryCode,
      isNotSanctioned: countryCode ? !this.isCountrySanctioned(countryCode) : false,
      // Hash of verification data (for commitment)
      verificationHash: this.hashVerificationData({
        dateOfBirth: extractedData?.dateOfBirth,
        nationality: countryCode,
        verifiedAt: new Date().toISOString()
      })
    };
  }

  /**
   * Hash verification data for commitment
   */
  hashVerificationData(data) {
    return crypto
      .createHash('sha256')
      .update(JSON.stringify(data))
      .digest('hex');
  }
}

// Export singleton instance
module.exports = new SynapseService();
