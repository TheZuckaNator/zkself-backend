const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

/**
 * ZK Proof Service
 * Handles generation and verification of zero-knowledge proofs
 * 
 * In production, this would use actual Circom circuits and snarkjs
 * For now, we simulate the proof generation process
 */
class ZkProofService {
  constructor() {
    this.circuitsPath = path.join(__dirname, '../circuits');
    this.proofTypes = {
      'age_over_18': {
        name: 'AgeOver18',
        description: 'Proves user is 18 or older',
        circuitFile: 'age_check.circom'
      },
      'age_over_21': {
        name: 'AgeOver21', 
        description: 'Proves user is 21 or older',
        circuitFile: 'age_check.circom'
      },
      'not_sanctioned': {
        name: 'NotSanctioned',
        description: 'Proves user is not from a sanctioned country',
        circuitFile: 'country_check.circom'
      },
      'is_human': {
        name: 'IsHuman',
        description: 'Proves user passed liveness verification',
        circuitFile: 'humanity_check.circom'
      },
      'unique_person': {
        name: 'UniquePerson',
        description: 'Proves unique identity without revealing who',
        circuitFile: 'uniqueness_check.circom'
      },
      'country_allowed': {
        name: 'CountryAllowed',
        description: 'Proves user is from an allowed country',
        circuitFile: 'country_check.circom'
      }
    };
  }

  /**
   * Generate a ZK proof
   */
  async generateProof(proofType, userData, options = {}) {
    const startTime = Date.now();
    
    const proofConfig = this.proofTypes[proofType];
    if (!proofConfig) {
      throw new Error(`Unknown proof type: ${proofType}`);
    }

    // Generate identity commitment (Poseidon hash in real implementation)
    const identityCommitment = this.generateIdentityCommitment(userData);
    
    // Generate nullifier
    const externalNullifier = options.externalNullifier || this.generateExternalNullifier(proofType);
    const nullifierHash = this.generateNullifierHash(identityCommitment, externalNullifier);

    // Prepare inputs for circuit
    const circuitInputs = this.prepareCircuitInputs(proofType, userData, {
      identityCommitment,
      externalNullifier,
      nullifierHash
    });

    // Generate proof (simulated - in production use snarkjs)
    const proof = await this.computeProof(proofType, circuitInputs);
    
    const generationTime = Date.now() - startTime;

    return {
      zkProof: proof.proof,
      publicSignals: proof.publicSignals,
      nullifierHash,
      externalNullifier,
      metadata: {
        generationTime,
        circuitName: proofConfig.name,
        witnessHash: this.hashWitness(circuitInputs)
      }
    };
  }

  /**
   * Verify a ZK proof
   */
  async verifyProof(proofType, zkProof, publicSignals) {
    const proofConfig = this.proofTypes[proofType];
    if (!proofConfig) {
      throw new Error(`Unknown proof type: ${proofType}`);
    }

    try {
      // In production, use snarkjs.groth16.verify with verification key
      // For now, simulate verification
      const isValid = this.simulateVerification(zkProof, publicSignals);
      
      return {
        valid: isValid,
        proofType,
        publicSignals
      };
    } catch (error) {
      console.error('Proof verification error:', error);
      return {
        valid: false,
        error: error.message
      };
    }
  }

  /**
   * Generate identity commitment using Poseidon hash
   * In production, use circomlibjs poseidon
   */
  generateIdentityCommitment(userData) {
    const data = JSON.stringify({
      verificationHash: userData.verificationHash,
      timestamp: userData.verifiedAt || Date.now()
    });
    
    // Simulate Poseidon hash with SHA256 for now
    return '0x' + crypto
      .createHash('sha256')
      .update(data)
      .digest('hex');
  }

  /**
   * Generate external nullifier for a specific context
   */
  generateExternalNullifier(context) {
    return '0x' + crypto
      .createHash('sha256')
      .update(context + Date.now().toString())
      .digest('hex')
      .slice(0, 64);
  }

  /**
   * Generate nullifier hash
   */
  generateNullifierHash(identityCommitment, externalNullifier) {
    return '0x' + crypto
      .createHash('sha256')
      .update(identityCommitment + externalNullifier)
      .digest('hex');
  }

  /**
   * Prepare circuit inputs based on proof type
   */
  prepareCircuitInputs(proofType, userData, commitments) {
    const baseInputs = {
      identityCommitment: commitments.identityCommitment,
      externalNullifier: commitments.externalNullifier
    };

    switch (proofType) {
      case 'age_over_18':
        return {
          ...baseInputs,
          ageThreshold: 18,
          currentAge: userData.age || 0,
          dateOfBirthHash: this.hashValue(userData.dateOfBirth)
        };
      
      case 'age_over_21':
        return {
          ...baseInputs,
          ageThreshold: 21,
          currentAge: userData.age || 0,
          dateOfBirthHash: this.hashValue(userData.dateOfBirth)
        };
      
      case 'not_sanctioned':
        return {
          ...baseInputs,
          countryCode: this.countryToNumber(userData.countryCode),
          sanctionedCountries: this.getSanctionedCountryCodes()
        };
      
      case 'is_human':
        return {
          ...baseInputs,
          livenessScore: userData.livenessScore || 0,
          livenessThreshold: 70,
          verificationHash: userData.verificationHash
        };
      
      case 'unique_person':
        return {
          ...baseInputs,
          identityHash: userData.verificationHash,
          registrationTimestamp: Date.now()
        };
      
      case 'country_allowed':
        return {
          ...baseInputs,
          countryCode: this.countryToNumber(userData.countryCode),
          allowedCountries: userData.allowedCountries?.map(c => this.countryToNumber(c)) || []
        };
      
      default:
        return baseInputs;
    }
  }

  /**
   * Compute the actual proof (simulated)
   * In production, use snarkjs.groth16.fullProve
   */
  async computeProof(proofType, inputs) {
    // Simulate proof computation delay
    await new Promise(resolve => setTimeout(resolve, 100));

    // Generate deterministic but unique proof based on inputs
    const inputHash = this.hashValue(JSON.stringify(inputs));
    
    // Simulated Groth16 proof structure
    const proof = {
      pi_a: [
        this.generateFieldElement(inputHash, 'a1'),
        this.generateFieldElement(inputHash, 'a2'),
        '1'
      ],
      pi_b: [
        [
          this.generateFieldElement(inputHash, 'b11'),
          this.generateFieldElement(inputHash, 'b12')
        ],
        [
          this.generateFieldElement(inputHash, 'b21'),
          this.generateFieldElement(inputHash, 'b22')
        ],
        ['1', '0']
      ],
      pi_c: [
        this.generateFieldElement(inputHash, 'c1'),
        this.generateFieldElement(inputHash, 'c2'),
        '1'
      ],
      protocol: 'groth16',
      curve: 'bn128'
    };

    // Public signals that will be verified
    const publicSignals = [
      inputs.externalNullifier,
      inputs.identityCommitment,
      this.generatePublicOutput(proofType, inputs)
    ];

    return { proof, publicSignals };
  }

  /**
   * Generate a field element (simulated)
   */
  generateFieldElement(seed, salt) {
    const hash = crypto
      .createHash('sha256')
      .update(seed + salt)
      .digest('hex');
    
    // Return as decimal string (like real snarkjs output)
    return BigInt('0x' + hash.slice(0, 62)).toString();
  }

  /**
   * Generate public output based on proof type
   */
  generatePublicOutput(proofType, inputs) {
    switch (proofType) {
      case 'age_over_18':
      case 'age_over_21':
        return inputs.currentAge >= inputs.ageThreshold ? '1' : '0';
      case 'not_sanctioned':
        return '1'; // Assuming not sanctioned if we get here
      case 'is_human':
        return inputs.livenessScore >= inputs.livenessThreshold ? '1' : '0';
      case 'unique_person':
        return inputs.identityHash;
      case 'country_allowed':
        return '1';
      default:
        return '1';
    }
  }

  /**
   * Simulate proof verification
   */
  simulateVerification(zkProof, publicSignals) {
    // In production, use snarkjs.groth16.verify
    // For simulation, verify proof structure
    if (!zkProof.pi_a || !zkProof.pi_b || !zkProof.pi_c) {
      return false;
    }
    if (!Array.isArray(publicSignals) || publicSignals.length === 0) {
      return false;
    }
    return true;
  }

  /**
   * Hash a value
   */
  hashValue(value) {
    return '0x' + crypto
      .createHash('sha256')
      .update(String(value))
      .digest('hex');
  }

  /**
   * Hash witness inputs
   */
  hashWitness(inputs) {
    return crypto
      .createHash('sha256')
      .update(JSON.stringify(inputs))
      .digest('hex');
  }

  /**
   * Convert country code to number for circuit
   */
  countryToNumber(countryCode) {
    if (!countryCode) return 0;
    const code = countryCode.toUpperCase();
    return code.charCodeAt(0) * 256 + code.charCodeAt(1);
  }

  /**
   * Get sanctioned country codes as numbers
   */
  getSanctionedCountryCodes() {
    const sanctioned = ['CU', 'IR', 'KP', 'SY', 'RU', 'BY'];
    return sanctioned.map(c => this.countryToNumber(c));
  }

  /**
   * Get available proof types
   */
  getProofTypes() {
    return Object.entries(this.proofTypes).map(([key, value]) => ({
      type: key,
      name: value.name,
      description: value.description
    }));
  }

  /**
   * Check if user can generate a specific proof type
   */
  canGenerateProof(proofType, userData) {
    switch (proofType) {
      case 'age_over_18':
        return userData.isAdult === true;
      case 'age_over_21':
        return userData.isOver21 === true;
      case 'not_sanctioned':
        return userData.isNotSanctioned === true;
      case 'is_human':
        return userData.isHuman === true;
      case 'unique_person':
        return userData.verificationHash != null;
      case 'country_allowed':
        return userData.countryCode != null;
      default:
        return false;
    }
  }
}

// Export singleton
module.exports = new ZkProofService();
