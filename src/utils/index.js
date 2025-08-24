/**
 * Utility modules index file for MCP Sanitizer
 *
 * This file exports all utility modules for easy importing.
 */

const stringUtils = require('./string-utils')
const objectUtils = require('./object-utils')
const validationUtils = require('./validation-utils')
const securityEnhancements = require('./security-enhancements')
const securityDecoder = require('./security-decoder')
// CVE-TBD-001 FIX: Import unified parser
const unifiedParser = require('./unified-parser')
// DoS protection removed - handled at infrastructure layer

module.exports = {
  stringUtils,
  objectUtils,
  validationUtils,
  securityEnhancements,
  securityDecoder,
  unifiedParser,

  // Re-export common functions for convenience
  htmlEncode: stringUtils.htmlEncode,
  validateStringLength: stringUtils.validateStringLength,
  validateAgainstBlockedPatterns: stringUtils.validateAgainstBlockedPatterns,
  enhancedStringValidation: stringUtils.enhancedStringValidation,

  isDangerousKey: objectUtils.isDangerousKey,
  validateObjectKey: objectUtils.validateObjectKey,
  validateObjectDepth: objectUtils.validateObjectDepth,

  validateNonEmptyString: validationUtils.validateNonEmptyString,
  validateFilePath: validationUtils.validateFilePath,
  validateURL: validationUtils.validateURL,
  validateCommand: validationUtils.validateCommand,

  // Security enhancement functions
  detectDirectionalOverrides: securityEnhancements.detectDirectionalOverrides,
  detectNullBytes: securityEnhancements.detectNullBytes,
  detectMultipleUrlEncoding: securityEnhancements.detectMultipleUrlEncoding,
  detectPostgresDollarQuotes: securityEnhancements.detectPostgresDollarQuotes,
  detectCyrillicHomographs: securityEnhancements.detectCyrillicHomographs,
  handleEmptyStrings: securityEnhancements.handleEmptyStrings,
  // Timing attack prevention removed - not applicable for sanitization
  comprehensiveSecurityAnalysis: securityEnhancements.comprehensiveSecurityAnalysis,

  // Security decoder functions
  enhancedSecurityDecode: securityDecoder.enhancedSecurityDecode,
  securityDecode: securityDecoder.securityDecode,
  
  // CVE-TBD-001 FIX: Unified parser functions
  parseUnified: unifiedParser.parseUnified,
  extractNormalized: unifiedParser.extractNormalized,
  isNormalizedString: unifiedParser.isNormalizedString,
  wrapValidator: unifiedParser.wrapValidator,
  // DoS protection removed - infrastructure concern
}
