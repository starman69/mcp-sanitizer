/**
 * Utility modules index file for MCP Sanitizer
 *
 * This file exports all utility modules for easy importing.
 */

const stringUtils = require('./string-utils')
const objectUtils = require('./object-utils')
const validationUtils = require('./validation-utils')

module.exports = {
  stringUtils,
  objectUtils,
  validationUtils,

  // Re-export common functions for convenience
  htmlEncode: stringUtils.htmlEncode,
  validateStringLength: stringUtils.validateStringLength,
  validateAgainstBlockedPatterns: stringUtils.validateAgainstBlockedPatterns,

  isDangerousKey: objectUtils.isDangerousKey,
  validateObjectKey: objectUtils.validateObjectKey,
  validateObjectDepth: objectUtils.validateObjectDepth,

  validateNonEmptyString: validationUtils.validateNonEmptyString,
  validateFilePath: validationUtils.validateFilePath,
  validateURL: validationUtils.validateURL,
  validateCommand: validationUtils.validateCommand
}
