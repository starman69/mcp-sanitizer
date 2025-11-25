/**
 * Pattern Encoder Utility
 *
 * This module provides encoding/decoding functionality for security patterns
 * to prevent WAF false positives during package distribution while maintaining
 * full security detection capabilities at runtime.
 */

/**
 * Decode a Base64-encoded regex pattern string
 * @param {string} encoded - Base64 encoded pattern
 * @param {string} flags - Regex flags (e.g., 'gi', 'i')
 * @returns {RegExp} Decoded regex pattern
 */
function decodePattern (encoded, flags = 'gi') {
  try {
    const decoded = Buffer.from(encoded, 'base64').toString('utf-8');
    return new RegExp(decoded, flags);
  } catch (error) {
    // Return pattern that matches nothing on error
    return /.^/;
  }
}

/**
 * Decode multiple patterns from an array of encoded strings
 * @param {Array<Object>} patterns - Array of {pattern: string, flags: string}
 * @returns {Array<RegExp>} Array of decoded regex patterns
 */
function decodePatterns (patterns) {
  return patterns.map(p => decodePattern(p.pattern, p.flags));
}

/**
 * Encode a regex pattern to Base64 (for build-time use only)
 * @param {RegExp|string} pattern - Regex pattern to encode
 * @returns {string} Base64 encoded pattern
 */
function encodePattern (pattern) {
  const patternStr = pattern instanceof RegExp ? pattern.source : pattern;
  return Buffer.from(patternStr).toString('base64');
}

module.exports = {
  decodePattern,
  decodePatterns,
  encodePattern
};
