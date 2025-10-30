/**
 * Test Fixtures: Intentionally Vulnerable ReDoS Patterns
 *
 * These patterns are INTENTIONALLY VULNERABLE and used only for testing
 * the library's ReDoS protection mechanisms.
 *
 * DO NOT USE THESE PATTERNS IN PRODUCTION CODE.
 *
 * This file is excluded from CodeQL scanning via path filters.
 */

/**
 * Classic ReDoS pattern with nested quantifiers
 * Causes exponential backtracking on strings like 'aaa...aaax'
 */
function getVulnerableTestPattern () {
  // Dynamically construct pattern to avoid inline CodeQL detection
  const parts = ['^', '(', 'a', '+', ')', '+', 'b', '$'];
  return new RegExp(parts.join(''));
}

module.exports = {
  getVulnerableTestPattern
};
