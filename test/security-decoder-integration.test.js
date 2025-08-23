/**
 * Security Decoder Integration Tests
 * 
 * These tests verify that the security decoder integration fixes
 * the dual validation system vulnerability where encoded attacks
 * could bypass legacy validators.
 */

const MCPSanitizer = require('../src/index')
const assert = require('assert')

describe('Security Decoder Integration', () => {
  let sanitizer

  beforeEach(() => {
    sanitizer = new MCPSanitizer('PRODUCTION')
  })

  describe('Bypass Prevention - File Path', () => {
    it('should decode and block URL-encoded directory traversal', () => {
      const encodedPath = '%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd'
      const result = sanitizer.sanitize(encodedPath, { type: 'file_path' })
      
      assert.strictEqual(result.blocked, true)
      assert(result.warnings.some(w => w.includes('blocked pattern') || w.includes('traversal')))
    })

    it('should decode and block Unicode-encoded directory traversal', () => {
      const unicodePath = '\\u002E\\u002E\\u002F\\u002E\\u002E\\u002F\\u002E\\u002E\\u002Fetc\\u002Fpasswd'
      const result = sanitizer.sanitize(unicodePath, { type: 'file_path' })
      
      assert.strictEqual(result.blocked, true)
      assert(result.warnings.some(w => w.includes('blocked pattern') || w.includes('traversal')))
    })

    it('should decode and block double-encoded attacks', () => {
      const doubleEncoded = '%252E%252E%252F%252E%252E%252F%252E%252E%252Fetc%252Fpasswd'
      const result = sanitizer.sanitize(doubleEncoded, { type: 'file_path' })
      
      assert.strictEqual(result.blocked, true)
      assert(result.warnings.some(w => w.includes('blocked pattern') || w.includes('traversal')))
    })

    it('should decode and block mixed encoding attacks', () => {
      const mixedEncoded = '%2E%2E%2F\\u002E\\u002E%2Fetc/passwd'
      const result = sanitizer.sanitize(mixedEncoded, { type: 'file_path' })
      
      assert.strictEqual(result.blocked, true)
      assert(result.warnings.some(w => w.includes('blocked pattern') || w.includes('traversal')))
    })
  })

  describe('Bypass Prevention - URL', () => {
    it('should decode and block URL-encoded dangerous protocols', () => {
      const encodedUrl = 'javascript%3Aalert%281%29'
      const result = sanitizer.sanitize(encodedUrl, { type: 'url' })
      
      assert.strictEqual(result.blocked, true)
    })

    it('should decode and block Unicode-encoded dangerous protocols', () => {
      const unicodeUrl = '\\u006A\\u0061\\u0076\\u0061\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074\\u003A\\u0061\\u006C\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029'
      const result = sanitizer.sanitize(unicodeUrl, { type: 'url' })
      
      assert.strictEqual(result.blocked, true)
    })

    it('should decode and block hex-encoded dangerous URLs', () => {
      const hexUrl = '\\x6A\\x61\\x76\\x61\\x73\\x63\\x72\\x69\\x70\\x74\\x3A\\x61\\x6C\\x65\\x72\\x74\\x28\\x31\\x29'
      const result = sanitizer.sanitize(hexUrl, { type: 'url' })
      
      assert.strictEqual(result.blocked, true)
    })
  })

  describe('Bypass Prevention - Command Injection', () => {
    it('should decode and block URL-encoded command injection', () => {
      const encodedCmd = 'ls%3B%20rm%20-rf%20%2F'
      const result = sanitizer.sanitize(encodedCmd, { type: 'command' })
      
      assert.strictEqual(result.blocked, true)
      assert(result.warnings.some(w => w.includes('dangerous') || w.includes('blocked pattern')))
    })

    it('should decode and block Unicode-encoded command injection', () => {
      const unicodeCmd = 'ls\\u003B\\u0020rm\\u0020-rf\\u0020\\u002F'
      const result = sanitizer.sanitize(unicodeCmd, { type: 'command' })
      
      assert.strictEqual(result.blocked, true)
      assert(result.warnings.some(w => w.includes('dangerous') || w.includes('blocked pattern')))
    })

    it('should decode and block null-byte command injection', () => {
      const nullByteCmd = 'cat file.txt\\x00; rm -rf /'
      const result = sanitizer.sanitize(nullByteCmd, { type: 'command' })
      
      assert.strictEqual(result.blocked, true)
    })
  })

  describe('Bypass Prevention - SQL Injection', () => {
    it('should decode and block URL-encoded SQL injection', () => {
      const encodedSql = 'SELECT%20%2A%20FROM%20users%3B%20DROP%20TABLE%20users%3B'
      const result = sanitizer.sanitize(encodedSql, { type: 'sql' })
      
      assert.strictEqual(result.blocked, true)
    })

    it('should decode and block Unicode-encoded SQL injection', () => {
      const unicodeSql = 'SELECT\\u0020\\u002A\\u0020FROM\\u0020users\\u003B\\u0020DROP\\u0020TABLE\\u0020users\\u003B'
      const result = sanitizer.sanitize(unicodeSql, { type: 'sql' })
      
      assert.strictEqual(result.blocked, true)
    })

    it('should decode and block HTML entity-encoded SQL injection', () => {
      const htmlSql = 'SELECT&#32;&#42;&#32;FROM&#32;users&#59;&#32;DROP&#32;TABLE&#32;users&#59;'
      const result = sanitizer.sanitize(htmlSql, { type: 'sql' })
      
      assert.strictEqual(result.blocked, true)
    })
  })

  describe('Security Decoder Performance', () => {
    it('should handle safe inputs efficiently', () => {
      const safeInputs = [
        'normal-file.txt',
        'https://api.example.com/data',
        'grep pattern file.log',
        'SELECT * FROM users WHERE id = 1'
      ]

      const types = ['file_path', 'url', 'command', 'sql']

      safeInputs.forEach((input, index) => {
        const startTime = Date.now()
        const result = sanitizer.sanitize(input, { type: types[index] })
        const endTime = Date.now()

        assert.strictEqual(result.blocked, false)
        assert(endTime - startTime < 100, 'Processing should be fast for safe inputs')
      })
    })

    it('should not exceed performance threshold for encoded inputs', () => {
      const encodedInputs = [
        '%2E%2E%2Fetc%2Fpasswd',
        'javascript%3Aalert%281%29',
        'ls%3B%20rm%20-rf%20%2F',
        'SELECT%20%2A%20FROM%20users%3B%20DROP%20TABLE%20users%3B'
      ]

      const types = ['file_path', 'url', 'command', 'sql']

      encodedInputs.forEach((input, index) => {
        const startTime = Date.now()
        const result = sanitizer.sanitize(input, { type: types[index] })
        const endTime = Date.now()

        // Should block the input
        assert.strictEqual(result.blocked, true)
        // Should complete within reasonable time (allowing for decoding overhead)
        assert(endTime - startTime < 200, 'Processing should complete within reasonable time even with decoding')
      })
    })
  })

  describe('Logging and Monitoring', () => {
    let originalConsoleWarn
    let warnings

    beforeEach(() => {
      warnings = []
      originalConsoleWarn = console.warn
      console.warn = (message) => warnings.push(message)
    })

    afterEach(() => {
      console.warn = originalConsoleWarn
    })

    it('should log bypass attempts', () => {
      const encodedPath = '%2E%2E%2Fetc%2Fpasswd'
      sanitizer.sanitize(encodedPath, { type: 'file_path' })

      assert(warnings.some(w => w.includes('Potential bypass attempt detected')))
      assert(warnings.some(w => w.includes('url-decode')))
    })

    it('should warn when legacy methods are used', () => {
      // Force use of legacy method by calling it directly (for testing)
      try {
        sanitizer._legacySanitizeFilePath('../etc/passwd')
      } catch (e) {
        // Expected to fail, we just want to check the warning
      }

      assert(warnings.some(w => w.includes('SECURITY WARNING: Using deprecated legacy')))
    })
  })

  describe('Edge Cases', () => {
    it('should handle null and undefined inputs', () => {
      const nullResult = sanitizer.sanitize(null, { type: 'file_path' })
      const undefinedResult = sanitizer.sanitize(undefined, { type: 'url' })

      assert.strictEqual(nullResult.blocked, false)
      assert.strictEqual(nullResult.sanitized, null)
      assert.strictEqual(undefinedResult.blocked, false)
      assert.strictEqual(undefinedResult.sanitized, undefined)
    })

    it('should handle non-string inputs appropriately', () => {
      const numberResult = sanitizer.sanitize(12345, { type: 'command' })
      const objectResult = sanitizer.sanitize({ key: 'value' }, { type: 'sql' })

      assert.strictEqual(numberResult.blocked, false)
      assert.strictEqual(numberResult.sanitized, 12345)
      assert.strictEqual(objectResult.blocked, false)
      assert.deepStrictEqual(objectResult.sanitized, { key: 'value' })
    })

    it('should handle extremely nested encoding attempts', () => {
      // Triple-encoded directory traversal
      const tripleEncoded = '%25252E%25252E%25252F%25252E%25252E%25252F%25252E%25252E%25252Fetc%25252Fpasswd'
      const result = sanitizer.sanitize(tripleEncoded, { type: 'file_path' })

      assert.strictEqual(result.blocked, true)
    })
  })
})