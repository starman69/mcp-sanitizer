/**
 * Tests for validation library integrations
 *
 * This test file verifies that the validation libraries
 * (validator, sanitize-filename, path-is-inside) work correctly.
 */

const { describe, it, expect } = require('@jest/globals')
const { URLValidator } = require('../../src/sanitizer/validators/url')
const { FilePathValidator } = require('../../src/sanitizer/validators/file-path')

describe('Validation Library Integration Tests', () => {
  describe('validator.js Integration in URL Validator', () => {
    let urlValidator

    beforeEach(() => {
      urlValidator = new URLValidator()
    })

    it('should validate URLs using validator.js isURL method', () => {
      const validUrls = [
        'https://example.com',
        'https://subdomain.example.com/path',
        'https://example.com:8080/path?query=1',
        'https://example.com/path#anchor'
      ]

      validUrls.forEach(url => {
        expect(urlValidator.isURL(url)).toBe(true)
      })
    })

    it('should reject invalid URLs using validator.js', () => {
      const invalidUrls = [
        'not-a-url',
        'ftp://example.com', // Not in allowed protocols
        '//example.com', // Protocol relative
        'example.com', // Missing protocol
        'javascript:alert(1)', // eslint-disable-line no-script-url -- Testing dangerous protocol
        'data:text/html,<script>alert(1)</script>' // Data URL
      ]

      invalidUrls.forEach(url => {
        expect(urlValidator.isURL(url)).toBe(false)
      })
    })

    it('should detect HTTPS URLs correctly', () => {
      expect(urlValidator.isHTTPS('https://example.com')).toBe(true)
      expect(urlValidator.isHTTPS('http://example.com')).toBe(false)
      expect(urlValidator.isHTTPS('ftp://example.com')).toBe(false)
      expect(urlValidator.isHTTPS('not-a-url')).toBe(false)
    })

    it('should detect IP addresses in hostnames', () => {
      expect(urlValidator.isIP('192.168.1.1')).toBe(true)
      expect(urlValidator.isIP('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toBe(true)
      expect(urlValidator.isIP('example.com')).toBe(false)
      expect(urlValidator.isIP('localhost')).toBe(false)
    })

    it('should validate fully qualified domain names', () => {
      expect(urlValidator.isFQDN('example.com')).toBe(true)
      expect(urlValidator.isFQDN('subdomain.example.com')).toBe(true)
      expect(urlValidator.isFQDN('example')).toBe(false) // No TLD
      expect(urlValidator.isFQDN('192.168.1.1')).toBe(false) // IP address
      expect(urlValidator.isFQDN('example_com')).toBe(false) // Underscore
    })

    it('should integrate validator.js in main validate method', async () => {
      // validator.js check is now non-blocking by default
      const result = await urlValidator.validate('http://example.com')
      expect(result.metadata.validatorCheck).toBe(true) // validator.js accepts http by default
      expect(result.isValid).toBe(true) // But still valid overall
    })

    it('should handle custom validation options', () => {
      const customValidator = new URLValidator({
        allowedProtocols: ['https:', 'wss:']
      })

      expect(customValidator.isURL('https://example.com')).toBe(true)
      expect(customValidator.isURL('wss://example.com')).toBe(true)
      expect(customValidator.isURL('http://example.com')).toBe(false)
    })
  })

  describe('sanitize-filename Integration', () => {
    let fileValidator

    beforeEach(() => {
      fileValidator = new FilePathValidator()
    })

    it('should sanitize dangerous filenames', () => {
      const dangerousFilenames = [
        { input: '../../../etc/passwd', expected: '.._.._.._etc_passwd' }, // sanitize-filename uses _ for /
        { input: 'file\x00name.txt', expected: 'file_name.txt' }, // null byte replaced with _
        { input: 'CON.txt', expected: '_' }, // Windows reserved name becomes _
        { input: 'file:name.txt', expected: 'file_name.txt' }, // : becomes _
        { input: 'file<>name.txt', expected: 'file__name.txt' }, // <> becomes __
        { input: 'file|name.txt', expected: 'file_name.txt' }, // | becomes _
        { input: '.hiddenfile', expected: '.hiddenfile' } // Should preserve
      ]

      dangerousFilenames.forEach(({ input, expected }) => {
        const sanitized = fileValidator.sanitizeFilename(input)
        expect(sanitized).toBe(expected)
      })
    })

    it('should use custom replacement character', () => {
      const filename = 'file<>name.txt'
      const sanitized = fileValidator.sanitizeFilename(filename, { replacement: '-' })
      expect(sanitized).toBe('file--name.txt')
    })

    it('should extract and sanitize filename from path', () => {
      const paths = [
        { input: '/home/user/../../../etc/passwd', expected: 'passwd' }, // basename is just 'passwd'
        { input: 'C:\\Windows\\System32\\cmd.exe', expected: 'C__Windows_System32_cmd.exe' }, // basename includes full path on non-Windows
        { input: '/var/log/app:log.txt', expected: 'app_log.txt' } // colon replaced with _
      ]

      paths.forEach(({ input, expected }) => {
        const sanitized = fileValidator.extractSafeFilename(input)
        expect(sanitized).toBe(expected)
      })
    })

    it('should handle empty and invalid inputs', () => {
      expect(fileValidator.sanitizeFilename('')).toBe('')
      expect(fileValidator.sanitizeFilename('.')).toBe('_') // sanitize-filename replaces single dot
      expect(fileValidator.sanitizeFilename('..')).toBe('_') // sanitize-filename replaces double dot
      expect(fileValidator.sanitizeFilename('...')).toBe('_') // sanitize-filename treats ... as single reserved name
    })
  })

  describe('path-is-inside Integration', () => {
    let fileValidator

    beforeEach(() => {
      fileValidator = new FilePathValidator()
    })

    it('should detect paths inside parent paths', () => {
      const basePath = '/home/user/documents'

      // Paths inside
      expect(fileValidator.isPathInside('/home/user/documents/file.txt', basePath)).toBe(true)
      expect(fileValidator.isPathInside('/home/user/documents/subfolder/file.txt', basePath)).toBe(true)

      // Paths outside
      expect(fileValidator.isPathInside('/home/user/downloads/file.txt', basePath)).toBe(false)
      expect(fileValidator.isPathInside('/etc/passwd', basePath)).toBe(false)
      expect(fileValidator.isPathInside('/home/user/../etc/passwd', basePath)).toBe(false)
    })

    it('should handle relative paths', () => {
      const currentDir = process.cwd()

      // Should resolve relative paths
      expect(fileValidator.isPathInside('./test.txt', currentDir)).toBe(true)
      expect(fileValidator.isPathInside('../mcp-sanitizer/test.txt', currentDir)).toBe(true)
      expect(fileValidator.isPathInside('../../test.txt', currentDir)).toBe(false)
    })

    it('should check if path is safe within allowed paths', () => {
      const allowedPaths = ['/home/user/documents', '/home/user/downloads']

      expect(fileValidator.isPathSafe('/home/user/documents/file.txt', allowedPaths)).toBe(true)
      expect(fileValidator.isPathSafe('/home/user/downloads/file.txt', allowedPaths)).toBe(true)
      expect(fileValidator.isPathSafe('/etc/passwd', allowedPaths)).toBe(false)
      expect(fileValidator.isPathSafe('/home/user/music/file.mp3', allowedPaths)).toBe(false)
    })

    it('should handle edge cases', () => {
      // Same path
      expect(fileValidator.isPathInside('/home/user', '/home/user')).toBe(true) // path-is-inside returns true for same path

      // Invalid paths
      // Empty paths resolve to current directory
      const isEmpty1 = fileValidator.isPathInside('', '/home')
      expect(typeof isEmpty1).toBe('boolean') // Just check it returns boolean
      expect(fileValidator.isPathInside('/home', '')).toBe(false)

      // Non-existent paths (should still work)
      expect(fileValidator.isPathInside('/fake/path/file.txt', '/fake/path')).toBe(true)
    })

    it('should handle Windows-style paths', () => {
      if (process.platform === 'win32') {
        expect(fileValidator.isPathInside('C:\\Users\\user\\file.txt', 'C:\\Users')).toBe(true)
        expect(fileValidator.isPathInside('D:\\file.txt', 'C:\\Users')).toBe(false)
      }
    })
  })

  describe('Integration with existing validators', () => {
    it('should enhance URL validation with validator.js', async () => {
      const urlValidator = new URLValidator({
        allowedProtocols: ['https:'],
        allowCredentialsInUrl: false
      })

      // Should fail both custom and validator.js checks
      const result1 = await urlValidator.validate('http://user:pass@example.com')
      expect(result1.isValid).toBe(false)
      expect(result1.warnings.length).toBeGreaterThanOrEqual(1) // At least one warning

      // Should pass all checks
      const result2 = await urlValidator.validate('https://example.com/path')
      expect(result2.isValid).toBe(true)
      expect(result2.metadata.validatorCheck).toBe(true) // Passes validator.js too
    })

    it('should enhance file path validation with libraries', async () => {
      const fileValidator = new FilePathValidator()

      // Test complete validation flow
      const dangerousPath = '../../../etc/passwd'
      const result = await fileValidator.validate(dangerousPath)
      expect(result.isValid).toBe(false)
      expect(result.warnings.some(w => w.includes('traversal'))).toBe(true) // Check for traversal in warning

      // Safe filename extraction
      const safeName = fileValidator.extractSafeFilename(dangerousPath)
      expect(safeName).toBe('passwd') // Just the basename
    })
  })

  describe('Performance with libraries', () => {
    it('should perform URL validation efficiently', () => {
      const urlValidator = new URLValidator()
      const iterations = 1000
      const testUrl = 'https://example.com/path?query=value#anchor'

      const start = Date.now()
      for (let i = 0; i < iterations; i++) {
        urlValidator.isURL(testUrl)
      }
      const duration = Date.now() - start

      const avgTime = duration / iterations
      expect(avgTime).toBeLessThan(0.5) // Less than 0.5ms per operation
    })

    it('should perform filename sanitization efficiently', () => {
      const fileValidator = new FilePathValidator()
      const iterations = 1000
      const testFilename = '../../../etc/passwd<>|:*?.txt'

      const start = Date.now()
      for (let i = 0; i < iterations; i++) {
        fileValidator.sanitizeFilename(testFilename)
      }
      const duration = Date.now() - start

      const avgTime = duration / iterations
      expect(avgTime).toBeLessThan(0.5) // Less than 0.5ms per operation
    })

    it('should perform path checking efficiently', () => {
      const fileValidator = new FilePathValidator()
      const iterations = 1000
      const testPath = '/home/user/documents/subfolder/file.txt'
      const basePath = '/home/user/documents'

      const start = Date.now()
      for (let i = 0; i < iterations; i++) {
        fileValidator.isPathInside(testPath, basePath)
      }
      const duration = Date.now() - start

      const avgTime = duration / iterations
      expect(avgTime).toBeLessThan(0.5) // Less than 0.5ms per operation
    })
  })
})
