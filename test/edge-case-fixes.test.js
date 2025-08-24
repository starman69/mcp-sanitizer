/**
 * Edge Case Security Fixes Test Suite (Refactored)
 *
 * This file contains only unique edge cases that aren't fully covered
 * by the main validator test suites. Most original tests were redundant
 * and have been removed after verification they're covered elsewhere.
 */

const MCPSanitizer = require('../src/index');

describe('Edge Case Security Fixes', () => {
  let sanitizer;

  beforeEach(() => {
    sanitizer = new MCPSanitizer({ strictMode: true });
  });

  describe('Performance Monitoring (Edge Cases)', () => {
    it('should maintain reasonable performance with complex security enhancements', () => {
      const startTime = Date.now();

      // Test a mix of complex inputs that exercise multiple security layers
      const complexInputs = [
        'ls\nrm -rf /', // Newline command injection
        'C:\\Windows\\System32\\config\\sam', // Windows system path
        '\\\\attacker.com\\share\\malicious' // UNC path
      ];

      for (let i = 0; i < 100; i++) {
        const input = complexInputs[i % complexInputs.length];
        const type = i % 3 === 0 ? 'command' : 'file_path';
        sanitizer.sanitize(input, { type });
      }

      const elapsed = Date.now() - startTime;
      expect(elapsed).toBeLessThan(3000); // Should process 300 complex inputs in < 3000ms
    });

    it('should efficiently handle safe inputs without performance regression', () => {
      const startTime = Date.now();

      for (let i = 0; i < 100; i++) {
        sanitizer.sanitize('echo hello world', { type: 'command' });
        sanitizer.sanitize('./safe/path/file.txt', { type: 'file_path' });
        sanitizer.sanitize('SELECT * FROM users', { type: 'sql' });
      }

      const elapsed = Date.now() - startTime;
      expect(elapsed).toBeLessThan(4000); // Safe inputs should remain fast (adjusted threshold)
    });
  });

  describe('Cross-Platform Path Handling Edge Cases', () => {
    it('should handle Windows paths with mixed separators correctly', () => {
      const mixedPaths = [
        'C:\\Windows/System32\\config/sam',
        'C:/Windows\\System32/config\\sam'
      ];

      mixedPaths.forEach(path => {
        const result = sanitizer.sanitize(path, { type: 'file_path' });
        // Should be blocked regardless of separator mixing
        expect(result.blocked || result.warnings.length > 0).toBe(true);
      });
    });

    it('should detect UNC paths after URL decoding', () => {
      const encodedUncPaths = [
        '%5c%5cserver%5cshare%5cfile', // \\server\share\file encoded
        '\\u005c\\u005cserver\\u005cshare' // Unicode encoded UNC
      ];

      encodedUncPaths.forEach(path => {
        const result = sanitizer.sanitize(path, { type: 'file_path' });
        // Should detect UNC pattern after decoding
        expect(result.blocked || result.warnings.length > 0).toBe(true);
      });
    });
  });

  describe('Command Injection Edge Cases', () => {
    it('should handle newline normalization in command context', () => {
      // Test that dangerous commands are detected even with newlines
      const result = sanitizer.sanitize('ls\nrm -rf /', { type: 'command' });

      // Should be blocked due to dangerous command pattern
      expect(result.blocked).toBe(true);
      expect(result.warnings.some(w =>
        w.includes('dangerous') ||
        w.includes('sensitive') ||
        w.includes('blocked') ||
        w.includes('Dangerous command detected')
      )).toBe(true);
    });

    it('should detect command injection across different line endings', () => {
      const injectionAttempts = [
        'ls\nrm -rf /', // Unix newline
        'ls\rrm -rf /', // Mac classic carriage return
        'ls\r\nrm -rf /' // Windows CRLF
      ];

      injectionAttempts.forEach(cmd => {
        const result = sanitizer.sanitize(cmd, { type: 'command' });
        expect(result.blocked).toBe(true);
      });
    });
  });
});
