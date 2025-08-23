/**
 * Encoding Bypass Security Tests
 * 
 * Tests for the 3 remaining edge cases and ensures they are blocked
 * after security decoder integration.
 */

const MCPSanitizer = require('../src/index');

describe('Encoding Bypass Security Fixes', () => {
  let sanitizer;

  beforeEach(() => {
    sanitizer = new MCPSanitizer('STRICT');
  });

  describe('Unicode Command Bypass Prevention', () => {
    it('should block Unicode-encoded cat command', () => {
      // This was bypassing: \u0063\u0061\u0074 = "cat"
      const result = sanitizer.sanitize('\u0063\u0061\u0074 /etc/passwd', { type: 'command' });
      expect(result.blocked).toBe(true);
      expect(result.warnings.some(w => w.includes('dangerous') || w.includes('sensitive') || w.includes('passwd'))).toBe(true);
    });

    it('should block hex-encoded commands', () => {
      // \x63\x61\x74 = "cat"
      const result = sanitizer.sanitize('\x63\x61\x74 /etc/passwd', { type: 'command' });
      expect(result.blocked).toBe(true);
    });

    it('should block HTML entity encoded commands', () => {
      // &#99;&#97;&#116; = "cat"
      const result = sanitizer.sanitize('&#99;&#97;&#116; /etc/passwd', { type: 'command' });
      expect(result.blocked).toBe(true);
    });
  });

  describe('Null Byte Command Bypass Prevention', () => {
    it('should block commands with null bytes', () => {
      const result = sanitizer.sanitize('cat /etc/passwd\0.txt', { type: 'command' });
      expect(result.blocked).toBe(true);
      expect(result.warnings.some(w => w.includes('dangerous') || w.includes('sensitive') || w.includes('passwd'))).toBe(true);
    });

    it('should block URL-encoded null bytes', () => {
      const result = sanitizer.sanitize('cat /etc/passwd%00.txt', { type: 'command' });
      expect(result.blocked).toBe(true);
    });

    it('should block hex-encoded null bytes', () => {
      const result = sanitizer.sanitize('cat /etc/passwd\\x00.txt', { type: 'command' });
      expect(result.blocked).toBe(true);
    });
  });

  describe('URL-Encoded Path Traversal Prevention', () => {
    it('should block single URL-encoded traversal', () => {
      // %2e%2e%2f = "../"
      const result = sanitizer.sanitize('%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', { type: 'file_path' });
      expect(result.blocked).toBe(true);
      expect(result.warnings.some(w => w.includes('traversal') || w.includes('system directory') || w.includes('blocked'))).toBe(true);
    });

    it('should block double URL-encoded traversal', () => {
      // %252e%252e%252f = "../" (double encoded)
      const result = sanitizer.sanitize('%252e%252e%252f%252e%252e%252fetc%252fpasswd', { type: 'file_path' });
      expect(result.blocked).toBe(true);
    });

    it('should block mixed encoding traversal', () => {
      // Mix of %2e and \u002e
      const result = sanitizer.sanitize('%2e%2e\u002f..\u002fetc\u002fpasswd', { type: 'file_path' });
      expect(result.blocked).toBe(true);
    });

    it('should block Unicode-encoded path separators', () => {
      // \u002e\u002e\u002f = "../"
      const result = sanitizer.sanitize('\u002e\u002e\u002f\u002e\u002e\u002fetc\u002fpasswd', { type: 'file_path' });
      expect(result.blocked).toBe(true);
    });
  });

  describe('Complex Multi-Layer Encoding', () => {
    it('should block triple-encoded attacks', () => {
      // Triple URL encoding
      const result = sanitizer.sanitize('%25252e%25252e%25252f', { type: 'file_path' });
      expect(result.blocked).toBe(true);
    });

    it('should block mixed Unicode and URL encoding', () => {
      // %5c = \, so %5cu0063 = \u0063 = 'c', full string decodes to 'cat /etc/passwd'
      const result = sanitizer.sanitize('%5cu0063%5cu0061%5cu0074%20%2fetc%2fpasswd', { type: 'command' });
      expect(result.blocked).toBe(true);
    });

    it('should block obfuscated SQL injection', () => {
      const result = sanitizer.sanitize('SELECT%20%2A%20FROM%20users%3B%20DROP', { type: 'sql' });
      expect(result.blocked).toBe(true);
    });
  });

  describe('Legacy Method Deprecation', () => {
    it('should use secure methods instead of legacy ones', () => {
      // Spy on console.warn to detect legacy method warnings
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      // Test file path with encoding
      sanitizer.sanitize('%2e%2e%2f', { type: 'file_path' });
      
      // Should log decoding warning
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('[MCP-Sanitizer]')
      );
      
      warnSpy.mockRestore();
    });
  });

  describe('Performance with Security Decoding', () => {
    it('should process safe inputs efficiently', () => {
      const startTime = Date.now();
      
      for (let i = 0; i < 100; i++) {
        sanitizer.sanitize('normal safe text', { type: 'command' });
      }
      
      const elapsed = Date.now() - startTime;
      expect(elapsed).toBeLessThan(200); // Should process 100 inputs in < 200ms
    });

    it('should handle encoded inputs with acceptable overhead', () => {
      const startTime = Date.now();
      
      for (let i = 0; i < 100; i++) {
        sanitizer.sanitize('%2e%2e%2f%2e%2e%2f', { type: 'file_path' });
      }
      
      const elapsed = Date.now() - startTime;
      expect(elapsed).toBeLessThan(300); // Encoded inputs should still be fast
    });
  });

  describe('Comprehensive Attack Vector Coverage', () => {
    const attackVectors = [
      // Unicode bypasses
      { input: '\u0072\u006d -rf /', type: 'command', name: 'Unicode rm command' },
      { input: '\u002f\u0065\u0074\u0063\u002f\u0070\u0061\u0073\u0073\u0077\u0064', type: 'file_path', name: 'Unicode /etc/passwd' },
      
      // URL encoding bypasses
      { input: '%72%6d%20%2d%72%66%20%2f', type: 'command', name: 'URL-encoded rm command' },
      { input: '%2f%65%74%63%2f%70%61%73%73%77%64', type: 'file_path', name: 'URL-encoded /etc/passwd' },
      
      // Hex encoding bypasses
      { input: '\x72\x6d -rf /', type: 'command', name: 'Hex-encoded rm command' },
      { input: '\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64', type: 'file_path', name: 'Hex-encoded /etc/passwd' },
      
      // Mixed encoding
      { input: '%5cu0072%5cu006d', type: 'command', name: 'Mixed URL+Unicode' },
      { input: '\u002e%2e/\u002e%2e/', type: 'file_path', name: 'Mixed Unicode+URL traversal' },
      
      // Control characters
      { input: 'ls\nrm -rf /', type: 'command', name: 'Newline injection' },
      { input: 'cat\0/etc/passwd', type: 'command', name: 'Null byte injection' },
      { input: 'echo\r\nrm -rf /', type: 'command', name: 'CRLF injection' }
    ];

    attackVectors.forEach(vector => {
      it(`should block ${vector.name}`, () => {
        const result = sanitizer.sanitize(vector.input, { type: vector.type });
        expect(result.blocked).toBe(true, `Failed to block: ${vector.name}`);
      });
    });
  });
});