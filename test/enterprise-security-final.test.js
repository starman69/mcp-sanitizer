/**
 * Enterprise Security Final Test Suite
 *
 * TDD tests for the remaining 8 security issues
 * These tests MUST pass for enterprise-grade inline sanitization
 *
 * Scope: Inline sanitization library (not edge/network level)
 * Focus: Maximum security within performance constraints
 */

const MCPSanitizer = require('../src/index');

describe('Enterprise Security - Final Gap Closure', () => {
  let sanitizer;

  beforeEach(() => {
    sanitizer = new MCPSanitizer({ strictMode: true });
  });

  describe('Issue 1 & 2: Directional Override Detection', () => {
    describe('Right-to-Left Override (U+202E)', () => {
      it('should detect and block RTL override attempts', () => {
        const payload = 'cat ‮/dwssap/cte/‬'; // RTL override
        const result = sanitizer.sanitize(payload, { type: 'command' });

        expect(result.blocked).toBe(true);
        expect(result.warnings).toEqual(expect.arrayContaining([
          expect.stringMatching(/directional|override|rtl|bidi/i)
        ]));
      });

      it('should handle RTL in SQL context', () => {
        const payload = "SELECT * FROM users WHERE name = '‮nimda‬'"; // 'admin' reversed
        const result = sanitizer.sanitize(payload, { type: 'sql' });

        expect(result.blocked).toBe(true);
        expect(result.warnings).toEqual(expect.arrayContaining([
          expect.stringMatching(/directional|override|rtl/i)
        ]));
      });

      it('should detect RTL with legitimate text', () => {
        const payload = 'echo hello ‮dlrow‬ test'; // 'world' reversed
        const result = sanitizer.sanitize(payload, { type: 'command' });

        expect(result.blocked).toBe(true);
      });
    });

    describe('Left-to-Right Override (U+202D)', () => {
      it('should detect and block LTR override attempts', () => {
        const payload = 'echo ‭secret‬ data'; // LTR override
        const result = sanitizer.sanitize(payload, { type: 'command' });

        expect(result.blocked).toBe(true);
        expect(result.warnings).toEqual(expect.arrayContaining([
          expect.stringMatching(/directional|override|ltr|bidi/i)
        ]));
      });

      it('should handle mixed directional characters', () => {
        const payload = 'cat ‭file‬.txt ‮elif‬.log'; // Mixed LTR and RTL
        const result = sanitizer.sanitize(payload, { type: 'command' });

        expect(result.blocked).toBe(true);
      });
    });

    describe('Other Bidirectional Control Characters', () => {
      it('should block Right-to-Left Embedding (U+202B)', () => {
        const payload = 'echo ‫hidden‬ text';
        const result = sanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });

      it('should block Left-to-Right Embedding (U+202A)', () => {
        const payload = 'echo ‪visible‬ text';
        const result = sanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });

      it('should block Pop Directional Formatting (U+202C)', () => {
        const payload = 'echo test‬ data';
        const result = sanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });
    });
  });

  describe('Issue 3: Literal Null Byte with Proper Warning', () => {
    it('should block literal null byte with correct warning message', () => {
      const payload = 'cat /etc/passwd\x00.txt';
      const result = sanitizer.sanitize(payload, { type: 'command' });

      expect(result.blocked).toBe(true);
      expect(result.warnings).toEqual(expect.arrayContaining([
        // eslint-disable-next-line no-control-regex
        expect.stringMatching(/null byte|control character|\x00/i)
      ]));
      expect(result.warnings).not.toEqual(expect.arrayContaining([
        expect.stringMatching(/Access to sensitive files/i)
      ]));
    });

    it('should detect null bytes in middle of string', () => {
      const payload = 'echo te\x00st data';
      const result = sanitizer.sanitize(payload, { type: 'command' });

      expect(result.blocked).toBe(true);
      expect(result.warnings).toEqual(expect.arrayContaining([
        expect.stringMatching(/null byte|control character/i)
      ]));
    });

    it('should handle multiple null bytes', () => {
      const payload = 'cat\x00 /etc/\x00passwd';
      const result = sanitizer.sanitize(payload, { type: 'command' });

      expect(result.blocked).toBe(true);
      expect(result.warnings).toEqual(expect.arrayContaining([
        expect.stringMatching(/null byte|control character/i)
      ]));
    });
  });

  describe('Issue 4: Double URL Encoding', () => {
    it('should decode and detect double URL encoded attacks', () => {
      // %25%36%33%25%36%31%25%37%34 = double encoded 'cat'
      const payload = '%25%36%33%25%36%31%25%37%34%20/etc/passwd';
      const result = sanitizer.sanitize(payload, { type: 'command' });

      expect(result.blocked).toBe(true);
      expect(result.warnings.length).toBeGreaterThan(0);
    });

    it('should handle triple URL encoding', () => {
      // Triple encoded 'rm'
      const payload = '%252572%25256D';
      const result = sanitizer.sanitize(payload, { type: 'command' });

      expect(result.warnings.length).toBeGreaterThan(0);
    });

    it('should detect mixed double encoding', () => {
      // Mix of single and double encoded
      const payload = '%63at %252Fetc%252Fpasswd'; // 'cat /etc/passwd'
      const result = sanitizer.sanitize(payload, { type: 'command' });

      expect(result.blocked).toBe(true);
    });

    it('should handle double encoded SQL injection', () => {
      const payload = '%27%253B%2520DROP%2520TABLE%2520users%253B--'; // '; DROP TABLE users;--
      const result = sanitizer.sanitize(payload, { type: 'sql' });

      expect(result.blocked).toBe(true);
    });
  });

  describe('Issue 5: PostgreSQL Dollar Quoting with Proper Warning', () => {
    it('should block PostgreSQL dollar quoting with correct warning', () => {
      const payload = 'SELECT $$; DROP TABLE users; --$$';
      const result = sanitizer.sanitize(payload, { type: 'sql' });

      expect(result.blocked).toBe(true);
      expect(result.warnings).toEqual(expect.arrayContaining([
        expect.stringMatching(/postgresql|dollar.*quot|database.*specific/i)
      ]));
    });

    it('should detect nested dollar quotes', () => {
      const payload = 'SELECT $outer$ $inner$ malicious $inner$ $outer$';
      const result = sanitizer.sanitize(payload, { type: 'sql' });

      expect(result.blocked).toBe(true);
      expect(result.warnings).toEqual(expect.arrayContaining([
        expect.stringMatching(/postgresql|dollar.*quot/i)
      ]));
    });
  });

  describe('Issue 6: Cyrillic Homograph with Proper Warning', () => {
    it('should block Cyrillic with homograph-specific warning', () => {
      const payload = 'сat /etc/passwd'; // Cyrillic 'с'
      const result = sanitizer.sanitize(payload, { type: 'command' });

      expect(result.blocked).toBe(true);
      expect(result.warnings).toEqual(expect.arrayContaining([
        expect.stringMatching(/homograph|unicode.*normalization|cyrillic|confusable/i)
      ]));
    });

    it('should provide detailed homograph information', () => {
      const payload = 'есhо test'; // Cyrillic 'е' and 'о'
      const result = sanitizer.sanitize(payload, { type: 'command' });

      expect(result.blocked).toBe(true);
      expect(result.warnings.some(w =>
        w.match(/homograph|cyrillic|confusable|lookalike/i)
      )).toBe(true);
    });
  });

  describe('Issue 7: Empty String Handling', () => {
    it('should allow empty strings without blocking', () => {
      const result = sanitizer.sanitize('', { type: 'command' });

      expect(result.blocked).toBe(false);
      expect(result.sanitized).toBe('');
      expect(result.warnings).toEqual([]);
    });

    it('should handle null input gracefully', () => {
      const result = sanitizer.sanitize(null, { type: 'command' });

      expect(result.blocked).toBe(false);
      expect(result.sanitized).toBe(null);
      expect(result.warnings).toEqual([]);
    });

    it('should handle undefined input gracefully', () => {
      const result = sanitizer.sanitize(undefined, { type: 'command' });

      expect(result.blocked).toBe(false);
      expect(result.sanitized).toBe(undefined);
      expect(result.warnings).toEqual([]);
    });

    it('should handle whitespace-only strings appropriately', () => {
      const result = sanitizer.sanitize('   ', { type: 'command' });

      expect(result.blocked).toBe(false);
      expect(result.sanitized).toBe(''); // Trimmed
      expect(result.warnings).toEqual([]);
    });
  });

  describe('Issue 8: Timing Attack Resistance', () => {
    it('should have minimal timing variance (<5%)', () => {
      const safe = 'hello world';
      const malicious = 'cat /etc/passwd';

      const timings = { safe: [], malicious: [] };
      const iterations = 100;

      // Warm up
      for (let i = 0; i < 10; i++) {
        sanitizer.sanitize(safe, { type: 'command' });
        sanitizer.sanitize(malicious, { type: 'command' });
      }

      // Collect timing samples
      for (let i = 0; i < iterations; i++) {
        let start = process.hrtime.bigint();
        sanitizer.sanitize(safe, { type: 'command' });
        timings.safe.push(Number(process.hrtime.bigint() - start));

        start = process.hrtime.bigint();
        sanitizer.sanitize(malicious, { type: 'command' });
        timings.malicious.push(Number(process.hrtime.bigint() - start));
      }

      // Calculate averages
      const avgSafe = timings.safe.reduce((a, b) => a + b, 0) / timings.safe.length;
      const avgMalicious = timings.malicious.reduce((a, b) => a + b, 0) / timings.malicious.length;

      // Calculate variance
      const variance = Math.abs(avgSafe - avgMalicious) / Math.max(avgSafe, avgMalicious);

      // Should be less than 5% variance
      expect(variance).toBeLessThan(0.05);
    });

    it('should maintain timing consistency across different attack types', () => {
      const inputs = [
        'normal text',
        'сat /etc/passwd', // Cyrillic
        '../../etc/passwd', // Path traversal
        "'; DROP TABLE users;--", // SQL injection
        '<script>alert("xss")</script>' // XSS
      ];

      const timings = inputs.map(input => {
        const samples = [];
        for (let i = 0; i < 50; i++) {
          const start = process.hrtime.bigint();
          sanitizer.sanitize(input, { type: 'command' });
          samples.push(Number(process.hrtime.bigint() - start));
        }
        return samples.reduce((a, b) => a + b, 0) / samples.length;
      });

      // All timings should be within 10% of each other
      const maxTime = Math.max(...timings);
      const minTime = Math.min(...timings);
      const variance = (maxTime - minTime) / maxTime;

      expect(variance).toBeLessThan(0.10);
    });
  });

  describe('Enterprise Edge Cases', () => {
    describe('Complex Multi-Vector Attacks', () => {
      it('should handle combined Unicode + encoding + injection', () => {
        // Cyrillic 'c' + URL encoding + SQL injection
        const payload = 'сat%20/etc/passwd%00%27%3B%20DROP%20TABLE%20users%3B--';
        const result = sanitizer.sanitize(payload, { type: 'command' });

        expect(result.blocked).toBe(true);
        expect(result.warnings.length).toBeGreaterThanOrEqual(1); // At least one critical issue detected
        // Security note: We throw immediately on first critical violation for performance
      });

      it('should detect polyglot attacks', () => {
        // eslint-disable-next-line no-script-url
        const payload = 'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>';
        const result = sanitizer.sanitize(payload, { type: 'command' });

        expect(result.blocked).toBe(true);
      });
    });

    describe('Performance Under Attack', () => {
      it('should handle ReDoS attempts efficiently', () => {
        const payload = 'a'.repeat(9999) + 'X'; // Stay within 10000 char limit
        const start = Date.now();
        const result = sanitizer.sanitize(payload, { type: 'command' });
        const duration = Date.now() - start;

        expect(duration).toBeLessThan(100); // Should complete quickly
        expect(result.blocked).toBe(false); // Not malicious, just long
      });

      it('should handle deeply nested encoding efficiently', () => {
        let payload = 'cat';
        // Apply 10 layers of URL encoding
        for (let i = 0; i < 10; i++) {
          payload = encodeURIComponent(payload);
        }

        const start = Date.now();
        // eslint-disable-next-line no-unused-vars
        const result = sanitizer.sanitize(payload, { type: 'command' });
        const duration = Date.now() - start;

        expect(duration).toBeLessThan(50);
      });
    });

    describe('Inline Sanitization Constraints', () => {
      it('should maintain acceptable latency for inline use', () => {
        const inputs = Array(100).fill('test input');
        const start = Date.now();

        inputs.forEach(input => {
          sanitizer.sanitize(input, { type: 'command' });
        });

        const avgTime = (Date.now() - start) / 100;
        expect(avgTime).toBeLessThan(15); // <15ms per request for inline use with enterprise security
      });

      it('should not consume excessive memory', () => {
        const initialMemory = process.memoryUsage().heapUsed;

        // Process many inputs
        for (let i = 0; i < 1000; i++) {
          sanitizer.sanitize(`input ${i}`, { type: 'command' });
        }

        const finalMemory = process.memoryUsage().heapUsed;
        const memoryIncrease = (finalMemory - initialMemory) / 1024 / 1024; // MB

        expect(memoryIncrease).toBeLessThan(50); // Less than 50MB increase
      });
    });
  });
});

module.exports = {
  // Export test utilities for reuse
  getDirectionalTestVectors () {
    return [
      { char: '\u202E', name: 'RTL Override' },
      { char: '\u202D', name: 'LTR Override' },
      { char: '\u202A', name: 'LTR Embedding' },
      { char: '\u202B', name: 'RTL Embedding' },
      { char: '\u202C', name: 'Pop Directional' },
      { char: '\u2066', name: 'LTR Isolate' },
      { char: '\u2067', name: 'RTL Isolate' },
      { char: '\u2068', name: 'First Strong Isolate' },
      { char: '\u2069', name: 'Pop Isolate' }
    ];
  },

  getEnterpriseAttackVectors () {
    return [
      // Add comprehensive enterprise attack vectors
      { vector: 'сat /etc/passwd', type: 'homograph' },
      { vector: 'echo\x00test', type: 'null-byte' },
      { vector: '%25%36%33%25%36%31%25%37%34', type: 'double-encoding' },
      { vector: 'cat ‮/dwssap/cte/‬', type: 'directional' },
      { vector: '$$; DROP TABLE users;$$', type: 'dollar-quote' }
    ];
  }
};
