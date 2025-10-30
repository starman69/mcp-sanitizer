/**
 * Comprehensive Security Test Suite
 *
 * This test suite validates protection against all known attack vectors
 * discovered during security audits. Originally created to address v1.1.0
 * security gaps, it now serves as the primary security regression test suite.
 *
 * Test Categories:
 * 1. Unicode Normalization & Homograph Attacks
 * 2. Null Bytes & Control Characters
 * 3. Advanced Encoding Bypasses
 * 4. Case-Sensitive Pattern Bypasses
 * 5. Database-Specific SQL Injection
 * 6. Edge Cases & Combined Attacks
 *
 * All tests in this file MUST pass for production readiness.
 */

const MCPSanitizer = require('../src/index');

describe('Comprehensive Security Test Suite', () => {
  let strictSanitizer;
  // moderateSanitizer removed - only using strict

  beforeEach(() => {
    strictSanitizer = new MCPSanitizer({ strictMode: true });
    // Only strict sanitizer needed
  });

  describe('1. Unicode Normalization & Homograph Attacks', () => {
    describe('Cyrillic Homographs', () => {
      it('should block Cyrillic "с" (U+0441) that looks like Latin "c"', () => {
        const payload = 'сat /etc/passwd'; // 'с' is Cyrillic
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
        expect(result.warnings).toEqual(expect.arrayContaining([
          expect.stringMatching(/homograph|unicode|cyrillic/i)
        ]));
      });

      it('should block mixed Cyrillic homographs', () => {
        const payload = 'саt /etc/passwd'; // 'с' and 'а' are Cyrillic
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });

      it('should block Cyrillic "о" (U+043E) in SQL context', () => {
        const payload = "SELECT * FROM users WHERE name = 'admin' оr 1=1"; // 'о' is Cyrillic
        const result = strictSanitizer.sanitize(payload, { type: 'sql' });
        expect(result.blocked).toBe(true);
      });
    });

    describe('Unicode Combining Characters', () => {
      it('should normalize and block combining diacritics', () => {
        const payload = 'c̀át̂ /etc/passwd'; // Combining grave and circumflex
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });

      it('should handle multiple combining characters', () => {
        const payload = 'ċȧṫ /etc/passwd'; // Various combining dots
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });
    });

    describe('Zero-Width and Invisible Characters', () => {
      it('should strip zero-width space (U+200B)', () => {
        const payload = 'ca​t /etc/pas​swd'; // Contains U+200B
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
        // After stripping, should detect as "cat /etc/passwd"
      });

      it('should strip zero-width joiner (U+200D)', () => {
        const payload = 'ca‍t /etc/passwd'; // Contains U+200D
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });

      it('should strip zero-width non-joiner (U+200C)', () => {
        const payload = 'ca‌t /etc/passwd'; // Contains U+200C
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });
    });

    describe('Directional Override Characters', () => {
      it('should detect right-to-left override (U+202E)', () => {
        const payload = 'cat ‮/dwssap/cte/‬'; // RTL override
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });

      it('should detect left-to-right override (U+202D)', () => {
        const payload = 'echo ‭secret‬ data'; // LTR override
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });
    });

    describe('Mathematical and Styled Unicode', () => {
      it('should normalize mathematical alphanumeric symbols', () => {
        const payload = '𝒸𝒶𝓉 /etc/passwd'; // Mathematical script
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });

      it('should normalize bold mathematical symbols', () => {
        const payload = '𝐜𝐚𝐭 /etc/passwd'; // Mathematical bold
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });
    });
  });

  describe('2. Null Byte & Control Character Injection', () => {
    describe('Null Byte Variations', () => {
      it('should block literal null byte (\\x00)', () => {
        const payload = 'cat /etc/passwd\x00.txt';
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
        expect(result.warnings).toEqual(expect.arrayContaining([
          expect.stringMatching(/null byte|control character/i)
        ]));
      });

      it('should block URL-encoded null byte (%00)', () => {
        const payload = 'cat /etc/passwd%00.txt';
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });

      it('should block Unicode-encoded null (\\u0000)', () => {
        const payload = 'cat /etc/passwd\\u0000.txt';
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });
    });

    describe('Control Characters', () => {
      it('should strip and detect SOH character (\\x01)', () => {
        const payload = 'cat\x01/etc/passwd';
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });

      it('should handle bell character (\\x07)', () => {
        const payload = 'cat\x07/etc/passwd';
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });

      it('should handle form feed (\\x0C)', () => {
        const payload = 'cat\x0C/etc/passwd';
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });

      it('should properly handle newlines to prevent command concatenation', () => {
        const payload = 'ls\nrm -rf /';
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
        // Should NOT become "lsrm -rf /" after processing
        if (result.sanitized) {
          expect(result.sanitized).not.toMatch(/lsrm/);
        }
      });
    });
  });

  describe('3. Advanced Encoding Bypasses', () => {
    describe('Hex Encoding', () => {
      it('should decode and block hex-encoded characters (\\xHH)', () => {
        const payload = 'c\\x61t /etc/passwd'; // \\x61 = 'a'
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });

      it('should handle multiple hex encodings', () => {
        const payload = '\\x63\\x61\\x74 /etc/passwd'; // 'cat' in hex
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });
    });

    describe('Octal Encoding', () => {
      it('should decode and block octal-encoded characters', () => {
        const payload = '\\143\\141\\164 /etc/passwd'; // 'cat' in octal
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });

      it('should handle mixed octal and normal text', () => {
        const payload = 'c\\141t /etc/passwd'; // 'a' in octal
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });
    });

    describe('HTML Entity Encoding', () => {
      it('should decode numeric HTML entities', () => {
        const payload = '&#99;&#97;&#116; /etc/passwd'; // 'cat' as HTML entities
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });

      it('should decode hex HTML entities', () => {
        const payload = '&#x63;&#x61;&#x74; /etc/passwd'; // 'cat' as hex HTML entities
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });
    });

    describe('Multi-Layer Encoding', () => {
      it('should handle double URL encoding', () => {
        const payload = '%25%36%33%25%36%31%25%37%34'; // Double-encoded 'cat'
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        // After decoding should reveal dangerous pattern
        expect(result.warnings.length).toBeGreaterThan(0);
      });

      it('should handle mixed Unicode and URL encoding', () => {
        const payload = '%5Cu0063%5Cu0061%5Cu0074 /etc/passwd'; // Mixed encoding
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });
    });
  });

  describe('4. Case-Sensitive Pattern Bypasses', () => {
    describe('Command Injection Case Variations', () => {
      it('should block uppercase command variations', () => {
        const payload = 'CAT /etc/passwd';
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });

      it('should block mixed case commands', () => {
        const payload = 'CaT /etc/passwd';
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });

      it('should block case variations in chained commands', () => {
        const payload = 'ls; RM -rf /';
        const result = strictSanitizer.sanitize(payload, { type: 'command' });
        expect(result.blocked).toBe(true);
      });
    });

    describe('SQL Injection Case Variations', () => {
      it('should block uppercase SQL keywords', () => {
        const payload = "'; DROP TABLE users;--";
        const result = strictSanitizer.sanitize(payload, { type: 'sql' });
        expect(result.blocked).toBe(true);
      });

      it('should block mixed case SQL injection', () => {
        const payload = "' Or 1=1--";
        const result = strictSanitizer.sanitize(payload, { type: 'sql' });
        expect(result.blocked).toBe(true);
      });

      it('should detect UnIoN SeLeCt regardless of case', () => {
        const payload = "' UnIoN SeLeCt * FROM passwords--";
        const result = strictSanitizer.sanitize(payload, { type: 'sql' });
        expect(result.blocked).toBe(true);
      });
    });

    describe('Path Traversal Case Variations', () => {
      it('should block Windows path with uppercase drive letter', () => {
        const payload = 'C:\\Windows\\System32\\config\\sam';
        const result = strictSanitizer.sanitize(payload, { type: 'file_path' });
        expect(result.blocked).toBe(true);
      });

      it('should handle mixed case in sensitive paths', () => {
        const payload = '/Etc/Passwd';
        const result = strictSanitizer.sanitize(payload, { type: 'file_path' });
        expect(result.blocked).toBe(true);
      });
    });
  });

  describe('5. Database-Specific SQL Injection', () => {
    describe('PostgreSQL Specific', () => {
      it('should block PostgreSQL dollar quoting', () => {
        const payload = 'SELECT $$; DROP TABLE users; --$$';
        const result = strictSanitizer.sanitize(payload, { type: 'sql' });
        expect(result.blocked).toBe(true);
        expect(result.warnings).toEqual(expect.arrayContaining([
          expect.stringMatching(/postgresql|dollar.*quot/i)
        ]));
      });

      it('should block tagged dollar quotes', () => {
        const payload = 'SELECT $tag$; DROP TABLE users; --$tag$';
        const result = strictSanitizer.sanitize(payload, { type: 'sql' });
        expect(result.blocked).toBe(true);
      });

      it('should block PostgreSQL E-strings', () => {
        const payload = "SELECT E'\\'; DROP TABLE users; --'";
        const result = strictSanitizer.sanitize(payload, { type: 'sql' });
        expect(result.blocked).toBe(true);
      });
    });

    describe('MySQL Specific', () => {
      it('should block MySQL backtick identifiers with injection', () => {
        const payload = 'SELECT * FROM `users`; DROP TABLE `accounts`';
        const result = strictSanitizer.sanitize(payload, { type: 'sql' });
        expect(result.blocked).toBe(true);
      });

      it('should detect MySQL comment syntax', () => {
        const payload = 'SELECT * FROM users WHERE id = 1 /*! OR 1=1 */';
        const result = strictSanitizer.sanitize(payload, { type: 'sql' });
        expect(result.blocked).toBe(true);
      });
    });

    describe('MSSQL Specific', () => {
      it('should block MSSQL Unicode strings', () => {
        const payload = "SELECT N'; DROP TABLE users; --'";
        const result = strictSanitizer.sanitize(payload, { type: 'sql' });
        expect(result.blocked).toBe(true);
      });

      it('should block MSSQL bracket identifiers', () => {
        const payload = 'SELECT * FROM [users]; DROP TABLE [accounts]';
        const result = strictSanitizer.sanitize(payload, { type: 'sql' });
        expect(result.blocked).toBe(true);
      });

      it('should detect xp_cmdshell attempts', () => {
        const payload = "'; EXEC xp_cmdshell('dir'); --";
        const result = strictSanitizer.sanitize(payload, { type: 'sql' });
        expect(result.blocked).toBe(true);
      });
    });

    describe('Oracle Specific', () => {
      it('should block Oracle alternative quoting', () => {
        const payload = "SELECT q'['; DROP TABLE users; --]'";
        const result = strictSanitizer.sanitize(payload, { type: 'sql' });
        expect(result.blocked).toBe(true);
      });

      it('should detect Oracle CHR function abuse', () => {
        const payload = 'SELECT CHR(39)||CHR(59)||CHR(32)||CHR(68)||CHR(82)||CHR(79)||CHR(80)';
        const result = strictSanitizer.sanitize(payload, { type: 'sql' });
        expect(result.blocked).toBe(true);
      });
    });
  });

  describe('Edge Cases and Combined Attacks', () => {
    it('should handle empty strings safely', () => {
      const result = strictSanitizer.sanitize('', { type: 'command' });
      expect(result.blocked).toBe(false);
      expect(result.sanitized).toBe('');
    });

    it('should handle very long inputs without performance degradation', () => {
      const longInput = 'a'.repeat(10000) + 'cat /etc/passwd';
      const startTime = Date.now();
      const result = strictSanitizer.sanitize(longInput, { type: 'command' });
      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(100); // Should process in under 100ms
      expect(result.blocked).toBe(true);
    });

    it('should detect attacks combining multiple techniques', () => {
      // Combines: Unicode homograph + case variation + encoding
      const payload = 'Сat\\x20/etc/passwd'; // Cyrillic C + hex space
      const result = strictSanitizer.sanitize(payload, { type: 'command' });
      expect(result.blocked).toBe(true);
    });

    it('should handle separator abuse in commands', () => {
      const payload = 'cat</etc/passwd';
      const result = strictSanitizer.sanitize(payload, { type: 'command' });
      expect(result.blocked).toBe(true);
    });

    it('should detect comment-based SQL bypass', () => {
      const payload = "admin'/**/OR/**/1=1--";
      const result = strictSanitizer.sanitize(payload, { type: 'sql' });
      expect(result.blocked).toBe(true);
    });
  });
});

// Export test utilities for reuse
module.exports = {
  getUnicodeTestVectors () {
    return [
      { input: 'сat /etc/passwd', description: 'Cyrillic homograph' },
      { input: 'c̀át̂ /etc/passwd', description: 'Combining diacritics' },
      { input: 'ca​t /etc/passwd', description: 'Zero-width space' },
      { input: '𝒸𝒶𝓉 /etc/passwd', description: 'Mathematical script' },
      { input: 'cat‮/dwssap/cte/‬', description: 'RTL override' }
    ];
  },

  getEncodingTestVectors () {
    return [
      { input: 'c\\x61t /etc/passwd', description: 'Hex encoding' },
      { input: '\\143\\141\\164 /etc/passwd', description: 'Octal encoding' },
      { input: '&#99;&#97;&#116; /etc/passwd', description: 'HTML entities' },
      { input: '%63%61%74 /etc/passwd', description: 'URL encoding' }
    ];
  },

  getSQLTestVectors () {
    return [
      { input: 'SELECT $$; DROP TABLE users; --$$', description: 'PostgreSQL dollar quote' },
      { input: "SELECT N'; DROP TABLE users; --'", description: 'MSSQL Unicode' },
      { input: "SELECT q'['; DROP TABLE users; --]'", description: 'Oracle alt quote' },
      { input: 'SELECT `users`; DROP TABLE `accounts`', description: 'MySQL backticks' }
    ];
  }
};
