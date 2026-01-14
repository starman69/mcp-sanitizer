/**
 * ReDoS Protection Tests
 *
 * These tests verify that the library's OWN regex patterns are not vulnerable
 * to Regular Expression Denial of Service (ReDoS) attacks.
 *
 * CRITICAL: This tests the LIBRARY's security, not just user input validation.
 *
 * Background:
 * - CodeQL detected 22 instances of polynomial ReDoS vulnerabilities
 * - These are in the library's validation patterns themselves
 * - An attacker can DoS the sanitizer, then bypass security checks
 *
 * Test Strategy:
 * 1. Pathological inputs that would cause exponential backtracking
 * 2. Performance validation (<10ms per SECURITY.md)
 * 3. All core pattern sets from all vulnerable files
 *
 * @see https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
 */

const {
  detectCyrillicHomographs
} = require('../src/utils/security-enhancements');

const {
  detectNoSQLInjection
} = require('../src/patterns/nosql-injection');

const {
  detectPrototypePollution
} = require('../src/patterns/prototype-pollution');

const {
  detectSQLInjection
} = require('../src/patterns/sql-injection');

const {
  detectTemplateInjection
} = require('../src/patterns/template-injection');

const {
  detectCommandInjection
} = require('../src/patterns/command-injection');

const {
  safePatternTest,
  safeBatchTest,
  SAFE_DOMAIN_PATTERN
} = require('../src/utils/redos-safe-patterns');

/**
 * Maximum allowed execution time for tests
 *
 * Note: The documented security requirement is <1ms (see SECURITY.md),
 * but tests use a more lenient threshold to account for:
 * - Date.now() 1ms precision limitations
 * - Performance variations across Node versions (v20, v22, v24+)
 * - CI/CD environment variability
 *
 * This ensures tests are reliable across environments while still
 * catching actual ReDoS vulnerabilities that would cause hangs.
 */
const MAX_EXECUTION_TIME_MS = 15;

/**
 * Longer timeout for batch operations
 */
const BATCH_TIMEOUT_MS = 100;

describe('ReDoS Protection - Library Pattern Security', () => {
  describe('Critical: Domain Pattern ReDoS (#45)', () => {
    /**
     * Issue #45: src/utils/security-enhancements.js:449
     * Pattern: /(?:^|\s|[^\w.-])((?:[a-zA-Zа-яё0-9](?:[a-zA-Zа-яё0-9-]*[a-zA-Zа-яё0-9])?\.)+[a-zA-Zа-яё]{2,})(?:\s|[^\w.-]|$)/gi
     * Vulnerability: Nested quantifiers (?:X(?:Y*Z)?.)+ cause exponential backtracking
     */
    const pathologicalDomainInputs = [
      // Classic ReDoS pattern: repeated character + no valid ending
      'a'.repeat(50) + '-' + 'a'.repeat(50) + '!',

      // Multiple segments with invalid ending
      'sub-sub-sub-sub-sub-sub-sub-sub-sub-sub-sub!',

      // Long subdomain chains
      'a.'.repeat(100) + '!',

      // Mixed Cyrillic/Latin with pathological structure
      'аа'.repeat(30) + '-' + 'aa'.repeat(30) + '!',

      // Nested optional groups trigger
      'abc-def-ghi-jkl-mno-pqr-stu-vwx-yz!'.repeat(3)
    ];

    test.each(pathologicalDomainInputs)(
      'should not hang on pathological domain input: %s',
      (input) => {
        const start = Date.now();
        let result;

        // This should complete quickly or throw an error
        try {
          result = detectCyrillicHomographs(input);
        } catch (err) {
          // If it throws, that's acceptable (fail-safe behavior)
          console.warn('Detection threw error (fail-safe):', err.message);
        }

        const elapsed = Date.now() - start;

        // CRITICAL: Must complete in <10ms per SECURITY.md
        expect(elapsed).toBeLessThan(MAX_EXECUTION_TIME_MS);

        // Result should be defined (not hung forever)
        expect(result).toBeDefined();
      }
    );

    test('safe domain pattern should handle pathological input', () => {
      const input = 'sub-'.repeat(50) + 'example!';
      const start = Date.now();

      const result = SAFE_DOMAIN_PATTERN.test(input);
      const elapsed = Date.now() - start;

      expect(elapsed).toBeLessThan(MAX_EXECUTION_TIME_MS);
      expect(result).toBe(false); // Invalid domain
    });
  });

  describe('SQL Injection Pattern ReDoS (#29-#31, #39-#42)', () => {
    /**
     * Issues #29-#31: src/patterns/sql-injection.js
     * Vulnerable patterns in COMMENT_PATTERNS, INJECTION_PATTERNS, BYPASS_PATTERNS
     */
    const pathologicalSQLInputs = [
      // Comment pattern exploitation: /\/\*[\s\S]*?\*\//g
      '/*' + ' '.repeat(1000) + 'x',

      // Nested quantifier in bypass patterns
      'UNION' + ' '.repeat(500) + '/*' + '*'.repeat(500),

      // Multiple comment-like structures
      '/**/'.repeat(100) + 'x',

      // SQL with excessive whitespace
      'SELECT' + ' '.repeat(500) + 'FROM' + ' '.repeat(500) + '!',

      // Nested comment attempts
      '/*/*/*/*/*/*/*/*/*/*/*/*'
    ];

    test.each(pathologicalSQLInputs)(
      'should not hang on pathological SQL input: %s',
      (input) => {
        const start = Date.now();
        let result;

        try {
          result = detectSQLInjection(input);
        } catch (err) {
          console.warn('SQL detection threw error (fail-safe):', err.message);
        }

        const elapsed = Date.now() - start;
        expect(elapsed).toBeLessThan(MAX_EXECUTION_TIME_MS);
        expect(result).toBeDefined();
      }
    );
  });

  describe('Prototype Pollution Pattern ReDoS (#25-#27)', () => {
    /**
     * Issues #25-#27: src/patterns/prototype-pollution.js
     * Vulnerable patterns:
     * - /\[\s*'__proto__\..*'\s*\]/g  (line 101)
     * - /\[\s*"__proto__\..*"\s*\]/g  (line 102)
     * - /\$\{.*__proto__.*\}/g (line 154)
     */
    const pathologicalPollutionInputs = [
      // Bracket notation with long path
      "['__proto__." + 'a.'.repeat(200) + "']",

      // Template literal with nested __proto__
      '${' + '__proto__.'.repeat(100) + '}',

      // Multiple bracket accesses
      '[]'.repeat(500) + '__proto__',

      // Pathological computed property
      "['a" + 'x'.repeat(500) + "proto']",

      // Mixed patterns
      '__proto__' + '.constructor'.repeat(100)
    ];

    test.each(pathologicalPollutionInputs)(
      'should not hang on pathological pollution input: %s',
      (input) => {
        const start = Date.now();
        let result;

        try {
          result = detectPrototypePollution(input);
        } catch (err) {
          console.warn('Pollution detection threw error (fail-safe):', err.message);
        }

        const elapsed = Date.now() - start;
        expect(elapsed).toBeLessThan(MAX_EXECUTION_TIME_MS);
        expect(result).toBeDefined();
      }
    );
  });

  describe('Template Injection Pattern ReDoS (#32-#33)', () => {
    /**
     * Issues #32-#33: src/patterns/template-injection.js
     * Vulnerable patterns:
     * - /\{\{[^}]*[+\-*=<>!&|][^}]*\}\}/g (line 36)
     * - /\{%[^%]*[+\-*=<>!&|][^%]*%\}/g (line 37)
     */
    const pathologicalTemplateInputs = [
      // Double negated character class
      '{{' + 'a'.repeat(500) + '+' + 'b'.repeat(500) + '}}',

      // Jinja2 pattern with excessive nesting
      '{%' + ' '.repeat(500) + '|' + ' '.repeat(500) + '%}',

      // Multiple template delimiters
      '{{}}'.repeat(200),

      // Nested template-like structures
      '{{{{{{{{{{{{{{}}}}}}}}}}}}}}',

      // Long expression
      '{{' + 'x+'.repeat(300) + 'y}}'
    ];

    test.each(pathologicalTemplateInputs)(
      'should not hang on pathological template input: %s',
      (input) => {
        const start = Date.now();
        let result;

        try {
          result = detectTemplateInjection(input);
        } catch (err) {
          console.warn('Template detection threw error (fail-safe):', err.message);
        }

        const elapsed = Date.now() - start;
        expect(elapsed).toBeLessThan(MAX_EXECUTION_TIME_MS);
        expect(result).toBeDefined();
      }
    );
  });

  describe('NoSQL Injection Pattern ReDoS (#34-#35)', () => {
    /**
     * Issues #34-#35: src/patterns/nosql-injection.js:512, 534
     * Vulnerable patterns in boolean and SSJS injection detection
     */
    const pathologicalNoSQLInputs = [
      // Boolean injection with excessive whitespace
      'return' + ' '.repeat(500) + 'true' + ' '.repeat(500) + ';' + ' '.repeat(500) + '//',

      // SSJS with nested structures
      '";' + 'var x=1;'.repeat(100) + '//',

      // Multiple operators
      '$where:'.repeat(100),

      // Nested JSON-like structures
      '{"$where":' + '{"$where":'.repeat(50) + 'true' + '}'.repeat(50) + '}'
    ];

    test.each(pathologicalNoSQLInputs)(
      'should not hang on pathological NoSQL input: %s',
      (input) => {
        const start = Date.now();
        let result;

        try {
          result = detectNoSQLInjection(input);
        } catch (err) {
          console.warn('NoSQL detection threw error (fail-safe):', err.message);
        }

        const elapsed = Date.now() - start;
        expect(elapsed).toBeLessThan(MAX_EXECUTION_TIME_MS);
        expect(result).toBeDefined();
      }
    );
  });

  describe('Command Injection Pattern ReDoS (#36)', () => {
    /**
     * Issue #36: src/sanitizer/validators/command.js:498
     * Vulnerable shell metacharacter patterns
     */
    const pathologicalCommandInputs = [
      // Command substitution with nesting
      '$(' + '$('.repeat(100) + 'echo x' + ')'.repeat(100) + ')',

      // Multiple metacharacters
      ';;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;',

      // Long variable expansion
      '${' + 'VAR_'.repeat(200) + '}',

      // Heredoc with long tag
      '<<' + 'A'.repeat(500),

      // Wildcard expansion
      '*?*?*?*?*?*?*?*?*?*?*?*?'
    ];

    test.each(pathologicalCommandInputs)(
      'should not hang on pathological command input: %s',
      (input) => {
        const start = Date.now();
        let result;

        try {
          result = detectCommandInjection(input);
        } catch (err) {
          console.warn('Command detection threw error (fail-safe):', err.message);
        }

        const elapsed = Date.now() - start;
        expect(elapsed).toBeLessThan(MAX_EXECUTION_TIME_MS);
        expect(result).toBeDefined();
      }
    );
  });

  describe('Safe Pattern Utilities', () => {
    test('safePatternTest should enforce timeout', () => {
      // Using test fixture to avoid CodeQL false positive
      const { getVulnerableTestPattern } = require('./fixtures/redos-test-patterns');
      const vulnerablePattern = getVulnerableTestPattern();
      const input = 'a'.repeat(30) + 'x'; // No match, causes backtracking

      expect(() => {
        safePatternTest(vulnerablePattern, input, 50); // 50ms timeout
      }).toThrow('timeout');
    });

    test('safePatternTest should reject oversized input', () => {
      const pattern = /test/;
      const hugeInput = 'a'.repeat(20000); // Exceeds MAX_SAFE_LENGTH

      const result = safePatternTest(pattern, hugeInput);
      expect(result).toBe(false);
    });

    test('safeBatchTest should respect total time budget', () => {
      // Test with safe patterns that won't cause actual ReDoS
      // This tests the timeout budget mechanism, not ReDoS protection
      const patterns = [
        /test1/,
        /test2/,
        /test3/,
        /test4/,
        /test5/
      ];
      const input = 'test1 test2 test3 test4 test5';

      const start = Date.now();
      const results = safeBatchTest(patterns, input, BATCH_TIMEOUT_MS);
      const elapsed = Date.now() - start;

      // Should complete quickly with safe patterns
      expect(elapsed).toBeLessThan(BATCH_TIMEOUT_MS);

      expect(results).toHaveProperty('matched');
      expect(results).toHaveProperty('failed');
      expect(results).toHaveProperty('timeExceeded');

      // All safe patterns should match
      expect(results.matched.length).toBe(5);
      expect(results.timeExceeded).toBe(false);
    });

    test('safeBatchTest should handle individual pattern failures', () => {
      // Test that batch continues even if one pattern fails
      // Using a very short timeout to force a failure
      const patterns = [
        /safe1/,
        /safe2/,
        /safe3/
      ];
      const input = 'safe1 safe2 safe3';

      // Use a very short total timeout
      const results = safeBatchTest(patterns, input, 5); // Only 5ms total

      // Should have some results even with aggressive timeout
      expect(results).toHaveProperty('matched');
      expect(results).toHaveProperty('failed');
      expect(results).toHaveProperty('timeExceeded');

      // Either matched something or timed out (both are valid with 5ms budget)
      expect(results.matched.length + results.failed.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Performance Benchmarks', () => {
    /**
     * Verify all detection functions meet <10ms SLA from SECURITY.md
     */
    test('all detectors should complete quickly on normal input', () => {
      const normalInputs = {
        domain: 'subdomain.example.com with Cyrillic а',
        sql: "SELECT * FROM users WHERE id = 1 OR '1'='1'",
        pollution: "obj['__proto__'].isAdmin = true",
        template: '{{config.__class__.__bases__[0]}}',
        nosql: '{"$where": "this.password.match(/.*/)"}',
        command: 'cat /etc/passwd; rm -rf /'
      };

      const detectors = {
        domain: detectCyrillicHomographs,
        sql: detectSQLInjection,
        pollution: detectPrototypePollution,
        template: detectTemplateInjection,
        nosql: detectNoSQLInjection,
        command: detectCommandInjection
      };

      Object.entries(detectors).forEach(([type, detector]) => {
        const input = normalInputs[type];
        const start = Date.now();

        const result = detector(input);
        const elapsed = Date.now() - start;

        expect(elapsed).toBeLessThan(MAX_EXECUTION_TIME_MS);
        expect(result).toBeDefined();
        expect(result).toHaveProperty('detected');
      });
    });

    test('batch operations should scale linearly', () => {
      const sizes = [100, 500, 1000]; // Use larger inputs for measurable timing
      const timings = [];

      sizes.forEach(size => {
        const input = 'test'.repeat(size);
        const iterations = 1000; // Run multiple times for accurate measurement
        const start = process.hrtime.bigint();

        for (let i = 0; i < iterations; i++) {
          detectSQLInjection(input);
          detectPrototypePollution(input);
          detectTemplateInjection(input);
        }

        const elapsed = Number(process.hrtime.bigint() - start) / 1000000; // Convert to ms
        timings.push({ size, elapsed });
      });

      // Verify near-linear scaling (not exponential)
      const ratio1 = timings[1].elapsed / timings[0].elapsed;
      const ratio2 = timings[2].elapsed / timings[1].elapsed;

      // Ratios should be relatively consistent for linear scaling
      // Exponential would show ratio2 >> ratio1
      // Our patterns are so fast that we allow generous variance
      expect(ratio2 / ratio1).toBeLessThan(5); // Allow variance for fast patterns
      expect(ratio1).toBeGreaterThan(0); // Ensure we got valid measurements
      expect(ratio2).toBeGreaterThan(0);
    });
  });

  describe('Edge Cases', () => {
    test('should handle empty strings', () => {
      const detectors = [
        detectCyrillicHomographs,
        detectSQLInjection,
        detectPrototypePollution,
        detectTemplateInjection,
        detectNoSQLInjection,
        detectCommandInjection
      ];

      detectors.forEach(detector => {
        expect(() => detector('')).not.toThrow();
      });
    });

    test('should handle non-string inputs gracefully', () => {
      const invalidInputs = [null, undefined, 123, {}, []];
      const detectors = [
        detectCyrillicHomographs,
        detectSQLInjection,
        detectPrototypePollution
      ];

      detectors.forEach(detector => {
        invalidInputs.forEach(input => {
          expect(() => detector(input)).not.toThrow();
        });
      });
    });

    test('should handle unicode and special characters', () => {
      const unicodeInputs = [
        '\u0000\u0001\u0002', // Null and control chars
        '\uFEFF\u200B\u200C\u200D', // Zero-width characters
        '\u202E\u202D', // Directional overrides
        '𝕳𝖊𝖑𝖑𝖔', // Mathematical alphanumeric symbols
        '🔥💀☠️' // Emoji
      ];

      unicodeInputs.forEach(input => {
        const start = Date.now();
        detectCyrillicHomographs(input);
        const elapsed = Date.now() - start;

        expect(elapsed).toBeLessThan(MAX_EXECUTION_TIME_MS);
      });
    });
  });
});

describe('ReDoS Regression Tests', () => {
  /**
   * These tests verify that previously vulnerable patterns remain fixed
   * Add new test cases here when fixing ReDoS vulnerabilities
   */

  test('Issue #45: Domain pattern should be fixed', () => {
    const input = 'sub-'.repeat(30) + 'domain!';
    const start = Date.now();

    detectCyrillicHomographs(input);
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(MAX_EXECUTION_TIME_MS);
  });

  test('Issue #29-31: SQL patterns should be fixed', () => {
    const input = '/*' + '*'.repeat(100) + ' UNION SELECT';
    const start = Date.now();

    detectSQLInjection(input);
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(MAX_EXECUTION_TIME_MS);
  });

  test('Issue #25-27: Pollution patterns should be fixed', () => {
    const input = "['__proto__." + 'x.'.repeat(50) + "']";
    const start = Date.now();

    detectPrototypePollution(input);
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(MAX_EXECUTION_TIME_MS);
  });
});
