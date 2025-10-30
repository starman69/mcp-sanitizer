/**
 * Comprehensive Unicode Security Test Suite
 *
 * Tests the enhanced Unicode protection system to achieve >95% protection rate
 * Covers all major homograph attack vectors and confusable character types
 *
 * This file complements security-comprehensive.test.js with specialized Unicode tests
 * focusing on specific attack vectors not covered in the main security suite.
 */

const MCPSanitizer = require('../src/index');
const {
  detectHomographs,
  normalizeConfusableChars,
  multiPassNormalization,
  detectIDNHomograph,
  ZERO_WIDTH_CHARS
} = require('../src/utils/enterprise-security');

describe('Comprehensive Unicode Security Protection', () => {
  let sanitizer;

  beforeEach(() => {
    sanitizer = new MCPSanitizer({ strictMode: true });
  });

  describe('Fullwidth Character Attacks', () => {
    const fullwidthAttacks = [
      { attack: 'ａｄｍｉｎ', expected: 'admin', description: 'fullwidth admin' },
      { attack: 'ｐａｓｓｗｏｒｄ', expected: 'password', description: 'fullwidth password' },
      { attack: 'ｃａｔ　／ｅｔｃ／ｐａｓｓｗｄ', expected: 'cat /etc/passwd', description: 'fullwidth command injection' },
      { attack: 'ｃｍｄ．ｅｘｅ', expected: 'cmd.exe', description: 'fullwidth executable' },
      { attack: '１２３', expected: '123', description: 'fullwidth digits' }
    ];

    fullwidthAttacks.forEach(({ attack, expected, description }) => {
      it(`should detect and normalize ${description}`, () => {
        const result = sanitizer.sanitize(attack, { type: 'command' });

        expect(result.blocked).toBe(true);
        expect(result.warnings).toEqual(expect.arrayContaining([
          expect.stringMatching(/fullwidth|confusable|homograph/i)
        ]));

        // Verify normalization
        const normalized = normalizeConfusableChars(attack);
        expect(normalized).toBe(expected);
      });
    });
  });

  describe('Zero-Width Character Injection', () => {
    const zeroWidthAttacks = [
      { attack: `adm${ZERO_WIDTH_CHARS.ZWSP}in`, name: 'ZWSP injection', char: 'ZWSP' },
      { attack: `cat${ZERO_WIDTH_CHARS.ZWJ}/etc/passwd`, name: 'ZWJ injection', char: 'ZWJ' },
      { attack: `rm${ZERO_WIDTH_CHARS.ZWNJ} -rf /`, name: 'ZWNJ injection', char: 'ZWNJ' },
      { attack: `sudo${ZERO_WIDTH_CHARS.WJ} rm`, name: 'Word Joiner injection', char: 'WJ' },
      { attack: `${ZERO_WIDTH_CHARS.BOM}admin`, name: 'BOM prefix', char: 'BOM' }
    ];

    zeroWidthAttacks.forEach(({ attack, name, char }) => {
      it(`should detect ${name}`, () => {
        const result = sanitizer.sanitize(attack, { type: 'command' });

        expect(result.blocked).toBe(true);
        expect(result.warnings).toEqual(expect.arrayContaining([
          expect.stringMatching(new RegExp(`zero.?width|${char}|invisible`, 'i'))
        ]));
      });
    });

    it('should detect multiple zero-width characters', () => {
      const multiZeroWidth = `ad${ZERO_WIDTH_CHARS.ZWSP}m${ZERO_WIDTH_CHARS.ZWJ}in`;
      const result = sanitizer.sanitize(multiZeroWidth, { type: 'command' });

      expect(result.blocked).toBe(true);
      expect(result.warnings.length).toBeGreaterThan(1);
    });
  });

  describe('Mathematical Symbol Spoofing', () => {
    const mathAttacks = [
      { attack: '𝟏𝟐𝟑', expected: '123', description: 'mathematical bold digits' },
      { attack: '𝐚𝐝𝐦𝐢𝐧', expected: 'admin', description: 'mathematical bold lowercase' },
      { attack: '𝐀𝐃𝐌𝐈𝐍', expected: 'ADMIN', description: 'mathematical bold uppercase' },
      { attack: '𝑎𝑑𝑚𝑖𝑛', expected: 'admin', description: 'mathematical italic' },
      { attack: '𝟘𝟙𝟚𝟛', expected: '0123', description: 'mathematical double-struck digits' }
    ];

    mathAttacks.forEach(({ attack, expected, description }) => {
      it(`should detect ${description}`, () => {
        const result = sanitizer.sanitize(attack, { type: 'command' });

        expect(result.blocked).toBe(true);
        expect(result.warnings).toEqual(expect.arrayContaining([
          expect.stringMatching(/mathematical|alphanumeric|unicode/i)
        ]));

        const normalized = normalizeConfusableChars(attack);
        expect(normalized).toBe(expected);
      });
    });
  });

  describe('Extended Cyrillic Homographs', () => {
    const cyrillicAttacks = [
      { attack: 'аdmin', cyrillic: 'а', latin: 'a', description: 'Cyrillic a' },
      { attack: 'сat', cyrillic: 'с', latin: 'c', description: 'Cyrillic c' },
      { attack: 'есho', cyrillic: 'е', latin: 'e', description: 'Cyrillic e' },
      { attack: 'lоgin', cyrillic: 'о', latin: 'o', description: 'Cyrillic o' },
      { attack: 'рassword', cyrillic: 'р', latin: 'p', description: 'Cyrillic p' },
      { attack: 'Аdministrator', cyrillic: 'А', latin: 'A', description: 'Cyrillic A' },
      { attack: 'Нome', cyrillic: 'Н', latin: 'H', description: 'Cyrillic H' },
      { attack: 'Мicrosoft', cyrillic: 'М', latin: 'M', description: 'Cyrillic M' }
    ];

    cyrillicAttacks.forEach(({ attack, cyrillic, latin, description }) => {
      it(`should detect ${description} (${cyrillic} → ${latin})`, () => {
        const result = sanitizer.sanitize(attack, { type: 'command' });

        expect(result.blocked).toBe(true);
        expect(result.warnings).toEqual(expect.arrayContaining([
          expect.stringMatching(/cyrillic|homograph|confusable/i)
        ]));

        const normalized = normalizeConfusableChars(attack);
        expect(normalized).toContain(latin);
        expect(normalized).not.toContain(cyrillic);
      });
    });
  });

  describe('Greek Lookalike Characters', () => {
    const greekAttacks = [
      { attack: 'αdmin', greek: 'α', latin: 'a', description: 'Greek alpha' },
      { attack: 'ερror', greek: 'ε', latin: 'e', description: 'Greek epsilon' },
      { attack: 'οpen', greek: 'ο', latin: 'o', description: 'Greek omicron' },
      { attack: 'ρassword', greek: 'ρ', latin: 'p', description: 'Greek rho' },
      { attack: 'τest', greek: 'τ', latin: 't', description: 'Greek tau' },
      { attack: 'Αdmin', greek: 'Α', latin: 'A', description: 'Greek Alpha' },
      { attack: 'Βeta', greek: 'Β', latin: 'B', description: 'Greek Beta' }
    ];

    greekAttacks.forEach(({ attack, greek, latin, description }) => {
      it(`should detect ${description} (${greek} → ${latin})`, () => {
        const result = sanitizer.sanitize(attack, { type: 'command' });

        expect(result.blocked).toBe(true);
        expect(result.warnings).toEqual(expect.arrayContaining([
          expect.stringMatching(/greek|homograph|confusable/i)
        ]));

        const normalized = normalizeConfusableChars(attack);
        expect(normalized).toContain(latin);
      });
    });
  });

  describe('IDN Homograph Domain Attacks', () => {
    const idnAttacks = [
      { domain: 'gооgle.com', target: 'google', description: 'Cyrillic o in google' },
      { domain: 'аpple.com', target: 'apple', description: 'Cyrillic a in apple' },
      { domain: 'microsоft.com', target: 'microsoft', description: 'Cyrillic o in microsoft' },
      { domain: 'αmazon.com', target: 'amazon', description: 'Greek alpha in amazon' },
      { domain: 'fаcebook.com', target: 'facebook', description: 'Cyrillic a in facebook' },
      { domain: 'ｇｏｏｇｌｅ．ｃｏｍ', target: 'google', description: 'Fullwidth google.com' },
      { domain: 'раypal.com', target: 'paypal', description: 'Cyrillic p in paypal' }
    ];

    idnAttacks.forEach(({ domain, target, description }) => {
      it(`should detect ${description}`, () => {
        const result = detectIDNHomograph(domain);

        expect(result.detected).toBe(true);
        expect(result.warnings).toEqual(expect.arrayContaining([
          expect.stringMatching(/idn|homograph|domain|confusable/i)
        ]));

        if (result.warnings.some(w => w.includes('spoofing'))) {
          expect(result.warnings).toEqual(expect.arrayContaining([
            expect.stringMatching(new RegExp(target, 'i'))
          ]));
        }
      });

      it(`should sanitize URL with ${description}`, () => {
        const url = `https://${domain}/login`;
        const result = sanitizer.sanitize(url, { type: 'url' });

        expect(result.blocked).toBe(true);
        expect(result.warnings.length).toBeGreaterThan(0);
      });
    });
  });

  describe('Multi-Pass Normalization', () => {
    it('should handle nested homograph encodings', () => {
      const nested = 'а𝒅𝓶ｉn'; // Mixed Cyrillic, mathematical, and fullwidth
      const result = multiPassNormalization(nested);

      expect(result.normalized).toBe('admin');
      expect(result.passes).toBeGreaterThan(1);
      expect(result.changes.length).toBeGreaterThan(0);
    });

    it('should detect suspicious multiple normalization passes', () => {
      const suspicious = '𝒂𝐝𝓶ｉ𝒏'; // Requires multiple passes
      const result = detectHomographs(suspicious, { multiPass: true });

      expect(result.detected).toBe(true);
      expect(result.metadata.normalizationPasses).toBeGreaterThan(1);
    });

    it('should handle convergence detection', () => {
      const convergent = 'normal text';
      const result = multiPassNormalization(convergent);

      expect(result.converged).toBe(true);
      expect(result.suspicious).toBe(false);
    });
  });

  describe('Combined Attack Vectors', () => {
    const combinedAttacks = [
      {
        attack: `аdm${ZERO_WIDTH_CHARS.ZWSP}in`,
        types: ['cyrillic', 'zero-width'],
        description: 'Cyrillic + ZWSP'
      },
      {
        attack: 'ｃａｔ　＞　／ｅｔｃ／ｐａｓｓｗｄ',
        types: ['fullwidth'],
        description: 'Fullwidth command with redirection'
      },
      {
        attack: `𝐠оо𝑔𝓵𝑒${ZERO_WIDTH_CHARS.ZWJ}.com`,
        types: ['mathematical', 'cyrillic', 'zero-width'],
        description: 'Mathematical + Cyrillic + ZWJ domain'
      },
      {
        attack: 'Αd𝐦in‒𝟏𝟐𝟑',
        types: ['greek', 'mathematical'],
        description: 'Greek + Mathematical symbols'
      }
    ];

    combinedAttacks.forEach(({ attack, types, description }) => {
      it(`should detect combined attack: ${description}`, () => {
        const result = sanitizer.sanitize(attack, { type: 'command' });

        expect(result.blocked).toBe(true);
        expect(result.warnings.length).toBeGreaterThan(0);

        // Should detect at least one of the attack types
        const hasExpectedWarning = types.some(type =>
          result.warnings.some(warning =>
            warning.toLowerCase().includes(type) ||
            warning.toLowerCase().includes('homograph') ||
            warning.toLowerCase().includes('confusable') ||
            warning.toLowerCase().includes('unicode')
          )
        );

        expect(hasExpectedWarning).toBe(true);
      });
    });
  });

  describe('Unicode Normalization Edge Cases', () => {
    it('should handle combining characters correctly', () => {
      const combining = 'e\u0301'; // é with combining acute accent
      const result = detectHomographs(combining, { multiPass: true });

      // This should normalize to é but not trigger homograph detection
      expect(result.normalized).toBe('é');
    });

    it('should handle emoji and special Unicode correctly', () => {
      const emoji = '👨‍💻 admin';
      const result = sanitizer.sanitize(emoji, { type: 'command' });

      // Emoji should not trigger homograph warnings
      const homographWarning = result.warnings.some(w =>
        w.toLowerCase().includes('homograph') || w.toLowerCase().includes('confusable')
      );
      expect(homographWarning).toBe(false);
    });

    it('should preserve legitimate Unicode text', () => {
      const legitimate = 'Hello 世界'; // Mixed English and Chinese
      const result = sanitizer.sanitize(legitimate, { type: 'text' });

      expect(result.blocked).toBe(false);
    });
  });

  describe('Performance and Protection Rate Analysis', () => {
    // Known homograph attack vectors from security research
    const knownAttacks = [
      'ａｄｍｉｎ', 'сat', 'есho', 'оpen', 'ρort', 'αdmin', 'сmd',
      'сurl', 'ｌｓ', 'ｒｍ', 'сhmod', 'ｗｇｅｔ', 'ｓｕｄｏ',
      `adm${ZERO_WIDTH_CHARS.ZWSP}in`, `cat${ZERO_WIDTH_CHARS.ZWJ}`,
      '𝟏𝟐𝟑', '𝐚𝐝𝐦𝐢𝐧', '𝑎𝑑𝑚𝑖𝑛', 'gооgle.com', 'аpple.com',
      'microsоft.com', 'раypal.com', 'fаcebook.com'
    ];

    it('should achieve >95% protection rate against known attacks', () => {
      let blockedCount = 0;
      const totalAttacks = knownAttacks.length;

      knownAttacks.forEach(attack => {
        const result = sanitizer.sanitize(attack, { type: 'command' });
        if (result.blocked) {
          blockedCount++;
        }
      });

      const protectionRate = (blockedCount / totalAttacks) * 100;
      console.log(`Unicode Protection Rate: ${protectionRate.toFixed(1)}% (${blockedCount}/${totalAttacks})`);

      expect(protectionRate).toBeGreaterThan(95);
    });

    it('should maintain performance for Unicode processing', () => {
      const testInput = 'аdm𝐢n＠ｅｘａｍｐｌｅ．ｃｏｍ';
      const iterations = 1000;

      const start = Date.now();
      for (let i = 0; i < iterations; i++) {
        detectHomographs(testInput, {
          checkIDN: true,
          multiPass: true,
          detectZeroWidth: true
        });
      }
      const duration = Date.now() - start;
      const avgTime = duration / iterations;

      console.log(`Average Unicode detection time: ${avgTime.toFixed(3)}ms`);
      expect(avgTime).toBeLessThan(10); // Should be < 10ms per SECURITY.md requirement
    });

    it('should handle large Unicode strings efficiently', () => {
      const largeUnicodeString = 'а'.repeat(1000) + 'ｄｍｉｎ' + '𝐭𝐞𝐬𝐭'.repeat(100);

      const start = Date.now();
      const result = detectHomographs(largeUnicodeString);
      const duration = Date.now() - start;

      expect(result.detected).toBe(true);
      expect(duration).toBeLessThan(100); // Should complete in <100ms
    });
  });

  describe('Integration with Main Sanitizer', () => {
    it('should integrate Unicode detection with command sanitization', () => {
      const unicodeCommand = 'ｃａｔ　／ｅｔｃ／ｐａｓｓｗｄ';
      const result = sanitizer.sanitize(unicodeCommand, { type: 'command' });

      expect(result.blocked).toBe(true);
      expect(result.warnings.length).toBeGreaterThan(0);
    });

    it('should integrate Unicode detection with URL sanitization', () => {
      const unicodeUrl = 'https://gооgle.com/malicious';
      const result = sanitizer.sanitize(unicodeUrl, { type: 'url' });

      expect(result.blocked).toBe(true);
    });

    it('should integrate Unicode detection with SQL sanitization', () => {
      const unicodeSQL = "SЕLECT * FROM users WHERE name = 'аdmin'";
      const result = sanitizer.sanitize(unicodeSQL, { type: 'sql' });

      expect(result.blocked).toBe(true);
    });
  });
});

module.exports = {
  // Export test utilities for other test files
  getUnicodeTestVectors () {
    return {
      fullwidth: ['ａｄｍｉｎ', 'ｐａｓｓｗｏｒｄ', '１２３'],
      cyrillic: ['аdmin', 'сat', 'есho', 'Аdmin'],
      greek: ['αdmin', 'ερror', 'οpen', 'Αdmin'],
      mathematical: ['𝟏𝟐𝟑', '𝐚𝐝𝐦𝐢𝐧', '𝑎𝑑𝑚𝑖𝑛'],
      zeroWidth: [`adm${ZERO_WIDTH_CHARS.ZWSP}in`, `cat${ZERO_WIDTH_CHARS.ZWJ}`],
      domains: ['gооgle.com', 'аpple.com', 'microsоft.com']
    };
  },

  calculateProtectionRate (results) {
    const blocked = results.filter(r => r.blocked).length;
    return (blocked / results.length) * 100;
  }
};
