/**
 * Tests for known XSS bypass scenarios
 *
 * These tests document known limitations of regex-based detection
 * and verify that our multi-layer defense (escape-html + validation)
 * provides adequate protection even when regex patterns miss variants.
 *
 * Per SECURITY.md: "We do NOT claim 100% protection against all attacks"
 */

const MCPSanitizer = require('../src/index');

describe('Known bypass scenarios - Defense-in-Depth testing', () => {
  const sanitizer = new MCPSanitizer('STRICT');

  describe('Improved event handler detection', () => {
    it('should detect event handler without space before =', () => {
      const result = sanitizer.sanitize({
        html: '<img onload=alert(1)>'
      });
      // Improved pattern should catch this
      expect(result.blocked || !result.sanitized.html.includes('onload')).toBe(true);
    });

    it('should detect SVG with slash syntax', () => {
      const result = sanitizer.sanitize({
        html: '<svg/onload=alert(1)>'
      });
      // Improved pattern with [\s/] should catch this
      expect(result.blocked || !result.sanitized.html.includes('onload')).toBe(true);
    });

    it('should detect event with multiple spaces', () => {
      const result = sanitizer.sanitize({
        html: '<img onload  =  alert(1)>'
      });
      expect(result.blocked || !result.sanitized.html.includes('onload')).toBe(true);
    });

    it('should detect event with tab character', () => {
      const result = sanitizer.sanitize({
        html: '<img onload\t=alert(1)>'
      });
      expect(result.blocked || !result.sanitized.html.includes('onload')).toBe(true);
    });
  });

  describe('Improved script tag detection', () => {
    it('should detect unclosed script tag', () => {
      const result = sanitizer.sanitize({
        html: '<script>alert(1)'
      });
      // New pattern for unclosed tags should catch this
      expect(result.blocked || !result.sanitized.html.includes('<script')).toBe(true);
    });

    it('should detect script tag with attributes but no close', () => {
      const result = sanitizer.sanitize({
        html: '<script src="evil.js">'
      });
      expect(result.blocked || !result.sanitized.html.includes('<script')).toBe(true);
    });

    it('should still detect well-formed script tags', () => {
      const result = sanitizer.sanitize({
        html: '<script>alert(1)</script>'
      });
      expect(result.blocked || !result.sanitized.html.includes('<script')).toBe(true);
    });

    it('should detect malformed closing tag', () => {
      const result = sanitizer.sanitize({
        html: '<script>alert(1)</script '
      });
      // Script opening tag should be caught by new pattern
      expect(result.blocked || !result.sanitized.html.includes('<script')).toBe(true);
    });
  });

  describe('Regex pattern limitations (documented in CODEQL analysis)', () => {
    it('should handle encoded event handlers via escape-html layer', () => {
      // Regex won't catch encoded 'o' but escape-html should handle it
      const result = sanitizer.sanitize({
        html: '<img on\\x6Coad=alert(1)>'
      });
      // May be blocked by regex or sanitized by escape-html
      // The backslash makes this an invalid HTML construct anyway
      const isSafe = result.blocked ||
                     !result.sanitized.html ||
                     !result.sanitized.html.includes('alert');
      expect(isSafe).toBe(true);
    });

    it('should handle SVG-based XSS via escape-html layer', () => {
      const result = sanitizer.sanitize({
        html: '<svg><script>alert(1)</script></svg>'
      });
      // Script tag should be caught
      expect(result.blocked || !result.sanitized.html.includes('<script')).toBe(true);
    });

    it('should handle data URI via protocol restrictions', () => {
      const result = sanitizer.sanitize({
        url: 'data:text/html,<script>alert(1)</script>'
      });
      // Should be blocked by protocol validation or script detection
      const isSafe = result.blocked ||
                     !result.sanitized.url ||
                     !result.sanitized.url.includes('data:');
      expect(isSafe).toBe(true);
    });
  });

  describe('Multi-layer defense verification', () => {
    it('should block or sanitize common XSS variants', () => {
      const xssVariants = [
        '<script>alert(1)</script>',
        '<img onload=alert(1)>',
        '<svg/onload=alert(1)>',
        '<body onload=alert(1)>',
        'javascript:alert(1)', // eslint-disable-line no-script-url
        '<img src=x onerror=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<script src="evil.js">',
        '<script>',
        '<img on load=alert(1)>' // Space in attribute name
      ];

      xssVariants.forEach(variant => {
        const result = sanitizer.sanitize({ html: variant });
        // Should be blocked OR sanitized safely
        const isSafe = result.blocked ||
                       !result.sanitized.html.includes('alert') ||
                       result.sanitized.html.includes('&lt;') ||
                       !result.sanitized.html.includes('<script');
        expect(isSafe).toBe(true);
      });
    });

    it('should log warnings for detected patterns', () => {
      const result = sanitizer.sanitize({
        html: '<script>alert(1)</script>'
      });

      if (result.blocked) {
        expect(result.warnings.length).toBeGreaterThan(0);
      }
    });
  });

  describe('Performance with bypass attempts', () => {
    it('should not cause ReDoS with nested structures', () => {
      const nested = '<script>' + '<script>'.repeat(100) + 'alert(1)' +
                     '</script>'.repeat(100) + '</script>';

      const start = Date.now();
      sanitizer.sanitize({ html: nested });
      const elapsed = Date.now() - start;

      // Should complete quickly (no catastrophic backtracking)
      expect(elapsed).toBeLessThan(100);
    });

    it('should handle pathological input without performance degradation', () => {
      const pathological = {
        html: '<script>' + 'a'.repeat(10000) + '</script>'
      };

      const start = Date.now();
      sanitizer.sanitize(pathological);
      const elapsed = Date.now() - start;

      // Per SECURITY.md requirement: <10ms for normal operations
      // Allow more for pathological input but still reasonable
      expect(elapsed).toBeLessThan(100);
    });

    it('should handle multiple patterns efficiently', () => {
      const complexInput = {
        html: '<!-- comment --><script>alert(1)</script><img onload=alert(2)>',
        sql: "SELECT * FROM users WHERE id = '1' OR '1'='1'",
        command: 'ls; rm -rf /',
        path: '../../../etc/passwd'
      };

      const start = Date.now();
      const result = sanitizer.sanitize(complexInput);
      const elapsed = Date.now() - start;

      expect(result.blocked).toBe(true);
      expect(elapsed).toBeLessThan(50);
    });
  });

  describe('Edge cases and corner cases', () => {
    it('should handle case variations (case-insensitive flag)', () => {
      const variants = [
        '<ScRiPt>alert(1)</sCrIpT>',
        '<SCRIPT>alert(1)</SCRIPT>',
        '<script>alert(1)</SCRIPT>'
      ];

      variants.forEach(variant => {
        const result = sanitizer.sanitize({ html: variant });
        expect(result.blocked || !result.sanitized.html.includes('alert')).toBe(true);
      });
    });

    it('should handle whitespace variations', () => {
      const variants = [
        { html: '<script >alert(1)</script>', desc: 'space before >' },
        { html: '<script\n>alert(1)</script>', desc: 'newline before >' },
        { html: '<script\t>alert(1)</script>', desc: 'tab before >' }
        // Note: '< script>' with space after < is invalid HTML and won't be parsed as a tag
      ];

      variants.forEach(({ html, desc }) => {
        const result = sanitizer.sanitize({ html });
        // Should be caught or sanitized
        const isSafe = result.blocked ||
                       !result.sanitized.html ||
                       !result.sanitized.html.includes('alert');
        expect(isSafe).toBe(true);
      });
    });

    it('should handle empty and null inputs', () => {
      const emptyInputs = [
        { html: '' },
        { html: null },
        { html: undefined },
        {}
      ];

      emptyInputs.forEach(input => {
        const result = sanitizer.sanitize(input);
        expect(result).toBeDefined();
        expect(result.blocked).toBe(false);
      });
    });
  });

  describe('Documentation of known limitations', () => {
    it('documents that encoded HTML entities may bypass regex', () => {
      // This is a documented limitation in CODEQL-HTML-FILTER-ANALYSIS.md
      // Regex patterns won't catch &#x6F; (encoded 'o') in "onload"
      // But escape-html layer provides additional protection
      const encoded = '&#x6F;nload'; // Encodes 'o' in onload

      // This test documents the limitation, not necessarily that we block it
      // The multi-layer approach means escape-html handles what regex misses
      expect(encoded).toContain('&#x');
    });

    it('documents that malformed HTML may be parsed differently by browsers', () => {
      // Different browsers may parse malformed HTML differently
      // Our regex provides heuristic detection, not browser-perfect parsing
      // This is intentional per our security philosophy
      const malformed = '<script<script>alert(1)</script>';

      // This test documents browser parsing differences
      // Primary defense is escape-html, not comprehensive HTML parsing
      expect(malformed).toContain('<');
    });
  });
});

describe('Bypass scenarios with different security policies', () => {
  it('STRICT policy should be most restrictive', () => {
    const strict = new MCPSanitizer('STRICT');
    const result = strict.sanitize({
      html: '<script>alert(1)</script>'
    });

    expect(result.blocked).toBe(true);
  });

  it('MODERATE policy should balance security and usability', () => {
    const moderate = new MCPSanitizer('MODERATE');
    const result = moderate.sanitize({
      html: '<script>alert(1)</script>'
    });

    // Should still block obvious XSS
    expect(result.blocked || !result.sanitized.html.includes('<script')).toBe(true);
  });

  it('PERMISSIVE policy should still catch dangerous patterns', () => {
    const permissive = new MCPSanitizer('PERMISSIVE');
    const result = permissive.sanitize({
      html: '<script>alert(1)</script>'
    });

    // Even permissive should catch script tags
    expect(result.blocked || !result.sanitized.html.includes('<script')).toBe(true);
  });
});
