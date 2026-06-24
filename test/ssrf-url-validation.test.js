/**
 * SSRF / URL location validation regression tests.
 *
 * Asserts CORRECT (post-fix) behavior, so these are RED until the fix lands.
 * Source: GHSA-4mfg-r38w-w8fg (EQSTLab / SK Shieldus) — URL sanitizer SSRF
 * bypass via localhost+port, bracketed IPv6 loopback, and link-local addresses
 * (CWE-918).
 *
 * A `blocked: true` result is the security boundary consumers rely on before
 * issuing an outbound request for `web_fetch` / `web_scraper` tools. Anything
 * that can reach an internal service must be blocked.
 */

const MCPSanitizer = require('../src/index');

const sanitizer = new MCPSanitizer();

function isBlocked (url) {
  return sanitizer.sanitize(url, { type: 'url' }).blocked === true;
}

describe('SSRF: URL location restrictions (GHSA-4mfg-r38w-w8fg)', () => {
  describe('baseline — already blocked (regression guard)', () => {
    const alreadyBlocked = [
      'http://localhost/',
      'http://127.0.0.1/',
      'http://127.0.0.1:8080/', // caught by the /^127\./ private-IP pattern
      'http://169.254.169.254/' // IPv4 link-local / cloud metadata
    ];

    it.each(alreadyBlocked)('blocks %s', (url) => {
      expect(isBlocked(url)).toBe(true);
    });
  });

  describe('reported bypasses — must be blocked', () => {
    const reportedBypasses = [
      'http://localhost:8080/', // Bug 1: `&& !parsedUrl.port` guard
      'http://[::1]:8080/', // Bug 2: bracketed IPv6 loopback
      'http://[fe80::1]:8080/' // Bug 2: bracketed IPv6 link-local
    ];

    it.each(reportedBypasses)('blocks %s', (url) => {
      expect(isBlocked(url)).toBe(true);
    });
  });

  describe('related encodings sharing the same root cause', () => {
    const relatedBypasses = [
      'http://[::1]/', // bracketed IPv6 loopback, no port
      'http://[0:0:0:0:0:0:0:1]/', // expanded IPv6 loopback
      'http://[::ffff:127.0.0.1]/', // IPv4-mapped IPv6 loopback
      'http://0.0.0.0/', // "all interfaces" — loopback on most OSes
      'http://[fc00::1]/' // IPv6 unique-local (private)
    ];

    it.each(relatedBypasses)('blocks %s', (url) => {
      expect(isBlocked(url)).toBe(true);
    });
  });
});
