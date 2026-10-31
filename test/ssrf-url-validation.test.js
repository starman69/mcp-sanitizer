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

describe('SSRF: internal names and reserved ranges (GHSA-qvp2-8q5w-gcfp)', () => {
  // String-level checks; apply to sync sanitize() without any DNS lookup.
  it.each([
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://metadata/computeMetadata/v1/',
    'http://instance-data/latest/meta-data/',
    'http://printer.local/',
    'http://nas.home.arpa/',
    'http://100.64.0.1/', // CGNAT
    'http://198.18.0.1/', // benchmarking
    'http://192.0.0.1/', // IETF protocol assignments
    'http://224.0.0.1/', // multicast
    'http://255.255.255.255/', // broadcast
    'http://[64:ff9b::7f00:1]/', // NAT64 of 127.0.0.1
    'http://[2002:a9fe:a9fe::]/', // 6to4 of 169.254.169.254
    'http://[fec0::1]/', // site-local
    'http://[ff02::1]/' // multicast
  ])('blocks %s', (url) => {
    expect(isBlocked(url)).toBe(true);
  });

  it.each([
    'https://example.com/',
    'https://internal.example.com/', // `internal` as a label, not the TLD
    'http://[2606:4700::1111]/',
    'http://100.128.0.1/', // just outside CGNAT
    'mcp://server/resource'
  ])('allows %s', (url) => {
    expect(isBlocked(url)).toBe(false);
  });

  it('documents the string-level limit: DNS aliases still pass sync sanitize()', () => {
    expect(isBlocked('http://127.0.0.1.nip.io/')).toBe(false);
  });
});

describe('SSRF: blockedDomains / allowedDomains are enforced', () => {
  const withDomains = (url) => new MCPSanitizer({
    contextSettings: { url: { blockedDomains: ['evil.com'], allowedDomains: ['example.com', 'evil.com'] } }
  }).sanitize(url, { type: 'url' }).blocked === true;

  it('blocks a blocked domain and its subdomains', () => {
    expect(withDomains('https://evil.com/')).toBe(true);
    expect(withDomains('https://a.evil.com/')).toBe(true);
  });

  it('allows only allowlisted domains when the allowlist is non-empty', () => {
    expect(withDomains('https://api.example.com/')).toBe(false);
    expect(withDomains('https://other.org/')).toBe(true);
    expect(withDomains('https://notexample.com/')).toBe(true);
  });

  it('STRICT policy blockedDomains now take effect', () => {
    const strict = new MCPSanitizer('STRICT');
    expect(strict.sanitize('http://0.0.0.0/', { type: 'url' }).blocked).toBe(true);
  });
});

describe('SSRF: DNS resolution checks (GHSA-qvp2-8q5w-gcfp)', () => {
  const dns = require('dns');
  const { resolveAndValidateURL, URLValidator } = require('../src/index');
  const fakeLookup = (table) => async (host) => {
    if (!table[host]) throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    return table[host];
  };
  const table = {
    '172.17.0.4.nip.io': [{ address: '172.17.0.4', family: 4 }],
    'mixed.example': [{ address: '93.184.216.34', family: 4 }, { address: '::1', family: 6 }],
    'example.com': [{ address: '93.184.216.34', family: 4 }]
  };

  describe('resolveAndValidateURL', () => {
    const resolve = (url) => resolveAndValidateURL(url, { lookup: fakeLookup(table) });

    it('rejects a public name that resolves to a private address', async () => {
      await expect(resolve('http://172.17.0.4.nip.io:19345/')).rejects.toThrow(/resolves to private/);
    });

    it('rejects when any resolved address is restricted', async () => {
      await expect(resolve('http://mixed.example/')).rejects.toThrow(/resolves to loopback/);
    });

    it('returns the checked address for pinning', async () => {
      const result = await resolve('https://example.com/x');
      expect(result).toMatchObject({ address: '93.184.216.34', family: 4 });
      expect(result.url.href).toBe('https://example.com/x');
    });

    it('still applies string-level checks before resolving', async () => {
      await expect(resolve('http://[::1]/')).rejects.toThrow(/private IP range/);
    });

    it('propagates lookup failures', async () => {
      await expect(resolve('http://nope.example/')).rejects.toThrow(/ENOTFOUND/);
    });
  });

  describe('URLValidator with validateDNS', () => {
    let spy;
    beforeEach(() => { spy = jest.spyOn(dns.promises, 'lookup').mockImplementation(fakeLookup(table)); });
    afterEach(() => spy.mockRestore());

    it('rejects a DNS alias to a private address', async () => {
      const result = await new URLValidator({ validateDNS: true }).validate('http://172.17.0.4.nip.io:19345/');
      expect(result.isValid).toBe(false);
    });

    it('fails closed when resolution fails', async () => {
      const result = await new URLValidator({ validateDNS: true }).validate('http://nope.example/');
      expect(result.isValid).toBe(false);
    });

    it('accepts a public name and records resolved addresses', async () => {
      const result = await new URLValidator({ validateDNS: true }).validate('https://example.com/');
      expect(result.isValid).toBe(true);
      expect(result.metadata.resolvedAddresses).toEqual([{ address: '93.184.216.34', family: 4 }]);
    });

    it('stays opt-in: no lookup without validateDNS', async () => {
      const result = await new URLValidator().validate('http://172.17.0.4.nip.io/');
      expect(result.isValid).toBe(true);
      expect(spy).not.toHaveBeenCalled();
    });
  });
});
