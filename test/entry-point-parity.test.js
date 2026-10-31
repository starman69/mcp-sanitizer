/**
 * Entry-point parity regression tests.
 *
 * Source: GHSA-v25x-53wq-6r99 — the 1.4.0 fixes landed in MCPSanitizer only;
 * the exported validators (URLValidator, sanitizeURL, validateFilePath, ...)
 * kept their own weaker checks. Every payload here must get the same verdict
 * from every public entry point.
 */

const MCPSanitizer = require('../src/index');
const lib = require('../src/index');

const sanitizer = new MCPSanitizer();

const urlEntryPoints = {
  'MCPSanitizer.sanitize': async (u) => sanitizer.sanitize(u, { type: 'url' }).blocked === true,
  'URLValidator.validate': async (u) => !(await new lib.URLValidator().validate(u)).isValid,
  validateURL: async (u) => !(await lib.validators.validateURL(u)).isValid,
  sanitizeURL: async (u) => !(await lib.sanitizeURL(u)).isValid
};

const filePathEntryPoints = {
  'MCPSanitizer.sanitize': async (p) => sanitizer.sanitize(p, { type: 'file_path' }).blocked === true,
  'FilePathValidator.validate': async (p) => !(await new lib.FilePathValidator().validate(p)).isValid,
  validateFilePath: async (p) => !(await lib.validateFilePath(p)).isValid
};

describe('Entry-point parity (GHSA-v25x-53wq-6r99)', () => {
  describe.each(Object.entries(urlEntryPoints))('URL via %s', (_name, isBlocked) => {
    test.each([
      'http://[::1]:8080/',
      'http://[::ffff:127.0.0.1]:8080/',
      'http://[fe80::1]/',
      'http://0.0.0.0:8080/',
      'http://[::]/',
      'http://[fd00::1]/',
      'http://127.0.0.1/',
      'http://localhost:3000/',
      'http://169.254.169.254/'
    ])('blocks %s', async (url) => {
      expect(await isBlocked(url)).toBe(true);
    });

    test('allows a public URL', async () => {
      expect(await isBlocked('https://example.com/')).toBe(false);
    });
  });

  describe.each(Object.entries(filePathEntryPoints))('file path via %s', (_name, isBlocked) => {
    test.each([
      'sub/.env',
      'project/.ssh/id_rsa',
      'project/.aws/credentials',
      '.env', // GHSA-6xj4-4chr-656w: sensitive first segment
      '.ssh/id_rsa',
      '.npmrc'
    ])('blocks %s', async (p) => {
      expect(await isBlocked(p)).toBe(true);
    });

    test('allows an ordinary file', async () => {
      expect(await isBlocked('data/report.txt')).toBe(false);
    });
  });

  describe('URLValidator allow* flags are per category', () => {
    test('allowPrivateIPs does not open loopback or link-local', async () => {
      const v = new lib.URLValidator({ allowPrivateIPs: true });
      expect((await v.validate('http://10.0.0.1/')).isValid).toBe(true);
      expect((await v.validate('http://[::1]/')).isValid).toBe(false);
      expect((await v.validate('http://169.254.169.254/')).isValid).toBe(false);
    });
  });
});
