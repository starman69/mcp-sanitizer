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

const expressMiddleware = require('../src/middleware/express');
const koaMiddleware = require('../src/middleware/koa');

const sanitizer = new MCPSanitizer();

// Run one MCP tool call through the Express / Koa tool middleware; true = blocked.
function expressToolBlocks (toolName, parameters) {
  return new Promise((resolve) => {
    const req = {
      path: '/tool',
      method: 'POST',
      ip: '203.0.113.1',
      params: { toolName },
      query: {},
      headers: {},
      body: { tool_name: toolName, parameters },
      get: () => ''
    };
    const res = {
      status () { return res; },
      json () { resolve(true); return res; }
    };
    expressMiddleware.createMCPToolMiddleware({ logWarnings: false })(req, res, (err) => resolve(Boolean(err)));
  });
}

async function koaToolBlocks (toolName, parameters) {
  const ctx = {
    path: '/tool',
    method: 'POST',
    ip: '203.0.113.1',
    params: { toolName },
    query: {},
    headers: {},
    state: {},
    status: 200,
    body: null,
    request: { body: { tool_name: toolName, parameters } },
    get: () => ''
  };
  let reachedNext = false;
  try {
    await koaMiddleware.createMCPToolMiddleware({ logWarnings: false })(ctx, async () => { reachedNext = true; });
  } catch (error) {
    return true;
  }
  return !reachedNext || ctx.status !== 200;
}

const urlEntryPoints = {
  'MCPSanitizer.sanitize': async (u) => sanitizer.sanitize(u, { type: 'url' }).blocked === true,
  'URLValidator.validate': async (u) => !(await new lib.URLValidator().validate(u)).isValid,
  validateURL: async (u) => !(await lib.validators.validateURL(u)).isValid,
  sanitizeURL: async (u) => !(await lib.sanitizeURL(u)).isValid,
  'express web_fetch tool': (u) => expressToolBlocks('web_fetch', { url: u }),
  'koa web_fetch tool': (u) => koaToolBlocks('web_fetch', { url: u })
};

const filePathEntryPoints = {
  'MCPSanitizer.sanitize': async (p) => sanitizer.sanitize(p, { type: 'file_path' }).blocked === true,
  'FilePathValidator.validate': async (p) => !(await new lib.FilePathValidator().validate(p)).isValid,
  validateFilePath: async (p) => !(await lib.validateFilePath(p)).isValid,
  'express file_reader tool': (p) => expressToolBlocks('file_reader', { file_path: p }),
  'koa file_reader tool': (p) => koaToolBlocks('file_reader', { file_path: p })
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
      'http://169.254.169.254/',
      'http://metadata.google.internal/', // GHSA-qvp2-8q5w-gcfp: internal names
      'http://100.64.0.1/', // and reserved ranges
      'http://[64:ff9b::7f00:1]/'
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
