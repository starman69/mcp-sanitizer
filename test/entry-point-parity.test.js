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

  // GHSA-f8hw-8j7g-r466: non-special schemes (mcp://) keep the host opaque, so
  // numeric / hex / octal / shorthand IPv4 forms were never canonicalized.
  const mcpUrlEntryPoints = {
    'MCPSanitizer.sanitize': async (u) => sanitizer.sanitize(u, { type: 'url' }).blocked === true,
    'MCPSanitizer#sanitizeURL': async (u) => sanitizer.sanitizeURL(u).then(() => false, () => true),
    'URLValidator.validate (mcp allowed)': async (u) =>
      !(await new lib.URLValidator({ allowedProtocols: ['http', 'https', 'mcp'] }).validate(u)).isValid,
    'express web_fetch tool': (u) => expressToolBlocks('web_fetch', { url: u }),
    'koa web_fetch tool': (u) => koaToolBlocks('web_fetch', { url: u })
  };

  describe.each(Object.entries(mcpUrlEntryPoints))('mcp:// URL via %s', (_name, isBlocked) => {
    test.each([
      'mcp://2852039166/', // 169.254.169.254
      'mcp://2130706433/', // 127.0.0.1
      'mcp://0x7f000001/',
      'mcp://0177.0.0.1/',
      'mcp://127.1/',
      'mcp://0x7f.1/',
      'mcp://10.1/',
      'mcp://0/',
      'mcp://%31%32%37.0.0.1/',
      'mcp://169.254.169.254%00/', // invalid host a consumer could decode
      'mcp://2130706433%00/',
      'mcp://169.254.169.254/',
      'mcp://localhost/'
    ])('blocks %s', async (url) => {
      expect(await isBlocked(url)).toBe(true);
    });

    test.each(['mcp://example.com/', 'mcp://1.1.1.1/'])('allows %s', async (url) => {
      expect(await isBlocked(url)).toBe(false);
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

// GHSA-rc4x-x73r-6v9w: a policy rejection fell back to the weaker legacy validator,
// and with cwd=/ every absolute path counted as inside a safe root.
describe('File-path policy is final at every entry point (GHSA-rc4x-x73r-6v9w)', () => {
  const pathEntryPoints = {
    ...filePathEntryPoints,
    'MCPSanitizer#sanitizeFilePath': (p) => sanitizer.sanitizeFilePath(p).then(() => false, () => true)
  };
  const ABSOLUTE = [
    '/tmp/ok.txt',
    '/tmp/' + 'a'.repeat(300) + '.txt',
    '/opt/app/secrets.json',
    '/home/victim/.bash_history',
    '/var/lib/service/state.json'
  ];

  for (const cwd of [process.cwd(), '/']) {
    describe(`cwd=${cwd}`, () => {
      const original = process.cwd();
      beforeAll(() => process.chdir(cwd));
      afterAll(() => process.chdir(original));

      describe.each(Object.entries(pathEntryPoints))('via %s', (_name, isBlocked) => {
        test.each(ABSOLUTE)('blocks %s', async (p) => {
          expect(await isBlocked(p)).toBe(true);
        });
      });
    });
  }

  // Relative paths resolve against cwd: cwd=/ reaches anything, cwd=/etc reaches system files
  for (const [cwd, paths] of [['/', ['opt/app/secrets.json', 'home/victim/.bash_history', 'etc/passwd']], ['/etc', ['passwd', 'shadow']]]) {
    describe(`relative paths with cwd=${cwd}`, () => {
      const original = process.cwd();
      beforeAll(() => process.chdir(cwd));
      afterAll(() => process.chdir(original));

      describe.each(Object.entries(pathEntryPoints))('via %s', (_name, isBlocked) => {
        test.each(paths)('blocks %s', async (p) => {
          expect(await isBlocked(p)).toBe(true);
        });
      });
    });
  }

  test('STRICT treats ./file.txt the same at every entry point', async () => {
    const strict = new MCPSanitizer('STRICT');
    expect(strict.sanitize('./file.txt', { type: 'file_path' }).blocked).toBe(false);
    await expect(strict.sanitizeFilePath('./file.txt')).resolves.toBeDefined();
  });

  test('rejection does not fall back to the legacy validator', async () => {
    const s = new MCPSanitizer();
    const legacy = jest.spyOn(s, '_legacySanitizeFilePath');
    await expect(s.sanitizeFilePath('/tmp/ok.txt')).rejects.toThrow();
    expect(legacy).not.toHaveBeenCalled();
  });

  test('legacy validator still runs when the modular validator crashes', async () => {
    const s = new MCPSanitizer();
    s.validatorManager = { sanitizeFilePath: () => Promise.reject(new Error('crash')) };
    await expect(s.sanitizeFilePath('/opt/app/secrets.json')).rejects.toThrow();
    await expect(s.sanitizeFilePath('data/report.txt')).resolves.toBe('data/report.txt');
  });
});

// GHSA-rc4x-x73r-6v9w / GHSA-cmcj-g4x5-4jx8: allowedDirectories and
// blockedDirectories were documented but never read.
describe('filePath allowedDirectories / blockedDirectories are enforced', () => {
  const production = new MCPSanitizer({ policy: 'PRODUCTION' });
  const custom = new MCPSanitizer({
    contextSettings: { filePath: { allowedDirectories: ['./data'], blockedDirectories: ['./data/private'] } }
  });
  const entryPoints = (s, config) => ({
    sanitize: async (p) => s.sanitize(p, { type: 'file_path' }).blocked,
    sanitizeFilePath: (p) => s.sanitizeFilePath(p).then(() => false, () => true),
    FilePathValidator: async (p) => !(await new lib.FilePathValidator(config).validate(p)).isValid
  });

  describe.each(Object.entries(entryPoints(production, production.options.contextSettings.filePath)))(
    'PRODUCTION via %s', (_name, isBlocked) => {
      test.each(['other/secret.txt', 'secret.txt', 'datax/secret.txt'])('blocks %s', async (p) => {
        expect(await isBlocked(p)).toBe(true);
      });
      test.each(['data/report.txt', 'uploads/file.txt'])('allows %s', async (p) => {
        expect(await isBlocked(p)).toBe(false);
      });
    });

  describe.each(Object.entries(entryPoints(custom, custom.options.contextSettings.filePath)))(
    'custom config via %s', (_name, isBlocked) => {
      test.each(['data/private/key.txt', 'other/x.txt'])('blocks %s', async (p) => {
        expect(await isBlocked(p)).toBe(true);
      });
      test('allows data/report.txt', async () => {
        expect(await isBlocked('data/report.txt')).toBe(false);
      });
    });
});

describe('sanitizeSQL does not fall back after SQLValidator rejects (GHSA-rc4x-x73r-6v9w)', () => {
  test.each(["1' OR '1'='1", "x' OR 1=1", "' OR ''='", "x'or'1'='1"])('rejects %s', async (q) => {
    expect((await new lib.SQLValidator().validate(q)).isValid).toBe(false);
    await expect(sanitizer.sanitizeSQL(q)).rejects.toThrow();
  });

  test('allows a benign query', async () => {
    const q = 'SELECT name FROM users WHERE id = 1';
    await expect(sanitizer.sanitizeSQL(q)).resolves.toBe(q);
  });

  // sanitize(type:'sql') takes whole queries; keep 1.4.2 behaviour for these
  test.each(['SELECT a FROM t WHERE b = 1 AND c = 2', "SELECT a FROM t WHERE status = 'a' OR status = 'b'"])(
    'sanitize() allows %s', (q) => {
      expect(sanitizer.sanitize(q, { type: 'sql' }).blocked).toBe(false);
    });
});
