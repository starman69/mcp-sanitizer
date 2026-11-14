/**
 * Hardening regression tests from the 1.4.4 proactive audit (no advisory filed).
 */

const MCPSanitizer = require('../src/index');

const sanitizer = new MCPSanitizer('PRODUCTION');
const blocked = (input, context) => sanitizer.sanitize(input, context).blocked === true;

describe('field names cannot override an explicit context', () => {
  it.each([
    [{ query: 'https://169.254.169.254/latest/meta-data/' }, 'url'],
    [{ sql: 'https://169.254.169.254/' }, 'url'],
    [{ query: '/root/.ssh/id_rsa' }, 'file_path'],
    [{ url: '../../etc/passwd' }, 'file_path'],
    [{ sql: 'rm -rf /' }, 'command'],
    [{ path: 'python3 -c id' }, 'command']
  ])('%j with type %s is blocked', (input, type) => {
    expect(blocked(input, { type })).toBe(true);
  });

  it('still allows clean nested values', () => {
    expect(blocked({ url: 'https://example.com/' }, { type: 'url' })).toBe(false);
  });

  it('still refines a generic context by field name', () => {
    expect(blocked({ url: 'https://169.254.169.254/' }, { type: 'request_body' })).toBe(true);
  });
});

describe('NoSQL operator keys are blocked in every context', () => {
  it.each([
    [{ username: 'admin', password: { $ne: null } }, { type: 'request_body' }],
    [{ password: { $regex: '.*' } }, {}],
    [[{ $where: 'sleep(5000)' }], {}],
    [{ a: { '＄ne': 1 } }, {}], // fullwidth dollar
    [{ filter: { $function: { body: 'x' } } }, { type: 'request_query' }],
    [{ '%24ne': 1 }, {}], // keys are checked after decoding
    [{ '\\u0024ne': 1 }, {}], // eslint-disable-line quote-props
    [{ $price: 1 }, { type: 'query' }] // any $ key in a query context
  ])('%j is blocked', (input, context) => {
    expect(blocked(input, context)).toBe(true);
  });

  it.each([
    [{ $schema: 'http://json-schema.org/draft-07/schema#', type: 'object' }],
    [{ properties: { a: { $ref: '#/$defs/a' } } }],
    [{ price: '$5' }],
    [{ $type: 'Shop.Order' }], // .NET / JSON-LD polymorphism
    [{ _id: { $oid: '5f1d' } }], // MongoDB Extended JSON
    [{ a: { $price: 3 } }]
  ])('%j is allowed', (input) => {
    expect(blocked(input, {})).toBe(false);
  });
});

describe('object keys are checked like values', () => {
  it.each([
    [{ '<img src=x onerror=alert(1)>': 1 }],
    [{ '{{7*7}}': 1 }],
    [{ '__proto__.isAdmin': true }],
    [{ 'constructor[prototype][isAdmin]': true }],
    [{ a: { 'x.prototype.y': 1 } }],
    [{ ['k'.repeat(20000)]: 1 }]
  ])('%j is blocked', (input) => {
    expect(blocked(input, {})).toBe(true);
  });

  it('allows ordinary keys', () => {
    expect(blocked({ 'Content-Type': 'x', user_name: 'a', 'first name': 'b', émoji: 'c' }, {})).toBe(false);
  });

  it('does not apply value patterns (SQL comment, shell) to keys', () => {
    expect(blocked({ '--main-color': 'red', 'card--active': 1, 'a;b': 1 }, {})).toBe(false);
  });

  it('checks keys after decoding', () => {
    expect(blocked({ '%3Cimg%3E': 1 }, {})).toBe(true);
  });
});

describe('nested strings and keys get the top-level security checks', () => {
  it.each([
    [{ a: 'a‮b' }],
    [{ a: 'a\u0000b' }],
    [['x‮y']],
    [{ a: { b: '%2561' } }], // double encoding
    [{ 'a‮b': 1 }],
    [{ 'a\u0000b': 1 }]
  ])('%j is blocked', (input) => {
    expect(blocked(input, {})).toBe(true);
  });
});

describe('template and prototype patterns', () => {
  const payloads = [
    '{{7*\n7}}',
    '{{\r7*7}}',
    '{{\u2028config.items()}}',
    '{% for x in ().__class__.__base__.__subclasses__() %}',
    '#{7*7}',
    '${\n7*7}', // eslint-disable-line no-template-curly-in-string
    'x.constructor .prototype',
    'Object.prototype.polluted',
    'constructor["prototype"]'
  ];
  describe.each(['PRODUCTION', 'STRICT', undefined])('policy %s', (policy) => {
    const s = policy ? new MCPSanitizer(policy) : new MCPSanitizer();
    it.each(payloads)('blocks %j', (p) => {
      expect(s.sanitize(p).blocked).toBe(true);
    });
    it.each(['hello world', 'price is $5 {ok}', 'a#b{c', 'the constructor of prototypes'])('allows %j', (p) => {
      expect(s.sanitize(p).blocked).toBe(false);
    });
  });
});

describe('sanitize(type: sql) catches injection payloads, not just keywords', () => {
  const payloads = [
    "1' OR '1'='1",
    "' OR ''='",
    "admin'#",
    '1 OR\t1=1',
    '1 AND SLEEP(5)',
    "1 WAITFOR DELAY '0:0:5'",
    "1 INTO OUTFILE '/tmp/x'",
    '1 OR(1=1)',
    '1 OR true',
    "' OR 1=1#",
    "admin'-- ",
    "x' /* c */ UNION/**/SELECT 1"
  ];
  describe.each(['PRODUCTION', 'MODERATE', undefined])('policy %s', (policy) => {
    const s = policy ? new MCPSanitizer(policy) : new MCPSanitizer();
    it.each(payloads)('blocks %j', (q) => {
      expect(s.sanitize(q, { type: 'sql' }).blocked).toBe(true);
    });
    it.each([
      'SELECT name FROM users WHERE id = 5',
      'SELECT a FROM t WHERE b = 1 AND c = 2',
      "SELECT a FROM t WHERE status = 'a' OR status = 'b'",
      "O'Brien",
      '42',
      "SELECT * FROM t WHERE color = '#fff'",
      "SELECT * FROM t WHERE tag = '#urgent' AND n = 2"
    ])('allows %j', (q) => {
      expect(s.sanitize(q, { type: 'sql' }).blocked).toBe(false);
    });
  });

  it.each(['1 OR(1=1)', '1 OR true'])('validateSQL rejects %j', async (q) => {
    expect((await require('../src/index').validators.validateSQL(q)).isValid).toBe(false);
  });
});

describe('IIS %uXXXX encoding is decoded before validation', () => {
  it.each([
    ['https://example.com/%u002e%u002e/admin', { type: 'url' }],
    ['%u003cscript%u003ealert(1)', {}]
  ])('%s is blocked', (input, context) => {
    expect(blocked(input, context)).toBe(true);
  });

  it('leaves non-hex %u text alone', () => {
    expect(sanitizer.sanitize('100%useful', {}).sanitized).toBe('100%useful');
  });
});

describe('oversized strings are rejected before normalization', () => {
  it('rejects a 1 MB nested string quickly', () => {
    const start = Date.now();
    expect(new MCPSanitizer().sanitize({ a: 'a'.repeat(1e6) }).blocked).toBe(true);
    expect(Date.now() - start).toBeLessThan(100);
  });

  it('rejects an oversized top-level string on length, before the homograph scan', () => {
    const result = new MCPSanitizer().sanitize('\u0430'.repeat(4e6));
    expect(result.blocked).toBe(true);
    expect(result.warnings.join(' ')).toMatch(/before normalization/);
  });

  it('still accepts encoded input that normalizes under the limit', () => {
    expect(new MCPSanitizer().sanitize('%41'.repeat(3000)).blocked).toBe(false);
  });
});
