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
    [{ filter: { $function: { body: 'x' } } }, { type: 'request_query' }]
  ])('%j is blocked', (input, context) => {
    expect(blocked(input, context)).toBe(true);
  });

  it.each([
    [{ $schema: 'http://json-schema.org/draft-07/schema#', type: 'object' }],
    [{ properties: { a: { $ref: '#/$defs/a' } } }],
    [{ price: '$5' }]
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
