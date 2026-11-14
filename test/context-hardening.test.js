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
