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
