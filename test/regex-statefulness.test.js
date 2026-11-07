/**
 * Regression tests for GHSA-f7gm-6p35-r39c (CVE-TBD-008):
 * shared global-flag regexes must not carry lastIndex between calls.
 */
const lib = require('../src/index');
const { testRegex } = require('../src/utils/redos-safe-patterns');
const { detectNoSQLInjection } = require('../src/patterns/nosql-injection');
const { detectPrototypePollution } = require('../src/patterns/prototype-pollution');

const PAYLOADS = [
  'UNION SELECT password FROM users WHERE 1=1',
  "' OR 1=1--",
  '1; DROP TABLE users',
  'EXEC xp_cmdshell',
  "WAITFOR DELAY '0:0:5'",
  'sleep(5)',
  '{{7*7}}',
  '#{7*7}',
  '$' + '{7*7}',
  'constructor.prototype.x',
  '__proto__[x]=1',
  '; cat /etc/passwd',
  '$(id)',
  '{"$where":"1"}'
];

const DETECTORS = {
  hasSecurityPatterns: (x) => lib.hasSecurityPatterns(x),
  detectAllPatterns: (x) => lib.detectAllPatterns(x).detected,
  isSecure: (x) => lib.patterns.createPatternDetector().isSecure(x),
  detectInjection: (x) => lib.detectInjection(x).patterns,
  command: (x) => lib.patterns.commandInjection.detectCommandInjection(x).detected,
  sql: (x) => lib.patterns.sqlInjection.detectSQLInjection(x).detected,
  template: (x) => lib.patterns.templateInjection.detectTemplateInjection(x).detected,
  nosql: (x) => detectNoSQLInjection(x).detected,
  prototype: (x) => detectPrototypePollution(x).detected
};

describe('GHSA-f7gm: detectors are stateless across calls', () => {
  for (const [name, fn] of Object.entries(DETECTORS)) {
    it(`${name} returns the same verdict on repeated input`, () => {
      for (const payload of PAYLOADS) {
        const first = fn(payload);
        for (let i = 0; i < 4; i++) expect(fn(payload)).toEqual(first);
      }
    });

    it(`${name} verdict does not depend on the previous input`, () => {
      const fresh = PAYLOADS.map((p) => fn(p));
      for (let i = 0; i < PAYLOADS.length; i++) {
        fn('x'.repeat(5) + PAYLOADS[(i + 1) % PAYLOADS.length].repeat(3));
        expect(fn(PAYLOADS[i])).toEqual(fresh[i]);
      }
    });
  }

  it('SQL injection detected on every repetition', () => {
    for (let i = 0; i < 6; i++) {
      expect(lib.hasSecurityPatterns('UNION SELECT password FROM users WHERE 1=1')).toBe(true);
    }
  });

  it('analyzeInput blocks on every repetition', async () => {
    const s = new lib.MCPSanitizer();
    for (let i = 0; i < 6; i++) {
      expect((await s.analyzeInput('UNION SELECT password FROM users WHERE 1=1')).shouldBlock).toBe(true);
    }
  });

  it('testRegex resets lastIndex on global regexes', () => {
    const re = /abc/g;
    expect(testRegex(re, 'xxabc')).toBe(true);
    expect(re.lastIndex).toBe(0);
    expect(testRegex(re, 'xxabc')).toBe(true);
    re.lastIndex = 99;
    expect(testRegex(re, 'abc')).toBe(true);
  });
});
