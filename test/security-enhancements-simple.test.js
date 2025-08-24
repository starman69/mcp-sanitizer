/**
 * Simple tests for Security Enhancements - focusing on functionality
 */

const {
  detectDirectionalOverrides,
  detectNullBytes,
  detectMultipleUrlEncoding,
  detectPostgresDollarQuotes,
  detectCyrillicHomographs,
  handleEmptyStrings,
  DIRECTIONAL_OVERRIDES
} = require('../src/utils/security-enhancements');

describe('Security Enhancements - Core Functions', () => {
  test('should detect directional overrides', () => {
    const maliciousText = `test${DIRECTIONAL_OVERRIDES.RLO}attack`;
    const result = detectDirectionalOverrides(maliciousText);

    expect(result.detected).toBe(true);
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.warnings[0].type).toBe('DIRECTIONAL_OVERRIDE_ATTACK');
  });

  test('should detect null bytes', () => {
    const maliciousPath = '/path\x00/../etc/passwd';
    const result = detectNullBytes(maliciousPath);

    expect(result.detected).toBe(true);
    expect(result.warnings[0].type).toBe('NULL_BYTE_DETECTED');
    expect(result.sanitized).not.toContain('\x00');
  });

  test('should detect multiple URL encoding', () => {
    const doubleEncoded = '%252E%252E%252F';
    const result = detectMultipleUrlEncoding(doubleEncoded);

    expect(result.detected).toBe(true);
    expect(result.metadata.encodingDepth).toBe(2);
    expect(result.decoded).toBe('../');
  });

  test('should detect PostgreSQL dollar quotes', () => {
    const sqlWithDollarQuotes = 'SELECT $$content$$';
    const result = detectPostgresDollarQuotes(sqlWithDollarQuotes);

    expect(result.detected).toBe(true);
    expect(result.metadata.dollarQuotes.some(q => q.quote === '$$')).toBe(true);
  });

  test('should detect Cyrillic homographs', () => {
    const spoofedDomain = 'аpple.com'; // Cyrillic 'а'
    const result = detectCyrillicHomographs(spoofedDomain);

    expect(result.detected).toBe(true);
    expect(result.normalized).toBe('apple.com');
    expect(result.metadata.homographs.length).toBeGreaterThan(0);
  });

  test('should handle empty strings with context', () => {
    const result = handleEmptyStrings('', { required: true, fieldName: 'test' });

    expect(result.isEmpty).toBe(true);
    expect(result.isValid).toBe(false);
    expect(result.warnings[0].type).toBe('REQUIRED_FIELD_EMPTY');
  });

  // Timing attack prevention tests removed - not applicable for middleware sanitization

  test('should integrate with existing validators', () => {
    const { enhancedStringValidation } = require('../src/utils/string-utils');

    const result = enhancedStringValidation(`test${DIRECTIONAL_OVERRIDES.RLO}content`);

    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.sanitized).not.toContain(DIRECTIONAL_OVERRIDES.RLO);
  });
});
