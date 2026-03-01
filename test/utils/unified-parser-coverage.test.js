/**
 * Coverage tests for utils/unified-parser.js
 *
 * Targets: NormalizedString methods (match, replace with ReDoS timeout,
 * slice, split, toLowerCase, toUpperCase, trim, valueOf, length, includes,
 * indexOf, wasNormalized, getOriginal, getMetadata), parseUnifiedBatch,
 * isNormalizedString, extractNormalized, wrapValidator,
 * unifiedParsingMiddleware.
 */

const {
  NormalizedString,
  parseUnified,
  parseUnifiedBatch,
  isNormalizedString,
  extractNormalized,
  wrapValidator,
  unifiedParsingMiddleware
} = require('../../src/utils/unified-parser');

describe('unified-parser coverage', () => {
  describe('NormalizedString', () => {
    let ns;

    beforeEach(() => {
      ns = parseUnified('test input');
    });

    it('toString should return normalized string', () => {
      expect(ns.toString()).toBe('test input');
    });

    it('getNormalized should return normalized string', () => {
      expect(ns.getNormalized()).toBe('test input');
    });

    it('getMetadata should return frozen metadata', () => {
      const meta = ns.getMetadata();
      expect(meta).toBeDefined();
      expect(meta.inputType).toBe('generic');
      expect(Object.isFrozen(meta)).toBe(true);
    });

    it('wasNormalized should return false for clean input', () => {
      expect(ns.wasNormalized()).toBe(false);
    });

    it('wasNormalized should return true for encoded input', () => {
      const encoded = parseUnified('%74%65%73%74');
      expect(encoded.wasNormalized()).toBe(true);
    });

    it('getOriginal should return the original input', () => {
      const encoded = parseUnified('%74%65%73%74');
      expect(encoded.getOriginal()).toBe('%74%65%73%74');
    });

    it('length should return normalized string length', () => {
      expect(ns.length).toBe(10);
    });

    it('valueOf should return normalized string', () => {
      expect(ns.valueOf()).toBe('test input');
    });

    it('includes should work on normalized string', () => {
      expect(ns.includes('test')).toBe(true);
      expect(ns.includes('missing')).toBe(false);
    });

    it('indexOf should work on normalized string', () => {
      expect(ns.indexOf('input')).toBe(5);
      expect(ns.indexOf('missing')).toBe(-1);
    });

    it('match should return matches for safe regex', () => {
      const result = ns.match(/test/);
      expect(result).not.toBeNull();
      expect(result[0]).toBe('test');
    });

    it('match should return null for non-matching regex', () => {
      const result = ns.match(/missing/);
      expect(result).toBeNull();
    });

    it('replace with string should return new NormalizedString', () => {
      const result = ns.replace('test', 'new');
      expect(result).toBeInstanceOf(NormalizedString);
      expect(result.getNormalized()).toBe('new input');
    });

    it('replace with regex should return new NormalizedString', () => {
      const result = ns.replace(/test/, 'replaced');
      expect(result.getNormalized()).toBe('replaced input');
    });

    it('slice should return new NormalizedString', () => {
      const result = ns.slice(0, 4);
      expect(result).toBeInstanceOf(NormalizedString);
      expect(result.getNormalized()).toBe('test');
    });

    it('split should return array of NormalizedStrings', () => {
      const parts = ns.split(' ');
      expect(parts).toHaveLength(2);
      expect(parts[0]).toBeInstanceOf(NormalizedString);
      expect(parts[0].getNormalized()).toBe('test');
      expect(parts[1].getNormalized()).toBe('input');
    });

    it('toLowerCase should return new NormalizedString', () => {
      const upper = parseUnified('TEST');
      const result = upper.toLowerCase();
      expect(result.getNormalized()).toBe('test');
    });

    it('toUpperCase should return new NormalizedString', () => {
      const result = ns.toUpperCase();
      expect(result.getNormalized()).toBe('TEST INPUT');
    });

    it('trim should return new NormalizedString', () => {
      const padded = parseUnified('  padded  ');
      const result = padded.trim();
      expect(result.getNormalized()).toBe('padded');
    });

    it('should be immutable', () => {
      expect(Object.isFrozen(ns)).toBe(true);
    });
  });

  describe('parseUnified', () => {
    it('should throw for non-string input', () => {
      expect(() => parseUnified(123)).toThrow('Input must be a string');
    });

    it('should parse with file_path type', () => {
      const result = parseUnified('/etc/passwd', { type: 'file_path' });
      expect(result.getMetadata().inputType).toBe('file_path');
    });

    it('should parse with command type', () => {
      const result = parseUnified('ls -la', { type: 'command' });
      expect(result.getMetadata().inputType).toBe('command');
    });

    it('should include parsing metadata', () => {
      const result = parseUnified('hello');
      const meta = result.getMetadata();
      expect(meta.parserDifferentialPrevented).toBe(true);
      expect(meta.unifiedParsingVersion).toBe('1.0.0');
      expect(meta.immutableWrapper).toBe(true);
      expect(meta.parseTimestamp).toBeDefined();
    });
  });

  describe('parseUnifiedBatch', () => {
    it('should parse array of strings', () => {
      const results = parseUnifiedBatch(['hello', 'world']);
      expect(results).toHaveLength(2);
      expect(results[0]).toBeInstanceOf(NormalizedString);
      expect(results[0].getNormalized()).toBe('hello');
    });

    it('should throw for non-array input', () => {
      expect(() => parseUnifiedBatch('notarray')).toThrow('Inputs must be an array');
    });
  });

  describe('isNormalizedString', () => {
    it('should return true for NormalizedString', () => {
      expect(isNormalizedString(parseUnified('test'))).toBe(true);
    });

    it('should return false for plain string', () => {
      expect(isNormalizedString('test')).toBe(false);
    });

    it('should return false for null', () => {
      expect(isNormalizedString(null)).toBe(false);
    });
  });

  describe('extractNormalized', () => {
    it('should extract from NormalizedString', () => {
      const ns = parseUnified('hello');
      expect(extractNormalized(ns)).toBe('hello');
    });

    it('should normalize plain strings on the fly', () => {
      const result = extractNormalized('hello');
      expect(result).toBe('hello');
    });

    it('should throw for non-string/non-NormalizedString', () => {
      expect(() => extractNormalized(123)).toThrow('Value must be string or NormalizedString');
    });
  });

  describe('wrapValidator', () => {
    it('should wrap a validator function', () => {
      const validator = (input) => input.length > 3;
      const wrapped = wrapValidator(validator);
      expect(wrapped('hello')).toBe(true);
      expect(wrapped('hi')).toBe(false);
    });

    it('should accept NormalizedString input', () => {
      const validator = (input) => input.includes('test');
      const wrapped = wrapValidator(validator);
      const ns = parseUnified('test value');
      expect(wrapped(ns)).toBe(true);
    });

    it('should throw for non-string input', () => {
      const validator = (input) => true;
      const wrapped = wrapValidator(validator);
      expect(() => wrapped(123)).toThrow('must be string or NormalizedString');
    });
  });

  describe('unifiedParsingMiddleware', () => {
    it('should normalize req.query, req.params, and req.body', () => {
      const req = {
        query: { search: 'test' },
        params: { id: '123' },
        body: { name: 'user', nested: { val: 'data' } }
      };
      const res = {};
      let nextCalled = false;
      const next = () => { nextCalled = true; };

      unifiedParsingMiddleware(req, res, next);

      expect(nextCalled).toBe(true);
      expect(req._unifiedParsingApplied).toBe(true);
      expect(req._parsingTimestamp).toBeDefined();
      expect(req._originalQuery).toEqual({ search: 'test' });
      expect(isNormalizedString(req.query.search)).toBe(true);
      expect(isNormalizedString(req.params.id)).toBe(true);
      expect(isNormalizedString(req.body.name)).toBe(true);
      expect(isNormalizedString(req.body.nested.val)).toBe(true);
    });

    it('should handle missing body', () => {
      const req = { query: {}, params: {} };
      const res = {};
      let nextCalled = false;

      unifiedParsingMiddleware(req, res, () => { nextCalled = true; });

      expect(nextCalled).toBe(true);
    });

    it('should preserve non-string values in body', () => {
      const req = {
        query: {},
        params: {},
        body: { count: 42, active: true }
      };
      const res = {};

      unifiedParsingMiddleware(req, res, () => {});

      expect(req.body.count).toBe(42);
      expect(req.body.active).toBe(true);
    });
  });
});
