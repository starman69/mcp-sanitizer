/**
 * Coverage tests for prototype-pollution.js
 *
 * Targets uncovered lines: 178-179 (object input path), 194-195 (JSON pollution
 * hit), 208-209 (Express pollution hit), 242 (circular ref in checkObjectKeys),
 * 250-274 (nested object key checking), 311 (JSON pollution match),
 * 349 (Express pollution match), 425-434 (isPrototypePollution, isDangerousKey).
 */

const {
  detectPrototypePollution,
  isPrototypePollution,
  isDangerousKey,
  checkObjectKeys,
  checkJSONPollutionPatterns,
  checkLodashPollutionPatterns,
  checkExpressPollutionPatterns
} = require('../../src/patterns/prototype-pollution');

describe('prototype-pollution coverage', () => {
  describe('detectPrototypePollution with object input', () => {
    it('should detect __proto__ key in object', () => {
      // Note: { __proto__: x } in JS sets the prototype, not a regular key.
      // Use Object.create(null) to create an object where __proto__ is a real key.
      const obj = Object.create(null);
      // eslint-disable-next-line no-proto
      obj.__proto__ = { admin: true };
      const result = detectPrototypePollution(obj);
      expect(result.detected).toBe(true);
      expect(result.severity).toBe('critical');
    });

    it('should detect constructor key in object', () => {
      const result = detectPrototypePollution({ constructor: { prototype: {} } });
      expect(result.detected).toBe(true);
    });

    it('should detect prototype key in object', () => {
      const result = detectPrototypePollution({ prototype: { isAdmin: true } });
      expect(result.detected).toBe(true);
    });

    it('should handle safe object', () => {
      const result = detectPrototypePollution({ name: 'safe', value: 42 });
      expect(result.detected).toBe(false);
    });
  });

  describe('checkObjectKeys', () => {
    it('should detect dangerous keys in flat objects', () => {
      // Use Object.create(null) so __proto__ is a real enumerable key
      const obj = Object.create(null);
      // eslint-disable-next-line no-proto
      obj.__proto__ = {};
      const result = checkObjectKeys(obj);
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.includes('dangerous_key'))).toBe(true);
    });

    it('should detect constructor key in flat objects', () => {
      const result = checkObjectKeys({ constructor: {} });
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.includes('dangerous_key'))).toBe(true);
    });

    it('should detect dangerous keys in nested objects', () => {
      const obj = Object.create(null);
      obj.user = Object.create(null);
      // eslint-disable-next-line no-proto
      obj.user.__proto__ = { isAdmin: true };
      const result = checkObjectKeys(obj);
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.includes('user.__proto__'))).toBe(true);
    });

    it('should detect pollution_key patterns with constructor substring', () => {
      const result = checkObjectKeys({ my_constructor_hack: 'value' });
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.includes('pollution_key'))).toBe(true);
    });

    it('should handle circular references without crashing', () => {
      const obj = { a: {} };
      obj.a.circular = obj;
      const result = checkObjectKeys(obj);
      // Should not throw, circular ref is handled by WeakSet
      expect(result).toBeDefined();
    });

    it('should detect deeply nested dangerous keys', () => {
      const result = checkObjectKeys({
        level1: {
          level2: {
            prototype: { polluted: true }
          }
        }
      });
      expect(result.detected).toBe(true);
    });
  });

  describe('checkJSONPollutionPatterns', () => {
    it('should detect __proto__ in JSON string', () => {
      const result = checkJSONPollutionPatterns('{"__proto__":{"admin":true}}');
      expect(result.detected).toBe(true);
    });

    it('should detect constructor in JSON string', () => {
      const result = checkJSONPollutionPatterns('{"constructor":{"prototype":{}}}');
      expect(result.detected).toBe(true);
    });

    it('should return not detected for safe JSON', () => {
      const result = checkJSONPollutionPatterns('{"name":"safe"}');
      expect(result.detected).toBe(false);
    });
  });

  describe('checkLodashPollutionPatterns', () => {
    it('should detect lodash set with __proto__', () => {
      const result = checkLodashPollutionPatterns('lodash.set(obj, "__proto__.isAdmin", true)');
      expect(result.detected).toBe(true);
    });

    it('should detect lodash merge with __proto__', () => {
      const result = checkLodashPollutionPatterns('lodash.merge(target, {"__proto__":{}})');
      expect(result.detected).toBe(true);
    });

    it('should detect _.set with __proto__', () => {
      const result = checkLodashPollutionPatterns('_.set(obj, "__proto__.admin", true)');
      expect(result.detected).toBe(true);
    });

    it('should detect property path pollution', () => {
      const result = checkLodashPollutionPatterns("obj['__proto__.isAdmin']");
      expect(result.detected).toBe(true);
    });

    it('should return not detected for safe lodash usage', () => {
      const result = checkLodashPollutionPatterns('lodash.map(array, fn)');
      expect(result.detected).toBe(false);
    });
  });

  describe('checkExpressPollutionPatterns', () => {
    it('should detect req.body.__proto__', () => {
      const result = checkExpressPollutionPatterns('req.body.__proto__');
      expect(result.detected).toBe(true);
    });

    it('should detect req.query.__proto__', () => {
      const result = checkExpressPollutionPatterns('req.query.__proto__');
      expect(result.detected).toBe(true);
    });

    it('should detect req.params.__proto__', () => {
      const result = checkExpressPollutionPatterns('req.params.__proto__');
      expect(result.detected).toBe(true);
    });

    it('should detect __proto__[polluted] bracket notation', () => {
      const result = checkExpressPollutionPatterns('__proto__[polluted]');
      expect(result.detected).toBe(true);
    });

    it('should detect constructor[prototype]', () => {
      const result = checkExpressPollutionPatterns('constructor[prototype]');
      expect(result.detected).toBe(true);
    });

    it('should detect constructor.prototype[ access', () => {
      const result = checkExpressPollutionPatterns('constructor.prototype[isAdmin]');
      expect(result.detected).toBe(true);
    });

    it('should return not detected for safe express input', () => {
      const result = checkExpressPollutionPatterns('req.body.username');
      expect(result.detected).toBe(false);
    });
  });

  describe('detectPrototypePollution aggregation branches', () => {
    it('should aggregate JSON pollution patterns when detected', () => {
      const result = detectPrototypePollution('{"__proto__":{"admin":true}}');
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.startsWith('json_pollution:'))).toBe(true);
    });

    it('should aggregate Express pollution patterns when detected', () => {
      const result = detectPrototypePollution('req.body.__proto__');
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.startsWith('express_pollution:'))).toBe(true);
    });
  });

  describe('isPrototypePollution boolean helper', () => {
    it('should return true for pollution input', () => {
      expect(isPrototypePollution('__proto__')).toBe(true);
    });

    it('should return false for safe input', () => {
      expect(isPrototypePollution('safe string')).toBe(false);
    });
  });

  describe('isDangerousKey', () => {
    it('should return true for __proto__', () => {
      expect(isDangerousKey('__proto__')).toBe(true);
    });

    it('should return true for constructor', () => {
      expect(isDangerousKey('constructor')).toBe(true);
    });

    it('should return true for prototype', () => {
      expect(isDangerousKey('prototype')).toBe(true);
    });

    it('should return true for key containing __proto__ substring', () => {
      expect(isDangerousKey('my__proto__hack')).toBe(true);
    });

    it('should return false for safe key', () => {
      expect(isDangerousKey('username')).toBe(false);
    });
  });
});
