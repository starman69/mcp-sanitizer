/**
 * Coverage tests for nosql-injection.js
 *
 * Targets uncovered lines: 205 (non-string input path), 603-609
 * (_identifyNoSQLType fallback), 651 (_getOperatorSeverity MEDIUM fallback),
 * 668 (_calculateSeverity LOW fallback).
 */

const {
  detectNoSQLInjection,
  NoSQLValidator
} = require('../../src/patterns/nosql-injection');

describe('nosql-injection coverage', () => {
  describe('detectNoSQLInjection with non-string input', () => {
    it('should handle object input with MongoDB operators', () => {
      const result = detectNoSQLInjection({ $gt: '', $ne: null });
      expect(result.detected).toBe(true);
    });

    it('should handle safe object input', () => {
      const result = detectNoSQLInjection({ name: 'safe' });
      expect(result.detected).toBe(false);
    });
  });

  describe('NoSQLValidator', () => {
    let validator;

    beforeEach(() => {
      validator = new NoSQLValidator();
    });

    describe('_identifyNoSQLType', () => {
      it('should identify MongoDB operators starting with $', () => {
        expect(validator._identifyNoSQLType('$where')).toBe('mongodb');
      });

      it('should identify CouchDB operators', () => {
        // CouchDB operators overlap with MongoDB ($-prefixed),
        // so the $ check matches first — CouchDB path is unreachable
        // for $-prefixed operators. Test the fallback instead.
        expect(validator._identifyNoSQLType('$allMatch')).toBe('mongodb');
      });

      it('should identify Redis commands', () => {
        expect(validator._identifyNoSQLType('FLUSHALL')).toBe('redis');
      });

      it('should return null for unknown operators', () => {
        expect(validator._identifyNoSQLType('unknownOp')).toBeNull();
      });
    });

    describe('_getOperatorSeverity', () => {
      it('should return critical for $where', () => {
        expect(validator._getOperatorSeverity('$where')).toBe('critical');
      });

      it('should return critical for $expr', () => {
        expect(validator._getOperatorSeverity('$expr')).toBe('critical');
      });

      it('should return high for $regex', () => {
        expect(validator._getOperatorSeverity('$regex')).toBe('high');
      });

      it('should return high for $ne', () => {
        expect(validator._getOperatorSeverity('$ne')).toBe('high');
      });

      it('should return medium for non-critical/non-high operators', () => {
        expect(validator._getOperatorSeverity('$set')).toBe('medium');
      });
    });

    describe('_calculateSeverity', () => {
      it('should return critical when any vulnerability is critical', () => {
        const vulns = [
          { severity: 'medium' },
          { severity: 'critical' }
        ];
        expect(validator._calculateSeverity(vulns)).toBe('critical');
      });

      it('should return high when highest is high', () => {
        const vulns = [
          { severity: 'medium' },
          { severity: 'high' }
        ];
        expect(validator._calculateSeverity(vulns)).toBe('high');
      });

      it('should return medium when highest is medium', () => {
        const vulns = [
          { severity: 'medium' },
          { severity: 'medium' }
        ];
        expect(validator._calculateSeverity(vulns)).toBe('medium');
      });

      it('should return low when all are low', () => {
        const vulns = [
          { severity: 'low' },
          { severity: 'low' }
        ];
        expect(validator._calculateSeverity(vulns)).toBe('low');
      });
    });
  });
});
