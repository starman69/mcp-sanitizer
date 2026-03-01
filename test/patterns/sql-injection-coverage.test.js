/**
 * Coverage tests for sql-injection.js
 *
 * Targets uncovered lines: 203-204 (database-specific patterns hit),
 * 210-211 (encoded patterns hit), 297 (db-specific inner match),
 * 317 (encoded match), 373 (isSQLInjection boolean).
 */

const {
  detectSQLInjection,
  isSQLInjection,
  checkDatabaseSpecificPatterns,
  checkEncodedPatterns
} = require('../../src/patterns/sql-injection');

describe('sql-injection coverage', () => {
  describe('checkDatabaseSpecificPatterns', () => {
    it('should detect MySQL INTO OUTFILE', () => {
      const result = checkDatabaseSpecificPatterns("SELECT * INTO OUTFILE '/tmp/data'");
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.startsWith('mysql_specific:'))).toBe(true);
    });

    it('should detect MySQL LOAD_FILE', () => {
      const result = checkDatabaseSpecificPatterns("LOAD_FILE('/etc/passwd')");
      expect(result.detected).toBe(true);
    });

    it('should detect MySQL INFORMATION_SCHEMA', () => {
      const result = checkDatabaseSpecificPatterns('SELECT * FROM INFORMATION_SCHEMA.TABLES');
      expect(result.detected).toBe(true);
    });

    it('should detect PostgreSQL COPY TO PROGRAM', () => {
      const result = checkDatabaseSpecificPatterns("COPY users TO PROGRAM 'cat /etc/passwd'");
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.startsWith('postgresql_specific:'))).toBe(true);
    });

    it('should detect PostgreSQL pg_read_file', () => {
      const result = checkDatabaseSpecificPatterns("pg_read_file('/etc/passwd')");
      expect(result.detected).toBe(true);
    });

    it('should detect PostgreSQL pg_sleep', () => {
      const result = checkDatabaseSpecificPatterns('pg_sleep(10)');
      expect(result.detected).toBe(true);
    });

    it('should detect PostgreSQL dollar quoting', () => {
      const result = checkDatabaseSpecificPatterns('$$malicious$$');
      expect(result.detected).toBe(true);
    });

    it('should detect MSSQL xp_cmdshell', () => {
      const result = checkDatabaseSpecificPatterns("EXEC xp_cmdshell 'whoami'");
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.startsWith('mssql_specific:'))).toBe(true);
    });

    it('should detect MSSQL OPENROWSET', () => {
      const result = checkDatabaseSpecificPatterns("OPENROWSET('SQLOLEDB', ...)");
      expect(result.detected).toBe(true);
    });

    it('should detect Oracle UTL_HTTP', () => {
      const result = checkDatabaseSpecificPatterns('UTL_HTTP.REQUEST(url)');
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.startsWith('oracle_specific:'))).toBe(true);
    });

    it('should detect Oracle ALL_TABLES', () => {
      const result = checkDatabaseSpecificPatterns('SELECT * FROM ALL_TABLES');
      expect(result.detected).toBe(true);
    });

    it('should detect SQLite sqlite_master', () => {
      const result = checkDatabaseSpecificPatterns('SELECT * FROM sqlite_master');
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.startsWith('sqlite_specific:'))).toBe(true);
    });

    it('should detect SQLite PRAGMA', () => {
      const result = checkDatabaseSpecificPatterns('PRAGMA table_info(users)');
      expect(result.detected).toBe(true);
    });

    it('should detect SQLite ATTACH DATABASE', () => {
      const result = checkDatabaseSpecificPatterns("ATTACH DATABASE ':memory:' AS db2");
      expect(result.detected).toBe(true);
    });

    it('should return not detected for safe input', () => {
      const result = checkDatabaseSpecificPatterns('SELECT name FROM users');
      expect(result.detected).toBe(false);
    });
  });

  describe('checkEncodedPatterns', () => {
    it('should detect hex-encoded SQL', () => {
      const result = checkEncodedPatterns('0x414243');
      expect(result.detected).toBe(true);
    });

    it('should detect CHAR() encoding', () => {
      const result = checkEncodedPatterns('CHAR(97)');
      expect(result.detected).toBe(true);
    });

    it('should detect CHR() encoding', () => {
      const result = checkEncodedPatterns('CHR(97)');
      expect(result.detected).toBe(true);
    });

    it('should detect CONCAT()', () => {
      const result = checkEncodedPatterns("CONCAT('SEL','ECT')");
      expect(result.detected).toBe(true);
    });

    it('should detect || concatenation', () => {
      const result = checkEncodedPatterns("'SEL' || 'ECT'");
      expect(result.detected).toBe(true);
    });

    it('should return not detected for safe input', () => {
      const result = checkEncodedPatterns('safe');
      expect(result.detected).toBe(false);
    });
  });

  describe('detectSQLInjection aggregation', () => {
    it('should aggregate database-specific patterns', () => {
      const result = detectSQLInjection("EXEC xp_cmdshell 'dir'");
      expect(result.detected).toBe(true);
      expect(result.severity).toBeDefined();
    });

    it('should aggregate encoded patterns', () => {
      const result = detectSQLInjection('SELECT CHAR(97)');
      expect(result.detected).toBe(true);
    });
  });

  describe('isSQLInjection boolean helper', () => {
    it('should return true for SQL injection', () => {
      expect(isSQLInjection("' OR 1=1 --")).toBe(true);
    });

    it('should return false for safe input', () => {
      expect(isSQLInjection('hello')).toBe(false);
    });
  });
});
