/**
 * Coverage tests for template-injection.js
 *
 * Targets uncovered lines: 262 (non-string input), 292-293 (expression language
 * patterns hit), 299-300 (code execution patterns hit), 386 (expression
 * language match), 405 (code execution match), 442 (isTemplateInjection).
 */

const {
  detectTemplateInjection,
  isTemplateInjection,
  checkExpressionLanguagePatterns,
  checkCodeExecutionPatterns
} = require('../../src/patterns/template-injection');

describe('template-injection coverage', () => {
  describe('detectTemplateInjection with non-string input', () => {
    it('should return not detected for numeric input', () => {
      const result = detectTemplateInjection(42);
      expect(result.detected).toBe(false);
      expect(result.severity).toBeNull();
    });

    it('should return not detected for null', () => {
      expect(detectTemplateInjection(null).detected).toBe(false);
    });

    it('should return not detected for object', () => {
      expect(detectTemplateInjection({}).detected).toBe(false);
    });
  });

  describe('checkExpressionLanguagePatterns', () => {
    it('should detect Spring EL type references T()', () => {
      const result = checkExpressionLanguagePatterns('T(java.lang.Runtime)');
      expect(result.detected).toBe(true);
    });

    it('should detect Spring EL bean references @', () => {
      const result = checkExpressionLanguagePatterns('@beanFactory.getBean(');
      expect(result.detected).toBe(true);
    });

    it('should detect OGNL static method calls', () => {
      const result = checkExpressionLanguagePatterns('@java.lang.Runtime@getRuntime()');
      expect(result.detected).toBe(true);
    });

    it('should detect MVEL with statement', () => {
      const result = checkExpressionLanguagePatterns('with(Runtime.getRuntime())');
      expect(result.detected).toBe(true);
    });

    it('should detect SpEL #root', () => {
      const result = checkExpressionLanguagePatterns('#root.getClass()');
      expect(result.detected).toBe(true);
    });

    it('should detect SpEL systemProperties', () => {
      const result = checkExpressionLanguagePatterns('systemProperties["os.name"]');
      expect(result.detected).toBe(true);
    });

    it('should detect SpEL systemEnvironment', () => {
      const result = checkExpressionLanguagePatterns('systemEnvironment["PATH"]');
      expect(result.detected).toBe(true);
    });

    it('should return not detected for safe input', () => {
      const result = checkExpressionLanguagePatterns('just a string');
      expect(result.detected).toBe(false);
    });
  });

  describe('checkCodeExecutionPatterns', () => {
    it('should detect eval()', () => {
      const result = checkCodeExecutionPatterns('eval("malicious")');
      expect(result.detected).toBe(true);
    });

    it('should detect system()', () => {
      const result = checkCodeExecutionPatterns('system("whoami")');
      expect(result.detected).toBe(true);
    });

    it('should detect shell_exec()', () => {
      const result = checkCodeExecutionPatterns('shell_exec("ls")');
      expect(result.detected).toBe(true);
    });

    it('should detect file_get_contents()', () => {
      const result = checkCodeExecutionPatterns('file_get_contents("/etc/passwd")');
      expect(result.detected).toBe(true);
    });

    it('should detect include()', () => {
      const result = checkCodeExecutionPatterns('include("malicious.php")');
      expect(result.detected).toBe(true);
    });

    it('should detect require()', () => {
      const result = checkCodeExecutionPatterns('require("evil.php")');
      expect(result.detected).toBe(true);
    });

    it('should detect curl_exec()', () => {
      const result = checkCodeExecutionPatterns('curl_exec($ch)');
      expect(result.detected).toBe(true);
    });

    it('should detect fsockopen()', () => {
      const result = checkCodeExecutionPatterns('fsockopen("attacker.com", 80)');
      expect(result.detected).toBe(true);
    });

    it('should return not detected for safe input', () => {
      const result = checkCodeExecutionPatterns('safe template content');
      expect(result.detected).toBe(false);
    });
  });

  describe('detectTemplateInjection aggregation', () => {
    it('should aggregate expression language patterns', () => {
      // eslint-disable-next-line no-template-curly-in-string
      const result = detectTemplateInjection('${T(java.lang.Runtime).getRuntime()}');
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.startsWith('expression_language:'))).toBe(true);
    });

    it('should aggregate code execution patterns', () => {
      const result = detectTemplateInjection('{{system("id")}}');
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.startsWith('code_execution:'))).toBe(true);
    });

    it('should combine multiple template attack types', () => {
      // eslint-disable-next-line no-template-curly-in-string
      const result = detectTemplateInjection('{{7*7}} ${eval("x")} system("id")');
      expect(result.detected).toBe(true);
      expect(result.patterns.length).toBeGreaterThan(2);
    });
  });

  describe('isTemplateInjection boolean helper', () => {
    it('should return true for template injection', () => {
      expect(isTemplateInjection('{{7*7}}')).toBe(true);
    });

    it('should return false for safe input', () => {
      expect(isTemplateInjection('hello')).toBe(false);
    });
  });
});
