/**
 * Coverage tests for command-injection.js
 *
 * Targets uncovered lines: 110 (non-string input), 133-134 (shell-specific
 * patterns hit), 140-141 (encoded patterns hit), 147-148 (time-based patterns
 * hit), 208 (shell-specific inner loop match), 228 (encoded pattern match),
 * 247 (time-based pattern match), 284 (isCommandInjection boolean).
 */

const {
  detectCommandInjection,
  isCommandInjection,
  checkShellSpecificPatterns,
  checkEncodedPatterns,
  checkTimeBasedPatterns
} = require('../../src/patterns/command-injection');

describe('command-injection coverage', () => {
  describe('detectCommandInjection with non-string input', () => {
    it('should return not detected for numeric input', () => {
      const result = detectCommandInjection(42);
      expect(result.detected).toBe(false);
      expect(result.severity).toBeNull();
      expect(result.patterns).toEqual([]);
    });

    it('should return not detected for null', () => {
      expect(detectCommandInjection(null).detected).toBe(false);
    });

    it('should return not detected for object input', () => {
      expect(detectCommandInjection({ cmd: 'rm' }).detected).toBe(false);
    });
  });

  describe('checkShellSpecificPatterns', () => {
    it('should detect bash IFS manipulation', () => {
      const result = checkShellSpecificPatterns('$(IFS=;)cat /etc/passwd');
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.startsWith('bash_specific:'))).toBe(true);
    });

    it('should detect bash IFS variable usage', () => {
      // eslint-disable-next-line no-template-curly-in-string
      const result = checkShellSpecificPatterns('cat${IFS}/etc/passwd');
      expect(result.detected).toBe(true);
    });

    it('should detect bash xargs piping', () => {
      const result = checkShellSpecificPatterns('find / | xargs rm');
      expect(result.detected).toBe(true);
    });

    it('should detect bash tee piping', () => {
      const result = checkShellSpecificPatterns('echo secret | tee /tmp/out');
      expect(result.detected).toBe(true);
    });

    it('should detect PowerShell Invoke-Expression', () => {
      const result = checkShellSpecificPatterns('Invoke-Expression "malicious"');
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.startsWith('powershell_specific:'))).toBe(true);
    });

    it('should detect PowerShell iex shorthand', () => {
      const result = checkShellSpecificPatterns('iex "Get-Process"');
      expect(result.detected).toBe(true);
    });

    it('should detect PowerShell Start-Process', () => {
      const result = checkShellSpecificPatterns('Start-Process cmd.exe');
      expect(result.detected).toBe(true);
    });

    it('should detect PowerShell Get-Content', () => {
      const result = checkShellSpecificPatterns('gc C:\\secrets.txt');
      expect(result.detected).toBe(true);
    });

    it('should detect PowerShell Set-Content', () => {
      const result = checkShellSpecificPatterns('sc C:\\output.txt');
      expect(result.detected).toBe(true);
    });

    it('should detect Windows cmd echo chaining', () => {
      const result = checkShellSpecificPatterns('& echo owned');
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.startsWith('cmd_specific:'))).toBe(true);
    });

    it('should detect Windows findstr piping', () => {
      const result = checkShellSpecificPatterns('type file | findstr password');
      expect(result.detected).toBe(true);
    });

    it('should detect Windows for loops', () => {
      const result = checkShellSpecificPatterns('for /f "tokens=*" %a in (file) do echo %a');
      expect(result.detected).toBe(true);
    });

    it('should return not detected for safe input', () => {
      const result = checkShellSpecificPatterns('normal text');
      expect(result.detected).toBe(false);
    });
  });

  describe('checkEncodedPatterns', () => {
    it('should detect hex-encoded input', () => {
      const result = checkEncodedPatterns('\\x72\\x6d');
      expect(result.detected).toBe(true);
      expect(result.severity).toBe('medium');
    });

    it('should detect octal-encoded input', () => {
      const result = checkEncodedPatterns('\\162\\155');
      expect(result.detected).toBe(true);
    });

    it('should detect unicode-encoded input', () => {
      const result = checkEncodedPatterns('\\u0072\\u006d');
      expect(result.detected).toBe(true);
    });

    it('should detect URL-encoded input', () => {
      const result = checkEncodedPatterns('%72%6d');
      expect(result.detected).toBe(true);
    });

    it('should return not detected for clean input', () => {
      const result = checkEncodedPatterns('safe');
      expect(result.detected).toBe(false);
    });
  });

  describe('checkTimeBasedPatterns', () => {
    it('should detect sleep command', () => {
      const result = checkTimeBasedPatterns('sleep 5');
      expect(result.detected).toBe(true);
      expect(result.severity).toBe('medium');
    });

    it('should detect ping with count', () => {
      const result = checkTimeBasedPatterns('ping -c 10 127.0.0.1');
      expect(result.detected).toBe(true);
    });

    it('should detect timeout command', () => {
      const result = checkTimeBasedPatterns('timeout 30');
      expect(result.detected).toBe(true);
    });

    it('should detect usleep command', () => {
      const result = checkTimeBasedPatterns('usleep 500000');
      expect(result.detected).toBe(true);
    });

    it('should return not detected for safe input', () => {
      const result = checkTimeBasedPatterns('hello');
      expect(result.detected).toBe(false);
    });
  });

  describe('detectCommandInjection aggregation', () => {
    it('should aggregate shell-specific patterns into main result', () => {
      const result = detectCommandInjection('Invoke-Expression "payload"');
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.startsWith('powershell_specific:'))).toBe(true);
    });

    it('should aggregate encoded patterns into main result', () => {
      const result = detectCommandInjection('\\x72\\x6d');
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.startsWith('encoded_pattern:'))).toBe(true);
    });

    it('should aggregate time-based patterns into main result', () => {
      const result = detectCommandInjection('sleep 10');
      expect(result.detected).toBe(true);
      expect(result.patterns.some(p => p.startsWith('time_based:'))).toBe(true);
    });

    it('should combine multiple pattern types and pick highest severity', () => {
      const result = detectCommandInjection('rm -rf / | tee /tmp/out && sleep 5');
      expect(result.detected).toBe(true);
      expect(result.patterns.length).toBeGreaterThan(2);
      expect(result.severity).toBe('critical');
    });
  });

  describe('isCommandInjection boolean helper', () => {
    it('should return true for malicious input', () => {
      expect(isCommandInjection('rm -rf /')).toBe(true);
    });

    it('should return false for safe input', () => {
      expect(isCommandInjection('hello world')).toBe(false);
    });
  });
});
