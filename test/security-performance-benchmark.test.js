/**
 * Security Performance Benchmark Tests
 *
 * These tests measure the performance impact of the security decoder integration
 * and ensure that the fixes don't significantly impact system performance.
 */

const MCPSanitizer = require('../src/index')

describe('Security Performance Benchmark', () => {
  let sanitizer
  const ITERATION_COUNT = 1000

  beforeEach(() => {
    sanitizer = new MCPSanitizer({
      policy: 'PRODUCTION',
      allowedFileExtensions: ['.txt', '.json', '.md', '.csv', '.yaml', '.yml', '.log', '.png', '.jpg', '.jsx', '.js', '.html', '.css']
    })
  })

  describe('Baseline Performance (Safe Inputs)', () => {
    it('should process safe file paths efficiently', () => {
      const safeInputs = [
        'document.txt',
        'data/config.json',
        'assets/image.png',
        'src/components/Header.jsx',
        'tests/unit/security.test.js'
      ]

      const startTime = Date.now()

      for (let i = 0; i < ITERATION_COUNT; i++) {
        const input = safeInputs[i % safeInputs.length]
        const result = sanitizer.sanitize(input, { type: 'file_path' })
        expect(result.blocked).toBe(false)
        expect(result.sanitized).toBe(input)
      }

      const endTime = Date.now()
      const avgTime = (endTime - startTime) / ITERATION_COUNT

      console.log(`Safe file paths: ${avgTime.toFixed(3)}ms per operation`)
      expect(avgTime).toBeLessThan(2) // Should be under 2ms for safe inputs
    })

    it('should process safe URLs efficiently', () => {
      const safeInputs = [
        'https://api.example.com/data',
        'https://cdn.jsdelivr.net/npm/package',
        'https://github.com/user/repo',
        'https://www.google.com/search?q=test',
        'mcp://server/resource'
      ]

      const startTime = Date.now()

      for (let i = 0; i < ITERATION_COUNT; i++) {
        const input = safeInputs[i % safeInputs.length]
        const result = sanitizer.sanitize(input, { type: 'url' })
        expect(result.blocked).toBe(false)
      }

      const endTime = Date.now()
      const avgTime = (endTime - startTime) / ITERATION_COUNT

      console.log(`Safe URLs: ${avgTime.toFixed(3)}ms per operation`)
      expect(avgTime).toBeLessThan(3) // URLs are more complex to parse
    })
  })

  describe('Security Decoder Impact (Encoded Inputs)', () => {
    it('should handle URL-encoded inputs with acceptable overhead', () => {
      const encodedInputs = [
        '%2E%2E%2Fetc%2Fpasswd', // ../etc/passwd
        'javascript%3Aalert%281%29', // javascript:alert(1)
        'ls%3B%20rm%20-rf%20%2F', // ls; rm -rf /
        'SELECT%20%2A%20FROM%20users%3B%20DROP%20TABLE%20users%3B' // SQL injection
      ]

      const types = ['file_path', 'url', 'command', 'sql']
      const startTime = Date.now()
      let blockedCount = 0

      for (let i = 0; i < ITERATION_COUNT; i++) {
        const input = encodedInputs[i % encodedInputs.length]
        const type = types[i % types.length]
        const result = sanitizer.sanitize(input, { type })

        if (result.blocked) {
          blockedCount++
        }
      }

      const endTime = Date.now()
      const avgTime = (endTime - startTime) / ITERATION_COUNT

      console.log(`Encoded inputs: ${avgTime.toFixed(3)}ms per operation`)
      console.log(`Blocked ${blockedCount}/${ITERATION_COUNT} inputs as expected`)

      expect(avgTime).toBeLessThan(5) // Should handle decoding within reasonable time
      expect(blockedCount).toBeGreaterThan(ITERATION_COUNT * 0.8) // Should block most malicious inputs
    })

    it('should handle Unicode-encoded inputs efficiently', () => {
      const unicodeInputs = [
        '\\u002E\\u002E\\u002Fetc\\u002Fpasswd', // ../etc/passwd
        '\\u006A\\u0061\\u0076\\u0061\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074\\u003A\\u0061\\u006C\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029', // javascript:alert(1)
        'ls\\u003B\\u0020rm\\u0020-rf\\u0020\\u002F', // ls; rm -rf /
        'SELECT\\u0020\\u002A\\u0020FROM\\u0020users\\u003B\\u0020DROP\\u0020TABLE\\u0020users\\u003B' // SQL injection
      ]

      const types = ['file_path', 'url', 'command', 'sql']
      const startTime = Date.now()
      let blockedCount = 0

      for (let i = 0; i < ITERATION_COUNT; i++) {
        const input = unicodeInputs[i % unicodeInputs.length]
        const type = types[i % types.length]
        const result = sanitizer.sanitize(input, { type })

        if (result.blocked) {
          blockedCount++
        }
      }

      const endTime = Date.now()
      const avgTime = (endTime - startTime) / ITERATION_COUNT

      console.log(`Unicode inputs: ${avgTime.toFixed(3)}ms per operation`)
      console.log(`Blocked ${blockedCount}/${ITERATION_COUNT} inputs as expected`)

      expect(avgTime).toBeLessThan(5)
      expect(blockedCount).toBeGreaterThan(ITERATION_COUNT * 0.8)
    })

    it('should handle deeply nested encoding efficiently', () => {
      const deeplyEncoded = [
        '%25252E%25252E%25252Fetc%25252Fpasswd', // Triple URL encoded ../etc/passwd
        '\\u0025\\u0032\\u0045\\u0025\\u0032\\u0045\\u0025\\u0032\\u0046', // Mixed Unicode + URL encoding
        '%252A%2520FROM%2520users%253B%2520DROP', // Double encoded SQL
        'javascript%253A%2520alert%2528%25271%2527%2529' // Double encoded JS
      ]

      const types = ['file_path', 'file_path', 'sql', 'url']
      const startTime = Date.now()
      let blockedCount = 0

      for (let i = 0; i < ITERATION_COUNT / 4; i++) { // Fewer iterations for complex cases
        const input = deeplyEncoded[i % deeplyEncoded.length]
        const type = types[i % types.length]
        const result = sanitizer.sanitize(input, { type })

        if (result.blocked) {
          blockedCount++
        }
      }

      const endTime = Date.now()
      const avgTime = (endTime - startTime) / (ITERATION_COUNT / 4)

      console.log(`Deeply encoded inputs: ${avgTime.toFixed(3)}ms per operation`)
      console.log(`Blocked ${blockedCount}/${ITERATION_COUNT / 4} inputs as expected`)

      expect(avgTime).toBeLessThan(10) // More complex decoding may take longer
      expect(blockedCount).toBeGreaterThan((ITERATION_COUNT / 4) * 0.7)
    })
  })

  describe('Memory Usage', () => {
    it('should not leak memory during intensive processing', () => {
      const mixedInputs = [
        // Safe inputs
        'document.txt',
        'https://api.example.com/data',
        'ls documents',
        'SELECT * FROM users WHERE id = 1',
        // Encoded malicious inputs
        '%2E%2E%2Fetc%2Fpasswd',
        'javascript%3Aalert%281%29',
        'ls%3B%20rm%20-rf%20%2F',
        'SELECT%20%2A%20FROM%20users%3B%20DROP%20TABLE%20users%3B'
      ]

      const types = ['file_path', 'url', 'command', 'sql', 'file_path', 'url', 'command', 'sql']

      const initialMemory = process.memoryUsage()

      for (let i = 0; i < ITERATION_COUNT * 2; i++) {
        const input = mixedInputs[i % mixedInputs.length]
        const type = types[i % types.length]
        sanitizer.sanitize(input, { type })

        // Force garbage collection occasionally if available
        if (i % 100 === 0 && global.gc) {
          global.gc()
        }
      }

      const finalMemory = process.memoryUsage()
      const heapGrowth = finalMemory.heapUsed - initialMemory.heapUsed

      console.log(`Memory growth: ${(heapGrowth / 1024 / 1024).toFixed(2)}MB`)

      // Memory growth should be reasonable (less than 50MB for this test)
      expect(heapGrowth).toBeLessThan(50 * 1024 * 1024)
    })
  })

  describe('Statistical Performance Analysis', () => {
    it('should provide consistent performance characteristics', () => {
      const testCases = [
        { input: 'safe-file.txt', type: 'file_path', category: 'safe' },
        { input: '%2E%2E%2Fetc%2Fpasswd', type: 'file_path', category: 'encoded' },
        { input: 'https://api.example.com/data', type: 'url', category: 'safe' },
        { input: 'javascript%3Aalert%281%29', type: 'url', category: 'encoded' },
        { input: 'ls documents', type: 'command', category: 'safe' },
        { input: 'ls%3B%20rm%20-rf%20%2F', type: 'command', category: 'encoded' }
      ]

      const results = {}

      testCases.forEach(testCase => {
        const times = []

        for (let i = 0; i < 100; i++) {
          const startTime = Date.now()
          sanitizer.sanitize(testCase.input, { type: testCase.type })
          const endTime = Date.now()
          times.push(endTime - startTime)
        }

        const avg = times.reduce((a, b) => a + b, 0) / times.length
        const max = Math.max(...times)
        const min = Math.min(...times)
        const std = Math.sqrt(times.reduce((a, b) => a + (b - avg) ** 2, 0) / times.length)

        results[`${testCase.category}_${testCase.type}`] = { avg, max, min, std }
      })

      // Print performance statistics
      Object.entries(results).forEach(([key, stats]) => {
        console.log(`${key}: avg=${stats.avg.toFixed(2)}ms, max=${stats.max}ms, min=${stats.min}ms, std=${stats.std.toFixed(2)}ms`)
      })

      // Validate that safe inputs are consistently fast
      expect(results.safe_file_path.avg).toBeLessThan(2)
      expect(results.safe_url.avg).toBeLessThan(3)
      expect(results.safe_command.avg).toBeLessThan(2)

      // Validate that encoded inputs don't have excessive overhead
      expect(results.encoded_file_path.avg).toBeLessThan(5)
      expect(results.encoded_url.avg).toBeLessThan(8)
      expect(results.encoded_command.avg).toBeLessThan(5)
    })
  })

  describe('Performance Regression Detection', () => {
    it('should maintain performance standards', () => {
      // These benchmarks represent acceptable performance thresholds
      const performanceStandards = {
        safe_file_path: 2.0, // 2ms max average for safe file paths
        safe_url: 3.0, // 3ms max average for safe URLs
        safe_command: 2.0, // 2ms max average for safe commands
        encoded_file_path: 8.0, // 8ms max average for encoded file paths
        encoded_url: 10.0, // 10ms max average for encoded URLs
        encoded_command: 8.0 // 8ms max average for encoded commands
      }

      const testResults = {}

      // Test each category
      Object.keys(performanceStandards).forEach(category => {
        const [safety, type] = category.split('_')
        const input = safety === 'safe'
          ? { file_path: 'test.txt', url: 'https://api.example.com/data', command: 'ls test' }[type]
          : { file_path: '%2E%2E%2Fetc%2Fpasswd', url: 'javascript%3Aalert%281%29', command: 'ls%3B%20rm%20-rf%20%2F' }[type]

        const startTime = Date.now()
        for (let i = 0; i < 100; i++) {
          sanitizer.sanitize(input, { type })
        }
        const endTime = Date.now()

        testResults[category] = (endTime - startTime) / 100
      })

      // Validate against standards
      Object.entries(performanceStandards).forEach(([category, threshold]) => {
        const actualTime = testResults[category]
        console.log(`${category}: ${actualTime.toFixed(3)}ms (threshold: ${threshold}ms)`)
        expect(actualTime).toBeLessThan(threshold)
      })
    })
  })
})
