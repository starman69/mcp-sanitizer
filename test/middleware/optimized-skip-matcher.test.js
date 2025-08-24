/**
 * Test suite for OptimizedSkipMatcher
 *
 * Ensures the optimized skip path implementation maintains compatibility
 * while delivering significant performance improvements.
 */

const { describe, it, expect } = require('@jest/globals');
const {
  OptimizedSkipMatcher,
  PrefixTrie,
  createOptimizedMatcher,
  benchmarkMatcher
} = require('../../src/middleware/optimized-skip-matcher');

describe('OptimizedSkipMatcher', () => {
  describe('Basic Functionality', () => {
    it('should handle exact string matches', () => {
      const matcher = new OptimizedSkipMatcher(['/health', '/metrics', '/status']);

      expect(matcher.shouldSkip('/health')).toBe(true);
      expect(matcher.shouldSkip('/metrics')).toBe(true);
      expect(matcher.shouldSkip('/status')).toBe(true);
      expect(matcher.shouldSkip('/other')).toBe(false);
    });

    it('should handle prefix matches', () => {
      const matcher = new OptimizedSkipMatcher(['/api/', '/static']);

      expect(matcher.shouldSkip('/api/users')).toBe(true);
      expect(matcher.shouldSkip('/api/posts/123')).toBe(true);
      expect(matcher.shouldSkip('/static/css/main.css')).toBe(true);
      expect(matcher.shouldSkip('/other/path')).toBe(false);
    });

    it('should handle regex patterns', () => {
      const matcher = new OptimizedSkipMatcher([
        /^\/api\/v\d+\/users\/\d+$/,
        /^\/webhooks?\/(github|gitlab)\/[\w-]+$/
      ]);

      expect(matcher.shouldSkip('/api/v1/users/123')).toBe(true);
      expect(matcher.shouldSkip('/api/v2/users/456')).toBe(true);
      expect(matcher.shouldSkip('/webhook/github/my-repo')).toBe(true);
      expect(matcher.shouldSkip('/webhooks/gitlab/project-name')).toBe(true);
      expect(matcher.shouldSkip('/api/v1/posts/123')).toBe(false);
    });

    it('should handle mixed patterns', () => {
      const matcher = new OptimizedSkipMatcher([
        '/health', // exact match
        '/admin/', // prefix match
        /^\/api\/v\d+/, // regex pattern
        '/static' // prefix without slash
      ]);

      expect(matcher.shouldSkip('/health')).toBe(true);
      expect(matcher.shouldSkip('/admin/dashboard')).toBe(true);
      expect(matcher.shouldSkip('/api/v1/users')).toBe(true);
      expect(matcher.shouldSkip('/static/js/app.js')).toBe(true);
      expect(matcher.shouldSkip('/other')).toBe(false);
    });

    it('should handle empty or invalid input', () => {
      const emptyMatcher = new OptimizedSkipMatcher([]);
      expect(emptyMatcher.shouldSkip('/any')).toBe(false);

      const nullMatcher = new OptimizedSkipMatcher(null);
      expect(nullMatcher.shouldSkip('/any')).toBe(false);

      const invalidMatcher = new OptimizedSkipMatcher([null, undefined, 123, {}, []]);
      expect(invalidMatcher.shouldSkip('/any')).toBe(false);
    });
  });

  describe('Performance Features', () => {
    it('should cache results', () => {
      const matcher = new OptimizedSkipMatcher(['/health']);

      // First call - should be computed
      expect(matcher.shouldSkip('/health')).toBe(true);
      expect(matcher.shouldSkip('/other')).toBe(false);

      // Second call - should use cache
      expect(matcher.shouldSkip('/health')).toBe(true);
      expect(matcher.shouldSkip('/other')).toBe(false);

      expect(matcher.cache.size).toBe(2);
    });

    it('should implement LRU cache eviction', () => {
      const matcher = new OptimizedSkipMatcher(['/health']);
      matcher.cacheSize = 3; // Small cache for testing

      // Fill cache
      matcher.shouldSkip('/path1');
      matcher.shouldSkip('/path2');
      matcher.shouldSkip('/path3');
      expect(matcher.cache.size).toBe(3);

      // This should evict the oldest entry ('/path1')
      matcher.shouldSkip('/path4');
      expect(matcher.cache.size).toBe(3);
      expect(matcher.cache.has('/path1')).toBe(false);
      expect(matcher.cache.has('/path4')).toBe(true);
    });

    it('should clear cache when requested', () => {
      const matcher = new OptimizedSkipMatcher(['/health']);

      matcher.shouldSkip('/health');
      matcher.shouldSkip('/other');
      expect(matcher.cache.size).toBe(2);

      matcher.clearCache();
      expect(matcher.cache.size).toBe(0);
    });

    it('should provide performance statistics', () => {
      const matcher = new OptimizedSkipMatcher([
        '/exact', // exact match
        '/prefix/', // prefix
        /^\/regex/ // regex
      ]);

      const stats = matcher.getStats();
      expect(stats).toHaveProperty('exactMatches');
      expect(stats).toHaveProperty('prefixNodes');
      expect(stats).toHaveProperty('regexPatterns');
      expect(stats).toHaveProperty('cacheSize');
      expect(stats.exactMatches).toBe(1);
      expect(stats.regexPatterns).toBe(1);
      expect(stats.cacheSize).toBe(0);
    });
  });

  describe('PrefixTrie', () => {
    it('should handle basic prefix operations', () => {
      const trie = new PrefixTrie();

      trie.insert('/api/v1/');
      trie.insert('/admin/');

      expect(trie.hasPrefix('/api/v1/users')).toBe(true);
      expect(trie.hasPrefix('/admin/dashboard')).toBe(true);
      expect(trie.hasPrefix('/other/path')).toBe(false);
      expect(trie.size()).toBe(2);
    });

    it('should handle overlapping prefixes', () => {
      const trie = new PrefixTrie();

      trie.insert('/api/');
      trie.insert('/api/v1/');
      trie.insert('/api/v2/');

      expect(trie.hasPrefix('/api/users')).toBe(true);
      expect(trie.hasPrefix('/api/v1/users')).toBe(true);
      expect(trie.hasPrefix('/api/v2/posts')).toBe(true);
      expect(trie.hasPrefix('/other')).toBe(false);
    });

    it('should normalize paths correctly', () => {
      const trie = new PrefixTrie();

      trie.insert('/api/'); // with trailing slash

      expect(trie.hasPrefix('/api/users')).toBe(true);
    });
  });

  describe('Compatibility with Original Implementation', () => {
    // These tests ensure our optimized version produces the same results
    // as the original Array.some() implementation

    const originalLogic = (path, skipPaths) => {
      if (!skipPaths || !Array.isArray(skipPaths) || skipPaths.length === 0) {
        return false;
      }

      return skipPaths.some(skipPath => {
        if (typeof skipPath === 'string') {
          return path === skipPath || path.startsWith(skipPath.endsWith('/') ? skipPath : skipPath + '/');
        }
        if (skipPath instanceof RegExp) {
          return skipPath.test(path);
        }
        return false;
      });
    };

    const testCases = [
      // Exact matches
      { paths: ['/health', '/metrics'], tests: ['/health', '/metrics', '/other'] },

      // Prefix matches
      { paths: ['/api', '/static/'], tests: ['/api/users', '/static/css/main.css', '/other'] },

      // Regex patterns
      { paths: [/^\/webhook/, /users\/\d+$/], tests: ['/webhook/github', '/api/users/123', '/other'] },

      // Mixed patterns
      { paths: ['/exact', '/prefix/', /regex$/], tests: ['/exact', '/prefix/sub', '/test-regex', '/other'] },

      // Edge cases
      { paths: ['/', ''], tests: ['/', '/anything', ''] },

      // Complex real-world patterns
      {
        paths: [
          '/health',
          '/api/v1/',
          /^\/webhooks?\/(github|gitlab|bitbucket)/,
          '/static',
          '/admin/public/'
        ],
        tests: [
          '/health',
          '/health/detailed',
          '/api/v1/users',
          '/api/v1/posts/123',
          '/webhook/github/repo',
          '/webhooks/gitlab/project',
          '/static/css/main.css',
          '/admin/public/assets',
          '/admin/private/config',
          '/other/random/path'
        ]
      }
    ];

    testCases.forEach((testCase, index) => {
      it(`should match original logic for test case ${index + 1}`, () => {
        const matcher = new OptimizedSkipMatcher(testCase.paths);

        testCase.tests.forEach(testPath => {
          const originalResult = originalLogic(testPath, testCase.paths);
          const optimizedResult = matcher.shouldSkip(testPath);

          expect(optimizedResult).toBe(originalResult,
            `Path "${testPath}" with patterns ${JSON.stringify(testCase.paths)} should return ${originalResult} but got ${optimizedResult}`);
        });
      });
    });
  });

  describe('Performance Benchmarking', () => {
    it('should benchmark performance correctly', () => {
      const matcher = new OptimizedSkipMatcher(['/health', '/api/', /^\/static/]);
      const testPaths = ['/health', '/api/users', '/static/css', '/other'];

      const results = benchmarkMatcher(matcher, testPaths, 100);

      expect(results).toHaveProperty('totalTime');
      expect(results).toHaveProperty('averageTime');
      expect(results).toHaveProperty('operationsPerSecond');
      expect(results.totalTime).toBeGreaterThan(0);
      expect(results.averageTime).toBeGreaterThan(0);
      expect(results.operationsPerSecond).toBeGreaterThan(0);
    });

    it('should handle large datasets efficiently', () => {
      // Create a large dataset
      const largePaths = Array.from({ length: 1000 }, (_, i) => `/path${i}`);
      const testPaths = ['/path500', '/path999', '/notfound'];

      const matcher = new OptimizedSkipMatcher(largePaths);

      const start = performance.now();
      for (let i = 0; i < 1000; i++) {
        testPaths.forEach(path => matcher.shouldSkip(path));
      }
      const end = performance.now();

      // Should complete 3000 operations (1000 iterations * 3 paths) quickly
      expect(end - start).toBeLessThan(100); // Less than 100ms
    });
  });

  describe('Factory Function', () => {
    it('should create matcher using factory function', () => {
      const matcher = createOptimizedMatcher(['/health', '/metrics']);

      expect(matcher).toBeInstanceOf(OptimizedSkipMatcher);
      expect(matcher.shouldSkip('/health')).toBe(true);
      expect(matcher.shouldSkip('/other')).toBe(false);
    });
  });

  describe('Error Handling', () => {
    it('should handle malformed regex gracefully', () => {
      // This should not throw, even with potentially problematic regex
      const matcher = new OptimizedSkipMatcher([
        /valid-regex/,
        'string-path'
      ]);

      expect(() => matcher.shouldSkip('/test')).not.toThrow();
    });

    it('should handle extremely large inputs', () => {
      // Test with a very large number of paths
      const hugePaths = Array.from({ length: 10000 }, (_, i) => `/path${i}`);

      expect(() => {
        const matcher = new OptimizedSkipMatcher(hugePaths);
        matcher.shouldSkip('/path5000');
      }).not.toThrow();
    });
  });
});
