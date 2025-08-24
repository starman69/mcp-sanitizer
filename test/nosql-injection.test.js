/**
 * Comprehensive NoSQL Injection Detection Tests
 * 
 * Tests all NoSQL injection vectors to ensure >95% protection rate
 * Covers MongoDB, CouchDB, Redis, Cassandra, and JavaScript injection
 */

const {
  detectNoSQLInjection,
  hasNoSQLInjection,
  hasNoSQLInjectionForDB,
  detectBulkNoSQLInjection,
  NoSQLValidator,
  SEVERITY_LEVELS,
  NOSQL_TYPES,
  getMongoDBOperators
} = require('../src/patterns/nosql-injection')

describe('NoSQL Injection Detection', () => {
  let validator

  beforeEach(() => {
    validator = new NoSQLValidator()
  })

  describe('MongoDB Injection Detection', () => {
    test('should detect $where JavaScript injection', () => {
      const maliciousQuery = '{"$where": "this.username == this.password"}'
      const result = detectNoSQLInjection(maliciousQuery)
      
      expect(result.detected).toBe(true)
      expect(result.severity).toBe(SEVERITY_LEVELS.CRITICAL)
      expect(result.nosqlType).toBe(NOSQL_TYPES.MONGODB)
      expect(result.vulnerabilities.some(v => v.codeExecution)).toBe(true)
    })

    test('should detect authentication bypass operators', () => {
      const testCases = [
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
        '{"username": {"$exists": true}, "password": {"$exists": true}}'
      ]

      testCases.forEach(query => {
        const result = detectNoSQLInjection(query)
        expect(result.detected).toBe(true)
        expect(result.severity).toBe(SEVERITY_LEVELS.HIGH)
        expect(result.vulnerabilities.some(v => v.authBypass)).toBe(true)
      })
    })

    test('should detect regex injection with ReDoS potential', () => {
      const regexQuery = '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}'
      const result = detectNoSQLInjection(regexQuery)
      
      expect(result.detected).toBe(true)
      expect(result.severity).toBe(SEVERITY_LEVELS.HIGH)
      expect(result.vulnerabilities.some(v => v.type === 'nosql_operator')).toBe(true)
    })

    test('should detect complex ReDoS patterns', () => {
      const complexRegex = '{"field": {"$regex": "(a+)+b"}}'
      const result = detectNoSQLInjection(complexRegex)
      
      expect(result.detected).toBe(true)
      const regexVuln = result.vulnerabilities.find(v => v.operator === '$regex')
      expect(regexVuln.redosRisk).toBe(true)
    })

    test('should detect JavaScript sleep/timing attacks', () => {
      const timingAttacks = [
        '{"$where": "sleep(5000) || true"}',
        '{"$where": "function() { var d = new Date(); while ((new Date() - d) < 5000); return true; }"}',
        '{"$where": "setTimeout(function(){}, 5000) || true"}'
      ]

      timingAttacks.forEach(attack => {
        const result = detectNoSQLInjection(attack)
        expect(result.detected).toBe(true)
        expect(result.severity).toBe(SEVERITY_LEVELS.CRITICAL)
      })
    })

    test('should detect logical operator injection', () => {
      const logicalQueries = [
        '{"$or": [{"username": "admin"}, {"role": "admin"}]}',
        '{"$and": [{"active": true}, {"$where": "1==1"}]}',
        '{"$nor": [{"deleted": true}]}'
      ]

      logicalQueries.forEach(query => {
        const result = detectNoSQLInjection(query)
        expect(result.detected).toBe(true)
      })
    })

    test('should detect array operator injection', () => {
      const arrayQueries = [
        '{"username": {"$in": ["admin", "root", "administrator"]}}',
        '{"permissions": {"$all": ["read", "write", "admin"]}}',
        '{"tags": {"$size": 0}}'
      ]

      arrayQueries.forEach(query => {
        const result = detectNoSQLInjection(query)
        expect(result.detected).toBe(true)
      })
    })

    test('should detect evaluation operators', () => {
      const evalQueries = [
        '{"$expr": {"$eq": ["$username", "$password"]}}',
        '{"age": {"$mod": [10, 0]}}',
        '{"$text": {"$search": "malicious"}}'
      ]

      evalQueries.forEach(query => {
        const result = detectNoSQLInjection(query)
        expect(result.detected).toBe(true)
      })
    })
  })

  describe('CouchDB Injection Detection', () => {
    test('should detect CouchDB selector injection', () => {
      const couchQuery = '{"selector": {"_id": {"$gt": null}}}'
      const result = detectNoSQLInjection(couchQuery)
      
      expect(result.detected).toBe(true)
      expect(result.nosqlType).toBe(NOSQL_TYPES.MONGODB) // CouchDB uses similar operators
    })

    test('should detect CouchDB Mango query patterns', () => {
      const mangoQueries = [
        '{"selector": {"username": {"$regex": ".*"}}}',
        '{"selector": {"type": {"$exists": true}}}',
        '{"selector": {"$or": [{"role": "admin"}]}}'
      ]

      mangoQueries.forEach(query => {
        const result = detectNoSQLInjection(query)
        expect(result.detected).toBe(true)
      })
    })
  })

  describe('Redis Injection Detection', () => {
    test('should detect dangerous Redis commands', () => {
      const redisCommands = [
        'EVAL "redis.call(\'flushall\')" 0',
        'EVAL "return redis.call(\'get\', \'sensitive_key\')" 0',
        'FLUSHALL',
        'CONFIG SET',
        'SCRIPT LOAD "return redis.call(\'auth\', \'password\')"'
      ]

      redisCommands.forEach(command => {
        const result = detectNoSQLInjection(command)
        expect(result.detected).toBe(true)
        expect(result.nosqlType).toBe(NOSQL_TYPES.REDIS)
        expect(result.severity).toBeOneOf([SEVERITY_LEVELS.HIGH, SEVERITY_LEVELS.CRITICAL])
      })
    })

    test('should detect Lua script injection', () => {
      const luaInjection = 'EVAL "local result = redis.call(\'keys\', \'*\'); return result" 0'
      const result = detectNoSQLInjection(luaInjection)
      
      expect(result.detected).toBe(true)
      expect(result.vulnerabilities.some(v => v.codeExecution)).toBe(true)
    })

    test('should detect Redis pub/sub injection', () => {
      const pubsubCommands = [
        'PUBLISH sensitive-channel "malicious data"',
        'SUBSCRIBE admin-channel',
        'PSUBSCRIBE *'
      ]

      pubsubCommands.forEach(command => {
        const result = detectNoSQLInjection(command)
        expect(result.detected).toBe(true)
      })
    })
  })

  describe('Cassandra CQL Injection Detection', () => {
    test('should detect dangerous CQL patterns', () => {
      const cqlQueries = [
        'SELECT * FROM users WHERE token(id) > token(?)',
        'SELECT * FROM users ALLOW FILTERING',
        'TRUNCATE users',
        'DROP TABLE sensitive_data',
        'ALTER TABLE users ADD COLUMN admin boolean'
      ]

      cqlQueries.forEach(query => {
        const result = detectNoSQLInjection(query)
        expect(result.detected).toBe(true)
        expect(result.nosqlType).toBe(NOSQL_TYPES.CASSANDRA)
      })
    })

    test('should detect CQL batch injection', () => {
      const batchQuery = `
        BEGIN BATCH
          INSERT INTO users (id, name) VALUES (1, 'admin');
          UPDATE users SET role = 'admin' WHERE id = 1;
        APPLY BATCH;
      `
      const result = detectNoSQLInjection(batchQuery)
      expect(result.detected).toBe(true)
    })
  })

  describe('JavaScript Injection in NoSQL', () => {
    test('should detect dangerous JavaScript patterns', () => {
      const jsPatterns = [
        'function() { require("child_process").exec("rm -rf /"); }',
        'function() { process.exit(1); }',
        'function() { eval("malicious code"); }',
        'this.constructor.constructor("return process")().exit()',
        'function() { global.process.mainModule.require("fs").readFileSync("/etc/passwd"); }'
      ]

      jsPatterns.forEach(pattern => {
        const query = `{"$where": "${pattern}"}`
        const result = detectNoSQLInjection(query)
        expect(result.detected).toBe(true)
        expect(result.severity).toBe(SEVERITY_LEVELS.CRITICAL)
      })
    })

    test('should detect Server-Side JavaScript (SSJS) injection', () => {
      const ssjsPatterns = [
        '"; var date = new Date(); do { curDate = new Date(); } while(curDate-date<5000); "',
        '\'; db.users.drop(); //',
        '"; this.constructor.constructor("return process")().exit(); //'
      ]

      ssjsPatterns.forEach(pattern => {
        const result = detectNoSQLInjection(pattern)
        expect(result.detected).toBe(true)
      })
    })
  })

  describe('Nested Object Detection', () => {
    test('should detect injection in deeply nested objects', () => {
      const nestedQuery = {
        user: {
          profile: {
            settings: {
              query: {
                $where: 'this.password === "admin"'
              }
            }
          }
        }
      }

      const result = detectNoSQLInjection(nestedQuery)
      expect(result.detected).toBe(true)
    })

    test('should handle maximum depth limits', () => {
      // Create deeply nested object
      let deepObject = { $where: 'malicious' }
      for (let i = 0; i < 15; i++) {
        deepObject = { nested: deepObject }
      }

      const result = detectNoSQLInjection(deepObject, { maxDepth: 10 })
      expect(result.detected).toBe(true)
      expect(result.vulnerabilities.some(v => v.type === 'depth_limit_exceeded')).toBe(true)
    })

    test('should detect operators in arrays', () => {
      const arrayQuery = {
        $or: [
          { username: 'admin' },
          { $where: 'true' },
          { role: { $ne: null } }
        ]
      }

      const result = detectNoSQLInjection(arrayQuery)
      expect(result.detected).toBe(true)
      expect(result.patterns.length).toBeGreaterThan(2)
    })
  })

  describe('String-based NoSQL Detection', () => {
    test('should detect operators in string format', () => {
      const stringQueries = [
        'username[$ne]=null&password[$ne]=null',
        'user[$where]=this.username==this.password',
        'filter[$regex]=.*admin.*',
        'sort[$exists]=true'
      ]

      stringQueries.forEach(query => {
        const result = detectNoSQLInjection(query)
        expect(result.detected).toBe(true)
      })
    })

    test('should detect boolean injection attempts', () => {
      const booleanInjections = [
        'true, $where: \'1 == 1\'',
        'admin\', $where: \'1 == 1\', a: \'a',
        'false; return true; //'
      ]

      booleanInjections.forEach(injection => {
        const result = detectNoSQLInjection(injection)
        expect(result.detected).toBe(true)
      })
    })
  })

  describe('Performance and Edge Cases', () => {
    test('should process large objects within time limit', () => {
      const largeObject = {}
      for (let i = 0; i < 50; i++) {
        largeObject[`field${i}`] = { value: `data${i}`, nested: { more: 'data' } }
      }
      largeObject.$where = 'malicious'

      const result = detectNoSQLInjection(largeObject)
      expect(result.detected).toBe(true)
      expect(result.performance.detectionTime).toBeLessThan(5) // <5ms requirement
    })

    test('should handle malformed JSON gracefully', () => {
      const malformedInputs = [
        '{"$where": function() { return true; }', // Missing closing brace
        '{$where: "this.username"', // Invalid JSON
        '{"$where":}', // Missing value
        null,
        undefined,
        ''
      ]

      malformedInputs.forEach(input => {
        const result = detectNoSQLInjection(input)
        expect(result).toBeDefined()
        // Should not throw errors
      })
    })

    test('should detect mixed injection types', () => {
      const mixedQuery = {
        mongodb: { $where: 'sleep(5000)' },
        redis: 'EVAL "redis.call(\'flushall\')" 0',
        cassandra: 'SELECT * FROM users ALLOW FILTERING'
      }

      const result = detectNoSQLInjection(mixedQuery)
      expect(result.detected).toBe(true)
      expect(result.patterns.length).toBeGreaterThan(3)
    })
  })

  describe('Utility Functions', () => {
    test('hasNoSQLInjection should return boolean', () => {
      expect(hasNoSQLInjection('{"$where": "true"}')).toBe(true)
      expect(hasNoSQLInjection('{"username": "admin"}')).toBe(false)
    })

    test('hasNoSQLInjectionForDB should detect specific database types', () => {
      expect(hasNoSQLInjectionForDB('{"$where": "true"}', NOSQL_TYPES.MONGODB)).toBe(true)
      expect(hasNoSQLInjectionForDB('FLUSHALL', NOSQL_TYPES.REDIS)).toBe(true)
      expect(hasNoSQLInjectionForDB('ALLOW FILTERING', NOSQL_TYPES.CASSANDRA)).toBe(true)
    })

    test('detectBulkNoSQLInjection should process arrays', () => {
      const inputs = [
        '{"$where": "true"}',
        '{"username": "admin"}',
        'FLUSHALL',
        'SELECT * FROM users ALLOW FILTERING'
      ]

      const results = detectBulkNoSQLInjection(inputs)
      expect(results).toHaveLength(4)
      expect(results.filter(r => r.detected)).toHaveLength(3)
    })

    test('getMongoDBOperators should return all operators', () => {
      const operators = getMongoDBOperators()
      expect(operators).toContain('$where')
      expect(operators).toContain('$regex')
      expect(operators).toContain('$ne')
      expect(operators.length).toBeGreaterThan(40)
    })
  })

  describe('Real-World Attack Scenarios', () => {
    test('should detect authentication bypass scenario', () => {
      // Common MongoDB authentication bypass
      const loginBypass = {
        username: { $ne: null },
        password: { $ne: null }
      }

      const result = detectNoSQLInjection(loginBypass)
      expect(result.detected).toBe(true)
      expect(result.severity).toBe(SEVERITY_LEVELS.HIGH)
      expect(result.vulnerabilities.some(v => v.authBypass)).toBe(true)
    })

    test('should detect timing attack scenario', () => {
      // MongoDB timing attack using $where
      const timingAttack = {
        $where: 'sleep(Math.floor(Math.random() * 1000) + 5000) || true'
      }

      const result = detectNoSQLInjection(timingAttack)
      expect(result.detected).toBe(true)
      expect(result.severity).toBe(SEVERITY_LEVELS.CRITICAL)
    })

    test('should detect data extraction scenario', () => {
      // CouchDB data extraction
      const dataExtraction = {
        selector: {
          _id: { $gt: null }
        },
        limit: 999999
      }

      const result = detectNoSQLInjection(dataExtraction)
      expect(result.detected).toBe(true)
    })

    test('should detect DoS attack scenario', () => {
      // Redis DoS attack
      const dosAttack = 'EVAL "while true do end" 0'
      
      const result = detectNoSQLInjection(dosAttack)
      expect(result.detected).toBe(true)
      expect(result.severity).toBe(SEVERITY_LEVELS.CRITICAL)
    })
  })

  describe('Configuration Options', () => {
    test('should respect strict mode', () => {
      const strictValidator = new NoSQLValidator({ strictMode: true })
      
      // In strict mode, even less dangerous operators should be flagged
      const result = strictValidator.detect({ field: { $exists: true } })
      expect(result.detected).toBe(true)
    })

    test('should respect disabled detection options', () => {
      const limitedValidator = new NoSQLValidator({
        enableJavaScriptDetection: false,
        enableCommandDetection: false
      })

      const jsResult = limitedValidator.detect('{"$where": "sleep(5000)"}')
      expect(jsResult.vulnerabilities.some(v => v.type === 'javascript_injection')).toBe(false)

      const cmdResult = limitedValidator.detect('FLUSHALL')
      expect(cmdResult.vulnerabilities.some(v => v.type === 'redis_command_injection')).toBe(false)
    })

    test('should handle custom max keys limit', () => {
      const limitedValidator = new NoSQLValidator({ maxKeys: 5 })
      
      const largeObject = {}
      for (let i = 0; i < 10; i++) {
        largeObject[`key${i}`] = 'value'
      }

      const result = limitedValidator.detect(largeObject)
      expect(result.vulnerabilities.some(v => v.type === 'key_limit_exceeded')).toBe(true)
    })
  })
})

// Custom Jest matcher for severity levels
expect.extend({
  toBeOneOf(received, array) {
    const pass = array.includes(received)
    if (pass) {
      return {
        message: () => `expected ${received} not to be one of ${array.join(', ')}`,
        pass: true,
      }
    } else {
      return {
        message: () => `expected ${received} to be one of ${array.join(', ')}`,
        pass: false,
      }
    }
  }
})