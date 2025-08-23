#!/usr/bin/env node

/**
 * Basic MCP-Style Server Example with Sanitization
 * 
 * This example demonstrates how to integrate MCP Sanitizer into a server
 * that follows MCP patterns without requiring the full MCP SDK.
 * 
 * It shows the security patterns you should use when building MCP tools
 * that handle file operations, commands, and other potentially dangerous inputs.
 * 
 * Usage: node examples/mcp-server-basic.js
 */

const MCPSanitizer = require('../src/index');
const readline = require('readline');
const fs = require('fs').promises;
const path = require('path');
const https = require('https');

// Initialize sanitizer with PRODUCTION policy for maximum security
const sanitizer = new MCPSanitizer('PRODUCTION');

// Create readline interface for interactive testing
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// Simulated MCP tools with security
const tools = {
  read_file: {
    description: 'Read a file with path sanitization',
    handler: async (args) => {
      // Sanitize the file path
      const result = sanitizer.sanitize(args.path, { type: 'file_path' });
      
      if (result.blocked) {
        return {
          error: true,
          message: 'Path blocked by security policy',
          warnings: result.warnings
        };
      }

      // Additional security: ensure path is within current directory
      const resolvedPath = path.resolve(result.sanitized);
      const baseDir = path.resolve(process.cwd());
      
      if (!resolvedPath.startsWith(baseDir)) {
        return {
          error: true,
          message: 'Access denied: Path outside allowed directory'
        };
      }

      try {
        const content = await fs.readFile(resolvedPath, 'utf-8');
        return {
          success: true,
          content: content.substring(0, 1000) // Limit output
        };
      } catch (error) {
        return {
          error: true,
          message: `File read error: ${error.message}`
        };
      }
    }
  },

  list_directory: {
    description: 'List files in a directory with path sanitization',
    handler: async (args) => {
      // Sanitize the directory path
      const result = sanitizer.sanitize(args.path, { type: 'file_path' });
      
      if (result.blocked) {
        return {
          error: true,
          message: 'Path blocked by security policy',
          warnings: result.warnings
        };
      }

      // Security check
      const resolvedPath = path.resolve(result.sanitized || '.');
      const baseDir = path.resolve(process.cwd());
      
      if (!resolvedPath.startsWith(baseDir)) {
        return {
          error: true,
          message: 'Access denied: Path outside allowed directory'
        };
      }

      try {
        const files = await fs.readdir(resolvedPath);
        return {
          success: true,
          files: files.slice(0, 50) // Limit results
        };
      } catch (error) {
        return {
          error: true,
          message: `Directory list error: ${error.message}`
        };
      }
    }
  },

  validate_url: {
    description: 'Validate and sanitize a URL',
    handler: async (args) => {
      // Sanitize the URL
      const result = sanitizer.sanitize(args.url, { type: 'url' });
      
      if (result.blocked) {
        return {
          error: true,
          message: 'URL blocked by security policy',
          warnings: result.warnings
        };
      }

      try {
        const urlObj = new URL(result.sanitized);
        
        // Additional security checks
        const blockedHosts = ['169.254.169.254', 'metadata.google.internal', 'localhost', '127.0.0.1'];
        if (blockedHosts.includes(urlObj.hostname)) {
          return {
            error: true,
            message: 'Access to internal/metadata endpoints blocked'
          };
        }

        return {
          success: true,
          sanitized_url: result.sanitized,
          protocol: urlObj.protocol,
          hostname: urlObj.hostname,
          safe: true
        };
      } catch (error) {
        return {
          error: true,
          message: `Invalid URL: ${error.message}`
        };
      }
    }
  },

  validate_command: {
    description: 'Validate a command for security issues',
    handler: async (args) => {
      // Sanitize the command
      const result = sanitizer.sanitize(args.command, { type: 'command' });
      
      if (result.blocked) {
        return {
          error: true,
          message: 'Command blocked by security policy',
          warnings: result.warnings,
          dangerous: true
        };
      }

      return {
        success: true,
        message: 'Command appears safe',
        sanitized: result.sanitized,
        safe: true
      };
    }
  },

  validate_sql: {
    description: 'Validate SQL query for injection attempts',
    handler: async (args) => {
      // Sanitize the SQL query
      const result = sanitizer.sanitize(args.query, { type: 'sql' });
      
      if (result.blocked) {
        return {
          error: true,
          message: 'SQL query blocked by security policy',
          warnings: result.warnings,
          injection_detected: true
        };
      }

      return {
        success: true,
        message: 'SQL query appears safe',
        sanitized: result.sanitized,
        safe: true
      };
    }
  },

  test_attack_vectors: {
    description: 'Test common attack vectors',
    handler: async () => {
      const attacks = [
        { type: 'file_path', input: '../../../etc/passwd', name: 'Path Traversal' },
        { type: 'file_path', input: '\\u002e\\u002e\\u002f\\u0065\\u0074\\u0063\\u002f\\u0070\\u0061\\u0073\\u0073\\u0077\\u0064', name: 'Unicode Path' },
        { type: 'command', input: 'ls; cat /etc/passwd', name: 'Command Injection' },
        { type: 'command', input: '\\u0063\\u0061\\u0074\\u0020\\u002f\\u0065\\u0074\\u0063\\u002f\\u0070\\u0061\\u0073\\u0073\\u0077\\u0064', name: 'Unicode Command' },
        { type: 'sql', input: "' OR 1=1 --", name: 'SQL Injection' },
        { type: 'url', input: 'javascript:alert(1)', name: 'XSS URL' },
        { type: 'file_path', input: 'C:\\Windows\\System32\\config\\sam', name: 'Windows System Path' },
        { type: 'file_path', input: '\\\\attacker.com\\share\\evil', name: 'UNC Path' }
      ];

      const results = attacks.map(attack => {
        const result = sanitizer.sanitize(attack.input, { type: attack.type });
        return {
          attack: attack.name,
          input: attack.input,
          blocked: result.blocked,
          status: result.blocked ? '✅ BLOCKED' : '❌ PASSED'
        };
      });

      const blocked = results.filter(r => r.blocked).length;
      const total = results.length;

      return {
        success: true,
        results,
        summary: {
          total_attacks: total,
          blocked: blocked,
          passed: total - blocked,
          security_score: `${Math.round(blocked / total * 100)}%`
        }
      };
    }
  }
};

// Interactive command processor
async function processCommand(input) {
  const parts = input.trim().split(' ');
  const command = parts[0];
  
  if (command === 'help') {
    console.log('\n📚 Available Commands:');
    console.log('  help                          - Show this help');
    console.log('  list                          - List available tools');
    console.log('  test                          - Run security test suite');
    console.log('  read <path>                   - Read a file');
    console.log('  ls [path]                     - List directory');
    console.log('  url <url>                     - Validate URL');
    console.log('  cmd <command>                 - Validate command');
    console.log('  sql <query>                   - Validate SQL query');
    console.log('  exit                          - Exit the server');
    console.log('\n💡 Examples:');
    console.log('  read package.json');
    console.log('  ls examples');
    console.log('  url https://example.com');
    console.log('  cmd "ls -la"');
    console.log('  sql "SELECT * FROM users"');
    return;
  }

  if (command === 'list') {
    console.log('\n🛠️  Available Tools:');
    Object.entries(tools).forEach(([name, tool]) => {
      console.log(`  ${name}: ${tool.description}`);
    });
    return;
  }

  if (command === 'test') {
    console.log('\n🔒 Running Security Tests...\n');
    const result = await tools.test_attack_vectors.handler();
    
    result.results.forEach(r => {
      console.log(`  ${r.status} ${r.attack}`);
      console.log(`      Input: ${r.input.substring(0, 50)}...`);
    });
    
    console.log('\n📊 Security Summary:');
    console.log(`  Total Attacks: ${result.summary.total_attacks}`);
    console.log(`  Blocked: ${result.summary.blocked}`);
    console.log(`  Passed: ${result.summary.passed}`);
    console.log(`  Security Score: ${result.summary.security_score}`);
    return;
  }

  if (command === 'read') {
    const filePath = parts.slice(1).join(' ');
    if (!filePath) {
      console.log('❌ Error: Please provide a file path');
      return;
    }
    const result = await tools.read_file.handler({ path: filePath });
    if (result.error) {
      console.log(`❌ Error: ${result.message}`);
      if (result.warnings) {
        console.log(`   Warnings: ${result.warnings.join(', ')}`);
      }
    } else {
      console.log(`✅ File content:\n${result.content}`);
    }
    return;
  }

  if (command === 'ls') {
    const dirPath = parts.slice(1).join(' ') || '.';
    const result = await tools.list_directory.handler({ path: dirPath });
    if (result.error) {
      console.log(`❌ Error: ${result.message}`);
      if (result.warnings) {
        console.log(`   Warnings: ${result.warnings.join(', ')}`);
      }
    } else {
      console.log(`✅ Files in ${dirPath}:`);
      result.files.forEach(file => console.log(`   ${file}`));
    }
    return;
  }

  if (command === 'url') {
    const url = parts.slice(1).join(' ');
    if (!url) {
      console.log('❌ Error: Please provide a URL');
      return;
    }
    const result = await tools.validate_url.handler({ url });
    if (result.error) {
      console.log(`❌ Error: ${result.message}`);
      if (result.warnings) {
        console.log(`   Warnings: ${result.warnings.join(', ')}`);
      }
    } else {
      console.log(`✅ URL is safe`);
      console.log(`   Sanitized: ${result.sanitized_url}`);
      console.log(`   Protocol: ${result.protocol}`);
      console.log(`   Hostname: ${result.hostname}`);
    }
    return;
  }

  if (command === 'cmd') {
    const cmd = parts.slice(1).join(' ');
    if (!cmd) {
      console.log('❌ Error: Please provide a command');
      return;
    }
    const result = await tools.validate_command.handler({ command: cmd });
    if (result.error) {
      console.log(`❌ DANGEROUS: ${result.message}`);
      if (result.warnings) {
        console.log(`   Warnings: ${result.warnings.join(', ')}`);
      }
    } else {
      console.log(`✅ Command appears safe`);
      console.log(`   Sanitized: ${result.sanitized}`);
    }
    return;
  }

  if (command === 'sql') {
    const query = parts.slice(1).join(' ');
    if (!query) {
      console.log('❌ Error: Please provide a SQL query');
      return;
    }
    const result = await tools.validate_sql.handler({ query });
    if (result.error) {
      console.log(`❌ SQL INJECTION DETECTED: ${result.message}`);
      if (result.warnings) {
        console.log(`   Warnings: ${result.warnings.join(', ')}`);
      }
    } else {
      console.log(`✅ SQL query appears safe`);
      console.log(`   Sanitized: ${result.sanitized}`);
    }
    return;
  }

  if (command === 'exit') {
    console.log('👋 Goodbye!');
    process.exit(0);
  }

  console.log(`❌ Unknown command: ${command}`);
  console.log('Type "help" for available commands');
}

// Main function
async function main() {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║     🛡️  MCP-Style Security Server with Sanitization        ║');
  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log('║  This server demonstrates MCP security patterns            ║');
  console.log('║  All inputs are sanitized to prevent attacks               ║');
  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log('║  Security Policy: PRODUCTION                               ║');
  console.log('║  Protection: Path Traversal, Command Injection, SQL, XSS   ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log('Type "help" for commands, "test" to run security tests');
  console.log('');

  // Interactive prompt
  const prompt = () => {
    rl.question('mcp> ', async (input) => {
      if (input.trim()) {
        await processCommand(input);
      }
      prompt();
    });
  };

  prompt();
}

// Error handling
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (error) => {
  console.error('❌ Unhandled rejection:', error);
  process.exit(1);
});

// Start the server
if (require.main === module) {
  main().catch(error => {
    console.error('Failed to start server:', error);
    process.exit(1);
  });
}

module.exports = { tools, sanitizer };