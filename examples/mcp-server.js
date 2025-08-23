#!/usr/bin/env node

/**
 * MCP Server Example with Sanitization
 * 
 * This example demonstrates how to integrate MCP Sanitizer into a real
 * Model Context Protocol (MCP) server to protect against malicious inputs.
 * 
 * The server implements common MCP tools (file operations, web requests, etc.)
 * with comprehensive input sanitization to prevent security vulnerabilities.
 * 
 * Usage: node examples/mcp-server.js
 */

const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { 
  CallToolRequestSchema,
  ListToolsRequestSchema 
} = require('@modelcontextprotocol/sdk/types.js');
const fs = require('fs').promises;
const path = require('path');
const https = require('https');
const MCPSanitizer = require('../src/index');

// Initialize sanitizer with PRODUCTION policy for maximum security
const sanitizer = new MCPSanitizer('PRODUCTION');

// Helper function to create sanitized error responses
function createSanitizedError(message, warnings = []) {
  return {
    isError: true,
    content: [{
      type: 'text',
      text: `Security Error: ${message}\nWarnings: ${warnings.join(', ')}`
    }]
  };
}

// Create MCP server instance
const server = new Server(
  {
    name: 'secure-mcp-server',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Define available tools with integrated sanitization
const tools = [
  {
    name: 'read_file',
    description: 'Read contents of a file (with path sanitization)',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Path to the file to read'
        }
      },
      required: ['path']
    }
  },
  {
    name: 'write_file',
    description: 'Write content to a file (with path and content sanitization)',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Path to the file to write'
        },
        content: {
          type: 'string',
          description: 'Content to write to the file'
        }
      },
      required: ['path', 'content']
    }
  },
  {
    name: 'list_directory',
    description: 'List files in a directory (with path sanitization)',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Path to the directory'
        }
      },
      required: ['path']
    }
  },
  {
    name: 'fetch_url',
    description: 'Fetch content from a URL (with URL sanitization)',
    inputSchema: {
      type: 'object',
      properties: {
        url: {
          type: 'string',
          description: 'URL to fetch'
        }
      },
      required: ['url']
    }
  },
  {
    name: 'search_files',
    description: 'Search for files with pattern (with pattern sanitization)',
    inputSchema: {
      type: 'object',
      properties: {
        directory: {
          type: 'string',
          description: 'Directory to search in'
        },
        pattern: {
          type: 'string',
          description: 'Search pattern (glob)'
        }
      },
      required: ['directory', 'pattern']
    }
  }
];

// Handle list tools request
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

// Handle tool execution with comprehensive sanitization
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'read_file': {
        // Sanitize file path
        const pathResult = sanitizer.sanitize(args.path, { type: 'file_path' });
        
        if (pathResult.blocked) {
          return createSanitizedError(
            'File path blocked by security policy',
            pathResult.warnings
          );
        }

        // Additional check: ensure path is within allowed directory
        const resolvedPath = path.resolve(pathResult.sanitized);
        const allowedBase = path.resolve(process.cwd());
        
        if (!resolvedPath.startsWith(allowedBase)) {
          return createSanitizedError('Access denied: Path outside allowed directory');
        }

        try {
          const content = await fs.readFile(resolvedPath, 'utf-8');
          return {
            content: [{
              type: 'text',
              text: content
            }]
          };
        } catch (error) {
          return createSanitizedError(`File read error: ${error.message}`);
        }
      }

      case 'write_file': {
        // Sanitize file path
        const pathResult = sanitizer.sanitize(args.path, { type: 'file_path' });
        
        if (pathResult.blocked) {
          return createSanitizedError(
            'File path blocked by security policy',
            pathResult.warnings
          );
        }

        // Sanitize content (check for malicious patterns)
        const contentResult = sanitizer.sanitize(args.content);
        
        if (contentResult.blocked) {
          return createSanitizedError(
            'Content blocked by security policy',
            contentResult.warnings
          );
        }

        // Additional check: ensure path is within allowed directory
        const resolvedPath = path.resolve(pathResult.sanitized);
        const allowedBase = path.resolve(process.cwd());
        
        if (!resolvedPath.startsWith(allowedBase)) {
          return createSanitizedError('Access denied: Path outside allowed directory');
        }

        try {
          await fs.writeFile(resolvedPath, contentResult.sanitized, 'utf-8');
          return {
            content: [{
              type: 'text',
              text: `File written successfully: ${pathResult.sanitized}`
            }]
          };
        } catch (error) {
          return createSanitizedError(`File write error: ${error.message}`);
        }
      }

      case 'list_directory': {
        // Sanitize directory path
        const pathResult = sanitizer.sanitize(args.path, { type: 'file_path' });
        
        if (pathResult.blocked) {
          return createSanitizedError(
            'Directory path blocked by security policy',
            pathResult.warnings
          );
        }

        // Additional check: ensure path is within allowed directory
        const resolvedPath = path.resolve(pathResult.sanitized);
        const allowedBase = path.resolve(process.cwd());
        
        if (!resolvedPath.startsWith(allowedBase)) {
          return createSanitizedError('Access denied: Path outside allowed directory');
        }

        try {
          const files = await fs.readdir(resolvedPath);
          return {
            content: [{
              type: 'text',
              text: files.join('\n')
            }]
          };
        } catch (error) {
          return createSanitizedError(`Directory list error: ${error.message}`);
        }
      }

      case 'fetch_url': {
        // Sanitize URL
        const urlResult = sanitizer.sanitize(args.url, { type: 'url' });
        
        if (urlResult.blocked) {
          return createSanitizedError(
            'URL blocked by security policy',
            urlResult.warnings
          );
        }

        // Additional check: only allow HTTPS in production
        const urlObj = new URL(urlResult.sanitized);
        if (urlObj.protocol !== 'https:') {
          return createSanitizedError('Only HTTPS URLs are allowed');
        }

        // Block requests to private IPs and metadata endpoints
        const blockedHosts = [
          '169.254.169.254', // AWS metadata
          'metadata.google.internal', // GCP metadata
          'localhost',
          '127.0.0.1',
          '0.0.0.0'
        ];

        if (blockedHosts.includes(urlObj.hostname)) {
          return createSanitizedError('Access to internal/metadata endpoints blocked');
        }

        return new Promise((resolve) => {
          https.get(urlResult.sanitized, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
              resolve({
                content: [{
                  type: 'text',
                  text: data.substring(0, 10000) // Limit response size
                }]
              });
            });
          }).on('error', (error) => {
            resolve(createSanitizedError(`Fetch error: ${error.message}`));
          });
        });
      }

      case 'search_files': {
        // Sanitize directory path
        const dirResult = sanitizer.sanitize(args.directory, { type: 'file_path' });
        
        if (dirResult.blocked) {
          return createSanitizedError(
            'Directory path blocked by security policy',
            dirResult.warnings
          );
        }

        // Sanitize search pattern (prevent glob injection)
        const patternResult = sanitizer.sanitize(args.pattern);
        
        if (patternResult.blocked) {
          return createSanitizedError(
            'Search pattern blocked by security policy',
            patternResult.warnings
          );
        }

        // Additional check: ensure directory is within allowed area
        const resolvedPath = path.resolve(dirResult.sanitized);
        const allowedBase = path.resolve(process.cwd());
        
        if (!resolvedPath.startsWith(allowedBase)) {
          return createSanitizedError('Access denied: Path outside allowed directory');
        }

        // Simple pattern matching (in production, use proper glob library)
        try {
          const files = await fs.readdir(resolvedPath);
          const pattern = patternResult.sanitized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const regex = new RegExp(pattern, 'i');
          const matches = files.filter(file => regex.test(file));
          
          return {
            content: [{
              type: 'text',
              text: matches.length > 0 
                ? `Found ${matches.length} files:\n${matches.join('\n')}`
                : 'No files found matching pattern'
            }]
          };
        } catch (error) {
          return createSanitizedError(`Search error: ${error.message}`);
        }
      }

      default:
        return createSanitizedError(`Unknown tool: ${name}`);
    }
  } catch (error) {
    // Log security events for monitoring
    console.error(`[SECURITY] Tool execution blocked: ${name}`, {
      args,
      error: error.message,
      timestamp: new Date().toISOString()
    });
    
    return createSanitizedError(`Security validation failed: ${error.message}`);
  }
});

// Start the server
async function main() {
  console.log('🛡️ Secure MCP Server Starting...');
  console.log('Security Policy: PRODUCTION');
  console.log('Sanitization: ENABLED');
  console.log('');
  console.log('Available tools:');
  tools.forEach(tool => {
    console.log(`  - ${tool.name}: ${tool.description}`);
  });
  console.log('');
  console.log('Security features:');
  console.log('  ✓ Path traversal prevention');
  console.log('  ✓ Command injection blocking');
  console.log('  ✓ URL validation and SSRF prevention');
  console.log('  ✓ Content sanitization');
  console.log('  ✓ Unicode/encoding attack prevention');
  console.log('  ✓ Template injection blocking');
  console.log('');
  
  const transport = new StdioServerTransport();
  await server.connect(transport);
  
  console.log('Server ready for MCP connections');
}

// Handle errors gracefully
process.on('uncaughtException', (error) => {
  console.error('[SECURITY] Uncaught exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (error) => {
  console.error('[SECURITY] Unhandled rejection:', error);
  process.exit(1);
});

// Run the server if executed directly
if (require.main === module) {
  main().catch(error => {
    console.error('Failed to start server:', error);
    process.exit(1);
  });
}

module.exports = { server, sanitizer };