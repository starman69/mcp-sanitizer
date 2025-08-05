/**
 * TypeScript definitions for MCP Sanitizer Middleware
 * 
 * This file provides comprehensive type definitions for all middleware
 * integrations, supporting Express.js, Fastify, and Koa frameworks.
 */

import { Request as ExpressRequest, Response as ExpressResponse, NextFunction } from 'express';
import { FastifyInstance, FastifyRequest, FastifyReply, FastifyPluginOptions } from 'fastify';
import { Context as KoaContext, Next as KoaNext } from 'koa';

// Core types from main sanitizer
export interface SanitizationWarning {
  type: string;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  field?: string;
  value?: any;
  pattern?: string;
}

export interface SanitizationResult {
  sanitized: any;
  warnings: SanitizationWarning[];
  blocked: boolean;
  originalValue?: any;
}

export interface SanitizationContext {
  type: string;
  path?: string;
  method?: string;
  timestamp?: number;
  [key: string]: any;
}

// Security policies
export type SecurityPolicy = 'PERMISSIVE' | 'DEVELOPMENT' | 'MODERATE' | 'PRODUCTION' | 'STRICT';

// Sanitization modes
export type SanitizationMode = 'sanitize' | 'block';

// Framework types
export type SupportedFramework = 'express' | 'fastify' | 'koa';

// Environment types
export type Environment = 'development' | 'production' | 'testing' | 'staging';

// Base middleware configuration
export interface BaseMiddlewareConfig {
  // Sanitization options
  sanitizeBody?: boolean;
  sanitizeParams?: boolean;
  sanitizeQuery?: boolean;
  sanitizeHeaders?: boolean;
  sanitizeResponse?: boolean;
  
  // Behavioral options
  mode?: SanitizationMode;
  policy?: SecurityPolicy;
  logWarnings?: boolean;
  
  // Performance options
  async?: boolean;
  skipHealthChecks?: boolean;
  skipStaticFiles?: boolean;
  
  // Response options
  blockStatusCode?: number;
  errorMessage?: string;
  includeDetails?: boolean;
  
  // MCP-specific options
  toolSpecificSanitization?: boolean;
  mcpContext?: boolean;
  
  // Sanitizer options
  sanitizer?: any; // MCPSanitizer instance
  sanitizerOptions?: object;
  
  // Callback functions
  onWarning?: (warnings: SanitizationWarning[], ...args: any[]) => void | Promise<void>;
  onBlocked?: (warnings: SanitizationWarning[], ...args: any[]) => void | Promise<void>;
  onError?: (error: Error, ...args: any[]) => void | Promise<void>;
}

// Express-specific types
export interface ExpressMiddlewareConfig extends BaseMiddlewareConfig {
  addWarningsToRequest?: boolean;
  onWarning?: (warnings: SanitizationWarning[], req: ExtendedExpressRequest) => void | Promise<void>;
  onBlocked?: (warnings: SanitizationWarning[], req: ExtendedExpressRequest, res: ExpressResponse) => boolean | Promise<boolean>;
  onError?: (error: Error, req: ExtendedExpressRequest, res: ExpressResponse, next: NextFunction) => boolean | Promise<boolean>;
}

export interface ExtendedExpressRequest extends ExpressRequest {
  sanitizationWarnings?: SanitizationWarning[];
  sanitizationResults?: Record<string, SanitizationResult>;
  mcpContext?: {
    toolName?: string;
    isToolExecution?: boolean;
    timestamp?: number;
  };
}

export type ExpressMiddleware = (req: ExtendedExpressRequest, res: ExpressResponse, next: NextFunction) => void | Promise<void>;

// Fastify-specific types
export interface FastifyMiddlewareConfig extends BaseMiddlewareConfig {
  decorateRequest?: boolean;
  decorateFastify?: boolean;
  usePreHandler?: boolean;
  schemaCompilation?: boolean;
  onWarning?: (warnings: SanitizationWarning[], request: ExtendedFastifyRequest, reply: FastifyReply) => void | Promise<void>;
  onBlocked?: (warnings: SanitizationWarning[], request: ExtendedFastifyRequest, reply: FastifyReply, results: Record<string, SanitizationResult>) => boolean | Promise<boolean>;
  onError?: (error: Error, request: ExtendedFastifyRequest, reply: FastifyReply) => boolean | Promise<boolean>;
}

export interface ExtendedFastifyRequest extends FastifyRequest {
  sanitizationWarnings?: SanitizationWarning[];
  sanitizationResults?: Record<string, SanitizationResult>;
  mcpContext?: {
    toolName?: string;
    isToolExecution?: boolean;
    timestamp?: number;
  };
}

export interface FastifyPluginConfig extends FastifyPluginOptions, FastifyMiddlewareConfig {}

// Koa-specific types
export interface KoaMiddlewareConfig extends BaseMiddlewareConfig {
  addToState?: boolean;
  contextKey?: string;
  loggerKey?: string;
  onWarning?: (warnings: SanitizationWarning[], ctx: ExtendedKoaContext) => void | Promise<void>;
  onBlocked?: (warnings: SanitizationWarning[], ctx: ExtendedKoaContext, results: Record<string, SanitizationResult>) => boolean | Promise<boolean>;
  onError?: (error: Error, ctx: ExtendedKoaContext) => boolean | Promise<boolean>;
}

export interface ExtendedKoaContext extends KoaContext {
  sanitizationWarnings?: SanitizationWarning[];
  sanitizationResults?: Record<string, SanitizationResult>;
  responseWarnings?: SanitizationWarning[];
  mcpContext?: {
    toolName?: string;
    isToolExecution?: boolean;
    timestamp?: number;
  };
  state: {
    [key: string]: any;
    sanitization?: {
      warnings: SanitizationWarning[];
      results: Record<string, SanitizationResult>;
      blocked: boolean;
      processed: boolean;
      responseWarnings?: SanitizationWarning[];
    };
  };
}

export type KoaMiddleware = (ctx: ExtendedKoaContext, next: KoaNext) => Promise<void>;

// Unified configuration type
export interface UnifiedMiddlewareConfig extends BaseMiddlewareConfig {
  express?: Partial<ExpressMiddlewareConfig>;
  fastify?: Partial<FastifyMiddlewareConfig>;
  koa?: Partial<KoaMiddlewareConfig>;
}

// Factory function types
export interface MiddlewareFactory {
  (config?: BaseMiddlewareConfig): ExpressMiddleware | KoaMiddleware | Function;
}

export interface UniversalMiddlewareFactory {
  express: () => ExpressMiddleware;
  fastify: FastifyPluginConfig;
  koa: () => KoaMiddleware;
  auto: (app: any) => ExpressMiddleware | KoaMiddleware | Function;
  tool: {
    express: () => ExpressMiddleware;
    fastify: FastifyPluginConfig;
    koa: () => KoaMiddleware;
  };
}

// Main module exports
export interface ExpressModule {
  createExpressMiddleware: (config?: ExpressMiddlewareConfig) => ExpressMiddleware;
  createMCPToolMiddleware: (config?: ExpressMiddlewareConfig) => ExpressMiddleware;
  DEFAULT_CONFIG: ExpressMiddlewareConfig;
}

export interface FastifyModule {
  (fastify: FastifyInstance, options: FastifyPluginConfig): Promise<void>;
  DEFAULT_CONFIG: FastifyMiddlewareConfig;
  mcpSanitizerPlugin: (fastify: FastifyInstance, options: FastifyPluginConfig) => Promise<void>;
}

export interface KoaModule {
  createKoaMiddleware: (config?: KoaMiddlewareConfig) => KoaMiddleware;
  createMCPToolMiddleware: (config?: KoaMiddlewareConfig) => KoaMiddleware;
  createMCPServerMiddleware: (config?: KoaMiddlewareConfig) => KoaMiddleware;
  DEFAULT_CONFIG: KoaMiddlewareConfig;
}

// Main middleware module
export interface MiddlewareModule {
  // Main factory functions
  createMiddleware: (framework: SupportedFramework | any, config?: UnifiedMiddlewareConfig) => ExpressMiddleware | KoaMiddleware | Function;
  createMCPToolMiddleware: (framework: SupportedFramework | any, config?: UnifiedMiddlewareConfig) => ExpressMiddleware | KoaMiddleware | Function;
  createUniversalMiddleware: (config?: UnifiedMiddlewareConfig) => UniversalMiddlewareFactory;
  createEnvironmentMiddleware: (environment?: Environment, customizations?: UnifiedMiddlewareConfig) => UniversalMiddlewareFactory;
  
  // Framework-specific exports
  express: ExpressModule;
  fastify: FastifyModule;
  koa: KoaModule;
  
  // Utility functions
  detectFramework: (app: any) => SupportedFramework | null;
  validateConfig: (config: UnifiedMiddlewareConfig) => UnifiedMiddlewareConfig;
  
  // Configuration
  UNIFIED_CONFIG: UnifiedMiddlewareConfig;
  FRAMEWORK_DETECTORS: Record<SupportedFramework, (app: any) => boolean>;
  
  // Convenience aliases
  create: (framework: SupportedFramework | any, config?: UnifiedMiddlewareConfig) => ExpressMiddleware | KoaMiddleware | Function;
  universal: (config?: UnifiedMiddlewareConfig) => UniversalMiddlewareFactory;
  env: (environment?: Environment, customizations?: UnifiedMiddlewareConfig) => UniversalMiddlewareFactory;
  
  // Backward compatibility
  middleware: {
    express: (config?: ExpressMiddlewareConfig) => ExpressMiddleware;
    fastify: FastifyModule;
    koa: (config?: KoaMiddlewareConfig) => KoaMiddleware;
  };
  
  // Type information
  types: {
    MiddlewareConfig: string;
    ExpressMiddleware: string;
    FastifyPlugin: string;
    KoaMiddleware: string;
    Framework: string;
    Environment: string;
    SanitizationMode: string;
    SecurityPolicy: string;
  };
}

// Export individual modules
export const express: ExpressModule;
export const fastify: FastifyModule;
export const koa: KoaModule;

// Export main functions
export function createMiddleware(framework: SupportedFramework | any, config?: UnifiedMiddlewareConfig): ExpressMiddleware | KoaMiddleware | Function;
export function createMCPToolMiddleware(framework: SupportedFramework | any, config?: UnifiedMiddlewareConfig): ExpressMiddleware | KoaMiddleware | Function;
export function createUniversalMiddleware(config?: UnifiedMiddlewareConfig): UniversalMiddlewareFactory;
export function createEnvironmentMiddleware(environment?: Environment, customizations?: UnifiedMiddlewareConfig): UniversalMiddlewareFactory;

// Export utility functions
export function detectFramework(app: any): SupportedFramework | null;
export function validateConfig(config: UnifiedMiddlewareConfig): UnifiedMiddlewareConfig;

// Export constants
export const UNIFIED_CONFIG: UnifiedMiddlewareConfig;
export const FRAMEWORK_DETECTORS: Record<SupportedFramework, (app: any) => boolean>;

// Default export
declare const middleware: MiddlewareModule;
export default middleware;

// Convenience type aliases
export type MiddlewareConfig = UnifiedMiddlewareConfig;
export type Middleware = ExpressMiddleware | KoaMiddleware | Function;

// Tool-specific types
export interface MCPToolContext {
  toolName: string;
  isToolExecution: boolean;
  timestamp: number;
}

export interface ToolSanitizationMap {
  [toolName: string]: {
    field: string;
    type: string;
  };
}

// Error types
export interface MCPSanitizationError extends Error {
  code: 'MCP_TOOL_BLOCKED' | 'MCP_SANITIZATION_ERROR';
  warnings: SanitizationWarning[];
  toolName?: string;
}

// Plugin registration helpers (for TypeScript projects)
declare module 'express' {
  interface Request {
    sanitizationWarnings?: SanitizationWarning[];
    sanitizationResults?: Record<string, SanitizationResult>;
    mcpContext?: MCPToolContext;
  }
}

declare module 'fastify' {
  interface FastifyRequest {
    sanitizationWarnings?: SanitizationWarning[];
    sanitizationResults?: Record<string, SanitizationResult>;
    mcpContext?: MCPToolContext;
  }
  
  interface FastifyInstance {
    mcpSanitizer?: any;
    mcpSanitizerConfig?: FastifyMiddlewareConfig;
  }
}

declare module 'koa' {
  interface Context {
    sanitizationWarnings?: SanitizationWarning[];
    sanitizationResults?: Record<string, SanitizationResult>;
    responseWarnings?: SanitizationWarning[];
    mcpContext?: MCPToolContext;
  }
}