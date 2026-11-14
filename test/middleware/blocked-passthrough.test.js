/**
 * Middleware in `mode: 'sanitize'` must never hand blocked input to the handler.
 * Previously a blocked body/query/params kept its raw value and next() ran.
 */

const express = require('../../src/middleware/express');
const koa = require('../../src/middleware/koa');
const fastifyPlugin = require('../../src/middleware/fastify');

const attack = { file_path: '../../etc/passwd', cmd: 'cat /etc/shadow; id' };

function runExpress (mw, req) {
  return new Promise((resolve) => {
    const res = { status () { return res; }, json () { resolve('responded'); return res; } };
    mw(req, res, () => resolve('next'));
  });
}

function expressReq (overrides = {}) {
  return { method: 'POST', path: '/api', body: {}, query: {}, params: {}, headers: {}, get: () => '', ...overrides };
}

describe('middleware withholds blocked input in sanitize mode', () => {
  it('express: blocked body is not passed through', async () => {
    const req = expressReq({ body: { ...attack } });
    expect(await runExpress(express.createExpressMiddleware({ logWarnings: false }), req)).toBe('next');
    expect(req.body).toEqual({});
  });

  it('express: blocked query is not passed through', async () => {
    const req = expressReq({ query: { q: '../../etc/passwd' } });
    await runExpress(express.createExpressMiddleware({ logWarnings: false }), req);
    expect(req.query).toEqual({});
  });

  it('express: getter-only req.query (Express 5) is still replaced', async () => {
    const proto = { get query () { return { q: '../../etc/passwd' }; } };
    const { query, ...rest } = expressReq();
    const req = Object.setPrototypeOf(rest, proto);
    await runExpress(express.createExpressMiddleware({ logWarnings: false }), req);
    expect(req.query).toEqual({});
  });

  it('express: clean input is still sanitized and passed on', async () => {
    const req = expressReq({ body: { name: 'alice' } });
    expect(await runExpress(express.createExpressMiddleware({ logWarnings: false }), req)).toBe('next');
    expect(req.body).toEqual({ name: 'alice' });
  });

  it('express tool middleware (sanitize mode): blocked parameter is withheld', async () => {
    const req = expressReq({
      path: '/tool',
      params: { toolName: 'file_reader' },
      body: { tool_name: 'file_reader', parameters: { file_path: '../../etc/passwd' } }
    });
    await runExpress(express.createMCPToolMiddleware({ mode: 'sanitize', logWarnings: false }), req);
    expect(JSON.stringify(req.body)).not.toContain('etc/passwd');
  });

  it('koa: blocked body is not passed through', async () => {
    const ctx = {
      path: '/api',
      method: 'POST',
      request: { body: { ...attack } },
      params: {},
      query: {},
      headers: {},
      state: {},
      status: 200,
      body: null,
      get: () => ''
    };
    let reached = false;
    await koa.createKoaMiddleware({ logWarnings: false })(ctx, async () => { reached = true; });
    expect(reached).toBe(true);
    expect(ctx.request.body).toEqual({});
  });

  it('fastify: blocked body is not passed through', async () => {
    const hooks = {};
    const instance = {
      decorate () {},
      decorateRequest () {},
      addHook (name, fn) { (hooks[name] = hooks[name] || []).push(fn); },
      schemaCompiler: () => (data) => ({ value: data }),
      setSchemaCompiler () {},
      register () {},
      post () {},
      log: { warn () {}, error () {}, info () {} }
    };
    await fastifyPlugin.mcpSanitizerPlugin(instance, { logWarnings: false });
    const request = { url: '/api', method: 'POST', body: { ...attack }, params: {}, query: {}, headers: {}, log: instance.log };
    const reply = { code () { return reply; }, send () { return reply; } };
    await hooks.preHandler[0](request, reply);
    expect(request.body).toEqual({});
  });
});
