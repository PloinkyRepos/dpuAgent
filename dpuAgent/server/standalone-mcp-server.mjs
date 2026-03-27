#!/usr/bin/env node
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';

async function loadSdkDeps() {
  const { types, streamHttp, mcp, zod } = await import('mcp-sdk');
  return {
    McpServer: mcp.McpServer,
    StreamableHTTPServerTransport: streamHttp.StreamableHTTPServerTransport,
    isInitializeRequest: types.isInitializeRequest,
    z: zod.z
  };
}

function resolveConfigPath() {
  const candidates = [
    process.env.DPU_MCP_CONFIG_PATH,
    process.env.MCP_CONFIG_FILE,
    path.join(process.cwd(), 'mcp-config.json')
  ];
  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }
    try {
      const stat = fs.statSync(candidate);
      if (stat.isFile()) {
        return candidate;
      }
    } catch {
      // try next candidate
    }
  }
  throw new Error('Unable to locate mcp-config.json for standalone DPU runtime.');
}

function loadConfig() {
  const configPath = resolveConfigPath();
  return {
    configPath,
    config: JSON.parse(fs.readFileSync(configPath, 'utf8'))
  };
}

function createLiteralUnionSchema(z, values) {
  const unique = [...new Set(Array.isArray(values) ? values : [])];
  if (!unique.length) {
    return null;
  }
  if (unique.length === 1) {
    return z.literal(unique[0]);
  }
  return z.union(unique.map((value) => z.literal(value)));
}

function createFieldSchema(z, fieldSpec) {
  if (typeof fieldSpec === 'string') {
    fieldSpec = { type: fieldSpec };
  }
  if (!fieldSpec || typeof fieldSpec !== 'object') {
    return z.any();
  }
  const type = typeof fieldSpec.type === 'string' ? fieldSpec.type.toLowerCase() : 'string';
  let schema;
  switch (type) {
    case 'string':
      schema = Array.isArray(fieldSpec.enum)
        ? (createLiteralUnionSchema(z, fieldSpec.enum) || z.string())
        : z.string();
      break;
    case 'number':
      schema = z.number();
      break;
    case 'boolean':
      schema = z.boolean();
      break;
    case 'array':
      schema = z.array(createFieldSchema(z, fieldSpec.items ?? { type: 'string' }));
      break;
    case 'object':
      schema = z.object(buildObjectShape(z, fieldSpec.properties || {}));
      break;
    default:
      schema = z.any();
      break;
  }
  if (fieldSpec.optional) {
    schema = schema.optional();
  }
  if (fieldSpec.nullable) {
    schema = schema.nullable();
  }
  return schema;
}

function buildObjectShape(z, spec = {}) {
  const shape = {};
  for (const [key, value] of Object.entries(spec || {})) {
    shape[key] = createFieldSchema(z, value);
  }
  return shape;
}

function buildCommandSpec(entry) {
  const cwdBase = entry?.cwd === 'workspace'
    ? process.cwd()
    : (typeof entry?.cwd === 'string' && entry.cwd.trim() ? path.resolve(process.cwd(), entry.cwd) : process.cwd());
  const commandValue = typeof entry?.command === 'string' ? entry.command.trim() : '';
  if (!commandValue) {
    throw new Error(`Missing command for MCP tool "${entry?.name || ''}".`.trim());
  }
  return {
    command: path.isAbsolute(commandValue) ? commandValue : path.resolve(process.cwd(), commandValue),
    cwd: cwdBase,
    env: entry?.env && typeof entry.env === 'object' ? entry.env : {}
  };
}

function executeShell(spec, payload) {
  return new Promise((resolve, reject) => {
    const child = spawn(spec.command, [], {
      cwd: spec.cwd,
      env: { ...process.env, ...spec.env },
      stdio: ['pipe', 'pipe', 'pipe']
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('error', reject);
    child.on('close', (code) => {
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8')
      });
    });
    child.stdin.end(`${JSON.stringify(payload ?? {})}\n`);
  });
}

function parseAuthInfo(headers = {}) {
  const raw = headers['x-ploinky-auth-info'] || headers['X-PLOINKY-AUTH-INFO'];
  if (!raw) {
    return null;
  }
  try {
    return JSON.parse(String(raw));
  } catch {
    return null;
  }
}

async function registerTools(server, config) {
  const { z } = await loadSdkDeps();
  for (const tool of Array.isArray(config.tools) ? config.tools : []) {
    const commandSpec = buildCommandSpec(tool);
    const definition = {
      title: tool.title,
      description: tool.description
    };
    const invocation = async (...cbArgs) => {
      let args = cbArgs[0] ?? {};
      let context = cbArgs[1] ?? {};
      if (cbArgs.length === 1 && typeof args === 'object' && args !== null && args.requestId) {
        context = args;
        args = {};
      }
      const authInfo = parseAuthInfo(context?.requestInfo?.headers || {});
      const result = await executeShell(commandSpec, {
        tool: tool.name,
        input: args,
        metadata: authInfo ? { ...context, authInfo } : context
      });
      if (result.code !== 0) {
        throw new Error(result.stderr?.trim() || `Tool ${tool.name} failed.`);
      }
      return {
        content: [{
          type: 'text',
          text: result.stdout || '{}'
        }]
      };
    };
    const registered = server.registerTool(tool.name, definition, invocation);
    registered.inputSchema = z.object(buildObjectShape(z, tool.inputSchema || {}));
  }
  if (typeof server.setToolRequestHandlers === 'function') {
    server.setToolRequestHandlers();
  }
}

async function createServerInstance() {
  const { McpServer } = await loadSdkDeps();
  const server = new McpServer({ name: 'dpu-agent', version: '0.1.0' });
  const { config } = loadConfig();
  await registerTools(server, config);
  return server;
}

async function main() {
  const { StreamableHTTPServerTransport, isInitializeRequest } = await loadSdkDeps();
  const port = Number.parseInt(String(process.env.PORT || '7000'), 10);
  const sessions = {};

  const serverHttp = http.createServer((req, res) => {
    const sendJson = (code, value) => {
      const payload = Buffer.from(JSON.stringify(value));
      res.writeHead(code, {
        'Content-Type': 'application/json',
        'Content-Length': payload.length
      });
      res.end(payload);
    };

    try {
      const requestUrl = new URL(req.url || '/', 'http://localhost');
      if (req.method === 'GET' && requestUrl.pathname === '/health') {
        return sendJson(200, { ok: true, server: 'dpu-agent' });
      }
      if (req.method !== 'POST' || requestUrl.pathname !== '/mcp') {
        return sendJson(404, { ok: false, error: 'Not found.' });
      }

      const chunks = [];
      req.on('data', (chunk) => chunks.push(chunk));
      req.on('end', async () => {
        let body = {};
        try {
          body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
        } catch {
          body = {};
        }

        const sessionId = req.headers['mcp-session-id'];
        const existing = sessionId && sessions[sessionId] ? sessions[sessionId] : null;
        try {
          if (!existing) {
            if (!isInitializeRequest(body)) {
              return sendJson(400, { jsonrpc: '2.0', error: { code: -32000, message: 'Missing session; send initialize first' }, id: null });
            }
            const server = await createServerInstance();
            const transport = new StreamableHTTPServerTransport({
              sessionIdGenerator: () => randomUUID(),
              enableJsonResponse: true,
              onsessioninitialized: (sid) => {
                sessions[sid] = { server, transport };
              }
            });
            await server.connect(transport);
            transport.onclose = () => {
              try {
                server.close();
              } catch {
                // ignore close errors
              }
              if (transport.sessionId && sessions[transport.sessionId]) {
                delete sessions[transport.sessionId];
              }
            };
            await transport.handleRequest(req, res, body);
            return;
          }
          await existing.transport.handleRequest(req, res, body);
        } catch (error) {
          if (!res.headersSent) {
            sendJson(500, {
              jsonrpc: '2.0',
              error: { code: -32603, message: error?.message || 'Internal server error.' },
              id: null
            });
          }
        }
      });
    } catch (error) {
      if (!res.headersSent) {
        sendJson(500, { ok: false, error: error?.message || 'Internal server error.' });
      }
    }
  });

  serverHttp.listen(port, () => {
    process.stdout.write(`DPU MCP server listening on ${port}\n`);
  });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
