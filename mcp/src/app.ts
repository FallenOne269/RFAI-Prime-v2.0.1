// HTTP app: OAuth metadata and endpoints, and the MCP Streamable HTTP endpoint at /mcp.
import express, { type Request, type Response, type NextFunction } from "express";
import { authorizationHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/authorize.js";
import { tokenHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/token.js";
import { clientRegistrationHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/register.js";
import { revocationHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/revoke.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { Config } from "./config.ts";
import { RfaiOAuthProvider, SUPPORTED_SCOPES, SCOPE_READ, SCOPE_RUN } from "./oauth.ts";
import { createMcpServer, RunLimiter } from "./tools.ts";
import { EmbeddedBackend, X402QuoteBackend, type CouncilBackend } from "./council.ts";
import type { MetadataFetcher } from "./cimd.ts";

export interface AppOptions {
  backend?: CouncilBackend;
  metadataFetcher?: MetadataFetcher;
  log?: (line: string) => void;
}

export function createApp(config: Config, opts: AppOptions = {}) {
  const provider = new RfaiOAuthProvider(config, opts.metadataFetcher);
  const backend: CouncilBackend = opts.backend ?? (config.backend === "x402" ? new X402QuoteBackend(config.x402Url) : new EmbeddedBackend());
  const limiter = new RunLimiter(config.maxRunsPerHour, config.maxConcurrentRuns);
  const log = opts.log ?? ((l: string) => console.log(l));

  const issuer = config.issuer.href.replace(/\/$/, "");
  const resource = config.resource.href;
  const prmUrl = `${issuer}/.well-known/oauth-protected-resource/mcp`;

  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", config.trustProxy);

  // Access log: method, path without query, status, duration. Never headers or bodies.
  app.use((req, res, next) => {
    const t = Date.now();
    res.on("finish", () => log(`${req.method} ${req.path.slice(0, 80)} ${res.statusCode} ${Date.now() - t}ms`));
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    next();
  });

  const cors = (req: Request, res: Response, next: NextFunction) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    if (req.method === "OPTIONS") return void res.sendStatus(204);
    next();
  };

  // RFC 9728 protected resource metadata (path-suffixed and root forms).
  const prm = {
    resource,
    authorization_servers: [issuer],
    scopes_supported: SUPPORTED_SCOPES,
    bearer_methods_supported: ["header"],
    resource_name: "RFAI Council",
  };
  app.all(["/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"], cors, (_req, res) => void res.json(prm));

  // RFC 8414 authorization server metadata.
  const asMeta = {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`,
    revocation_endpoint: `${issuer}/revoke`,
    scopes_supported: SUPPORTED_SCOPES,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
    revocation_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
    code_challenge_methods_supported: ["S256"],
    authorization_response_iss_parameter_supported: true,
    client_id_metadata_document_supported: config.allowClientIdMetadataDocuments,
  };
  app.all(["/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/mcp"], cors, (_req, res) => void res.json(asMeta));

  // client_secret_basic support: the SDK reads client credentials from the form body only.
  const basicToBody = [
    express.urlencoded({ extended: false, limit: "16kb" }),
    (req: Request, res: Response, next: NextFunction) => {
      const h = req.headers.authorization;
      if (h && /^basic /i.test(h)) {
        try {
          const raw = Buffer.from(h.slice(6).trim(), "base64").toString("utf8");
          const i = raw.indexOf(":");
          if (i < 0) throw new Error("bad");
          const id = decodeURIComponent(raw.slice(0, i).replace(/\+/g, " "));
          const secret = decodeURIComponent(raw.slice(i + 1).replace(/\+/g, " "));
          if (req.body?.client_id && req.body.client_id !== id) throw new Error("mismatch");
          req.body = { ...(req.body ?? {}), client_id: id, client_secret: secret };
        } catch {
          res.status(401).json({ error: "invalid_client", error_description: "Malformed Basic credentials" });
          return;
        }
      }
      next();
    },
  ];

  app.use("/authorize", authorizationHandler({ provider, rateLimit: { windowMs: 60_000, limit: 60 } }));
  app.use("/token", ...basicToBody, tokenHandler({ provider, rateLimit: { windowMs: 60_000, limit: 60 } }));
  app.use("/register", clientRegistrationHandler({ clientsStore: provider.clientsStore, clientSecretExpirySeconds: 0, rateLimit: { windowMs: 3600_000, limit: 30 } }));
  app.use("/revoke", ...basicToBody, revocationHandler({ provider, rateLimit: { windowMs: 60_000, limit: 60 } }));
  app.post("/oauth/consent", express.urlencoded({ extended: false, limit: "16kb" }), provider.consentHandler());

  app.get("/", (_req, res) => void res.type("text/plain").send(`RFAI Council MCP server. MCP endpoint: ${resource}\n`));
  app.get("/healthz", (_req, res) => void res.json({ ok: true }));

  // ---- /mcp -----------------------------------------------------------------

  const challenge = (error?: string, description?: string, scope = SUPPORTED_SCOPES.join(" ")) => {
    let v = `Bearer resource_metadata="${prmUrl}", scope="${scope}"`;
    if (error) v += `, error="${error}"`;
    if (description) v += `, error_description="${description.replace(/"/g, "'")}"`;
    return v;
  };

  const originCheck = (req: Request, res: Response, next: NextFunction) => {
    // Streamable HTTP requires Origin validation (DNS rebinding). Server-to-server clients send
    // no Origin; browsers must come from an allowed origin.
    const origin = req.headers.origin;
    if (origin && origin !== issuer && !config.allowedOrigins.includes(origin)) {
      res.status(403).json({ jsonrpc: "2.0", error: { code: -32000, message: "Origin not allowed" }, id: null });
      return;
    }
    next();
  };

  const bearer = async (req: Request, res: Response, next: NextFunction) => {
    const h = req.headers.authorization;
    if (!h || !/^Bearer /i.test(h)) {
      res.setHeader("WWW-Authenticate", challenge());
      res.status(401).json({ error: "invalid_token", error_description: "Missing bearer token" });
      return;
    }
    try {
      const info = await provider.verifyAccessToken(h.slice(7).trim());
      if (!info.scopes.includes(SCOPE_READ)) {
        res.setHeader("WWW-Authenticate", challenge("insufficient_scope", "council:read is required"));
        res.status(403).json({ error: "insufficient_scope" });
        return;
      }
      (req as any).auth = info;
      next();
    } catch (e) {
      const msg = e instanceof InvalidTokenError ? e.message : "invalid token";
      res.setHeader("WWW-Authenticate", challenge("invalid_token", msg));
      res.status(401).json({ error: "invalid_token", error_description: msg });
    }
  };

  // Step-up: a token without council:run gets HTTP 403 insufficient_scope for council_ask calls,
  // so clients can re-authorize with the wider scope.
  const runScope = (req: Request, res: Response, next: NextFunction) => {
    const msgs = Array.isArray(req.body) ? req.body : [req.body];
    const wantsRun = msgs.some((m: any) => m?.method === "tools/call" && m?.params?.name === "council_ask");
    if (wantsRun && !(req as any).auth?.scopes?.includes(SCOPE_RUN)) {
      res.setHeader("WWW-Authenticate", challenge("insufficient_scope", "council:run is required", `${SCOPE_READ} ${SCOPE_RUN}`));
      res.status(403).json({ error: "insufficient_scope" });
      return;
    }
    next();
  };

  app.post(
    "/mcp",
    originCheck,
    bearer,
    express.json({ limit: "64kb" }),
    runScope,
    async (req: Request, res: Response) => {
      const server = createMcpServer({ backend, limiter, x402Url: config.x402Url });
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on("close", () => {
        void transport.close();
        void server.close();
      });
      try {
        await server.connect(transport);
        await transport.handleRequest(req as any, res, req.body);
      } catch {
        if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal error" }, id: null });
      }
    },
  );
  app.all("/mcp", originCheck, (_req, res) => {
    res.setHeader("Allow", "POST");
    res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed: this server is stateless, use POST" }, id: null });
  });

  // Errors (bad JSON etc.): no stack traces, no echo of input.
  app.use((err: any, req: Request, res: Response, _next: NextFunction) => {
    if (res.headersSent) return;
    if (err?.type === "entity.parse.failed") {
      res.status(400).json({ jsonrpc: "2.0", error: { code: -32700, message: "Parse error" }, id: null });
    } else if (err?.type === "entity.too.large") {
      res.status(413).json({ jsonrpc: "2.0", error: { code: -32600, message: "Request too large" }, id: null });
    } else {
      res.status(500).json({ error: "server_error" });
    }
  });

  return { app, provider, backend };
}
