// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import http, {
  type IncomingHttpHeaders,
  type IncomingMessage,
  type OutgoingHttpHeaders,
  type ServerResponse,
} from "node:http";
import https, { type RequestOptions } from "node:https";
import { homedir } from "node:os";
import { join } from "node:path";
import tls, { type PeerCertificate } from "node:tls";
import { fileURLToPath } from "node:url";

import { HTTPS_PIN_PROXY_PORT } from "../lib/ports.js";
import type { ValidatedEndpoint } from "./ssrf.js";
import { isPrivateIp } from "./private-networks.js";

const ROUTE_PREFIX = "/.nemoclaw/https-pin/";
const HEALTH_PATH = "/.nemoclaw/https-pin/health";
const STATE_DIR = join(homedir(), ".nemoclaw", "state", "https-pin-proxy");
const ROUTES_PATH = join(STATE_DIR, "routes.json");
const ROUTES_LOCK_PATH = join(STATE_DIR, "routes.lock");
const TOKEN_PATH = join(STATE_DIR, "proxy-token");
const PID_PATH = join(STATE_DIR, "proxy.pid");
const LOG_PATH = join(STATE_DIR, "proxy.log");
const LOOPBACK_HOST = "127.0.0.1";
const LISTEN_HOST = "127.0.0.1";
const HEALTH_TOKEN_HEADER = "x-nemoclaw-https-pin-proxy-token";
const ROUTES_LOCK_TIMEOUT_MS = 2_000;
const ROUTES_LOCK_STALE_MS = 30_000;
const UPSTREAM_REQUEST_TIMEOUT_MS = 30_000;
const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

export interface HttpsPinProxyRoute {
  id: string;
  hostname: string;
  port: number;
  basePath: string;
  baseSearch: string;
  resolvedAddress: string;
  resolvedFamily?: number;
}

interface PersistedRoute extends HttpsPinProxyRoute {
  updatedAt: string;
}

type RouteMap = Record<string, PersistedRoute>;

function ensureStateDir(): void {
  if (!existsSync(STATE_DIR)) {
    mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  }
  chmodSync(STATE_DIR, 0o700);
}

function writeFileAtomically(path: string, contents: string): void {
  ensureStateDir();
  const tmpPath = join(STATE_DIR, `.${Date.now()}.${String(process.pid)}.tmp`);
  let fd: number | null = null;
  try {
    fd = openSync(tmpPath, "wx", 0o600);
    writeFileSync(fd, contents);
    fsyncSync(fd);
    closeSync(fd);
    fd = null;
    renameSync(tmpPath, path);
    chmodSync(path, 0o600);
  } catch (err) {
    if (fd !== null) {
      closeSync(fd);
    }
    try {
      unlinkSync(tmpPath);
    } catch {
      // Best effort cleanup; the write failure is the meaningful error.
    }
    throw err;
  }
}

function removeStaleRoutesLock(): void {
  try {
    if (Date.now() - statSync(ROUTES_LOCK_PATH).mtimeMs > ROUTES_LOCK_STALE_MS) {
      unlinkSync(ROUTES_LOCK_PATH);
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      throw err;
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function acquireRoutesLock(): Promise<number> {
  ensureStateDir();
  const deadline = Date.now() + ROUTES_LOCK_TIMEOUT_MS;
  while (Date.now() < deadline) {
    try {
      const fd = openSync(ROUTES_LOCK_PATH, "wx", 0o600);
      writeFileSync(fd, `${String(process.pid)}\n`);
      return fd;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") {
        throw err;
      }
      removeStaleRoutesLock();
      await sleep(25);
    }
  }
  throw new Error("Timed out waiting for HTTPS pin proxy route lock.");
}

async function withRoutesLock<T>(fn: () => T): Promise<T> {
  const fd = await acquireRoutesLock();
  try {
    return fn();
  } finally {
    closeSync(fd);
    try {
      unlinkSync(ROUTES_LOCK_PATH);
    } catch {
      // The lock may have been removed as stale by another process after timeout.
    }
  }
}

function readRoutes(): RouteMap {
  try {
    const parsed = JSON.parse(readFileSync(ROUTES_PATH, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as RouteMap)
      : {};
  } catch {
    return {};
  }
}

function writeRoutes(routes: RouteMap): void {
  writeFileAtomically(ROUTES_PATH, `${JSON.stringify(routes, null, 2)}\n`);
}

function routeIdFor(validated: ValidatedEndpoint): string {
  return createHash("sha256")
    .update(`${validated.url}\0${validated.pinnedUrl}`)
    .digest("hex")
    .slice(0, 24);
}

function normalizeBasePath(pathname: string): string {
  return pathname.startsWith("/") ? pathname : `/${pathname}`;
}

function localBaseUrlFor(routeId: string, basePath: string, port: number): string {
  return `http://${LOOPBACK_HOST}:${String(port)}${ROUTE_PREFIX}${routeId}${basePath}`;
}

function targetPort(parsed: URL): number {
  if (parsed.port) return Number(parsed.port);
  return 443;
}

function hostHeaderValue(hostname: string, port: number): string {
  const host = hostname.includes(":") && !hostname.startsWith("[") ? `[${hostname}]` : hostname;
  return port === 443 ? host : `${host}:${String(port)}`;
}

function mergeSearch(baseSearch: string, requestSearch: string): string {
  if (!baseSearch) return requestSearch;
  if (!requestSearch) return baseSearch;
  return `${baseSearch}&${requestSearch.slice(1)}`;
}

export function sanitizeResponseHeaders(headers: IncomingHttpHeaders): OutgoingHttpHeaders {
  const sanitized: OutgoingHttpHeaders = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!HOP_BY_HOP_HEADERS.has(key.toLowerCase())) {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

function sanitizeRequestHeaders(headers: IncomingHttpHeaders, host: string): OutgoingHttpHeaders {
  const sanitized = sanitizeResponseHeaders(headers);
  sanitized.host = host;
  return sanitized;
}

function routeFromValidatedEndpoint(
  validated: ValidatedEndpoint,
  port = HTTPS_PIN_PROXY_PORT,
): HttpsPinProxyRoute {
  if (validated.protocol !== "https:" || !validated.dnsResolved || !validated.resolvedAddress) {
    throw new Error("HTTPS pin proxy routes require a DNS-backed HTTPS endpoint.");
  }

  const parsed = new URL(validated.url);
  const id = routeIdFor(validated);
  const basePath = normalizeBasePath(parsed.pathname || "/");
  return {
    id,
    hostname: validated.hostname,
    port: targetPort(parsed),
    basePath,
    baseSearch: parsed.search,
    resolvedAddress: validated.resolvedAddress,
    resolvedFamily: validated.resolvedFamily,
  };
}

export function endpointForValidatedEndpoint(validated: ValidatedEndpoint): {
  endpoint: string;
  httpsPinRoute?: HttpsPinProxyRoute;
} {
  if (validated.protocol === "http:") {
    return { endpoint: validated.pinnedUrl };
  }

  if (!validated.dnsResolved) {
    return { endpoint: validated.url };
  }

  const httpsPinRoute = routeFromValidatedEndpoint(validated);
  return {
    endpoint: localBaseUrlFor(httpsPinRoute.id, httpsPinRoute.basePath, HTTPS_PIN_PROXY_PORT),
    httpsPinRoute,
  };
}

async function registerHttpsPinProxyRoute(route: HttpsPinProxyRoute): Promise<void> {
  await withRoutesLock(() => {
    const routes = readRoutes();
    routes[route.id] = {
      ...route,
      updatedAt: new Date().toISOString(),
    };
    writeRoutes(routes);
  });
}

function isPersistedRoute(value: unknown): value is PersistedRoute {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const route = value as Partial<PersistedRoute>;
  return (
    typeof route.id === "string" &&
    typeof route.hostname === "string" &&
    typeof route.port === "number" &&
    typeof route.basePath === "string" &&
    typeof route.baseSearch === "string" &&
    typeof route.resolvedAddress === "string"
  );
}

function loadRoute(routeId: string): PersistedRoute | null {
  const route = readRoutes()[routeId];
  return isPersistedRoute(route) ? route : null;
}

function requestPathForRoute(route: PersistedRoute, requestUrl: URL): string {
  const pathAfterRoute = requestUrl.pathname.slice(`${ROUTE_PREFIX}${route.id}`.length) || "/";
  return `${pathAfterRoute}${mergeSearch(route.baseSearch, requestUrl.search)}`;
}

export function buildPinnedHttpsRequestOptions(args: {
  route: HttpsPinProxyRoute;
  method?: string;
  headers?: IncomingMessage["headers"];
  path: string;
}): RequestOptions {
  const host = hostHeaderValue(args.route.hostname, args.route.port);
  return {
    protocol: "https:",
    hostname: args.route.resolvedAddress,
    host: args.route.resolvedAddress,
    family: args.route.resolvedFamily,
    port: args.route.port,
    method: args.method,
    path: args.path,
    headers: sanitizeRequestHeaders(args.headers ?? {}, host),
    servername: args.route.hostname,
    checkServerIdentity: (_servername: string, cert: PeerCertificate) =>
      tls.checkServerIdentity(args.route.hostname, cert),
  };
}

function sendError(res: ServerResponse, statusCode: number, message: string): void {
  res.writeHead(statusCode, { "content-type": "text/plain; charset=utf-8" });
  res.end(message);
}

function readProxyToken(): string | null {
  try {
    const token = readFileSync(TOKEN_PATH, "utf8").trim();
    return /^[a-f0-9]{64}$/.test(token) ? token : null;
  } catch {
    return null;
  }
}

function loadOrCreateProxyToken(): string {
  const existing = readProxyToken();
  if (existing) return existing;
  const token = randomBytes(32).toString("hex");
  writeFileAtomically(TOKEN_PATH, `${token}\n`);
  return token;
}

function healthResponseBody(token: string): string {
  return `ok:${createHash("sha256").update(token).digest("hex")}\n`;
}

function headerValue(headers: IncomingHttpHeaders, name: string): string | undefined {
  const value = headers[name];
  if (Array.isArray(value)) return value[0];
  return value;
}

function handleProxyRequest(req: IncomingMessage, res: ServerResponse): void {
  if (req.url === HEALTH_PATH) {
    const token = readProxyToken();
    if (!token || headerValue(req.headers, HEALTH_TOKEN_HEADER) !== token) {
      sendError(res, 404, "Unknown HTTPS pin proxy route.\n");
      return;
    }
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    res.end(healthResponseBody(token));
    return;
  }

  const requestUrl = new URL(req.url ?? "/", `http://${LOOPBACK_HOST}`);
  if (!requestUrl.pathname.startsWith(ROUTE_PREFIX)) {
    sendError(res, 404, "Unknown HTTPS pin proxy route.\n");
    return;
  }

  const rest = requestUrl.pathname.slice(ROUTE_PREFIX.length);
  const routeId = rest.split("/")[0];
  if (!routeId) {
    sendError(res, 404, "Missing HTTPS pin proxy route.\n");
    return;
  }

  const route = loadRoute(routeId);
  if (!route) {
    sendError(res, 404, "HTTPS pin proxy route is not registered.\n");
    return;
  }
  if (isPrivateIp(route.resolvedAddress)) {
    sendError(res, 502, "HTTPS pin proxy route points to a private/internal address.\n");
    return;
  }

  const upstreamPath = requestPathForRoute(route, requestUrl);
  // lgtm[js/file-access-to-http] Routes are persisted under a 0700 state dir and
  // revalidated as public IPs before use; TLS identity remains bound to hostname.
  const upstream = https.request(
    buildPinnedHttpsRequestOptions({
      route,
      method: req.method,
      headers: req.headers,
      path: upstreamPath,
    }),
    (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode ?? 502, sanitizeResponseHeaders(upstreamRes.headers));
      upstreamRes.pipe(res);
    },
  );

  const destroyUpstream = (message: string) => {
    if (!upstream.destroyed) {
      upstream.destroy(new Error(message));
    }
  };
  const onRequestAborted = () => destroyUpstream("HTTPS pin proxy client request aborted");
  const onResponseClose = () => {
    if (!res.writableEnded) {
      destroyUpstream("HTTPS pin proxy client response closed");
    }
  };

  req.on("aborted", onRequestAborted);
  res.on("close", onResponseClose);
  upstream.setTimeout(UPSTREAM_REQUEST_TIMEOUT_MS, () => {
    destroyUpstream("HTTPS pin proxy upstream request timed out");
  });
  upstream.on("close", () => {
    req.off("aborted", onRequestAborted);
    res.off("close", onResponseClose);
  });
  upstream.on("error", (err) => {
    if (!res.headersSent) {
      sendError(res, 502, `HTTPS pin proxy upstream request failed: ${err.message}\n`);
    } else {
      res.destroy(err);
    }
  });
  req.pipe(upstream);
}

async function waitForProxyHealth(port: number, token: string): Promise<boolean> {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    if (await isProxyHealthy(port, token)) return true;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  return false;
}

function isProxyHealthy(port: number, token: string): Promise<boolean> {
  return new Promise((resolve) => {
    const expectedBody = healthResponseBody(token);
    const req = http.request(
      {
        host: LOOPBACK_HOST,
        port,
        path: HEALTH_PATH,
        method: "GET",
        headers: {
          [HEALTH_TOKEN_HEADER]: token,
        },
        timeout: 500,
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          body += chunk;
          if (body.length > expectedBody.length) {
            req.destroy();
          }
        });
        res.on("end", () => {
          resolve(res.statusCode === 200 && body === expectedBody);
        });
      },
    );
    req.on("error", () => resolve(false));
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
    req.end();
  });
}

function spawnProxyProcess(port = HTTPS_PIN_PROXY_PORT): void {
  ensureStateDir();
  const modulePath = fileURLToPath(import.meta.url);
  const logFd = openSync(LOG_PATH, "a", 0o600);
  try {
    const child = spawn(process.execPath, [modulePath, "serve"], {
      detached: true,
      env: {
        ...process.env,
        NEMOCLAW_HTTPS_PIN_PROXY_PORT: String(port),
      },
      stdio: ["ignore", logFd, logFd],
    });
    child.unref();
    if (child.pid) {
      writeFileSync(PID_PATH, `${String(child.pid)}\n`, { mode: 0o600 });
      chmodSync(PID_PATH, 0o600);
    }
  } finally {
    closeSync(logFd);
  }
}

export async function ensureHttpsPinProxyRoutes(routes: HttpsPinProxyRoute[]): Promise<void> {
  if (routes.length === 0) return;
  const proxyToken = loadOrCreateProxyToken();
  if (!(await isProxyHealthy(HTTPS_PIN_PROXY_PORT, proxyToken))) {
    spawnProxyProcess();
  }
  if (!(await waitForProxyHealth(HTTPS_PIN_PROXY_PORT, proxyToken))) {
    throw new Error(
      `HTTPS endpoint pinning proxy did not become ready on ${LOOPBACK_HOST}:${String(
        HTTPS_PIN_PROXY_PORT,
      )}. Check ${LOG_PATH}.`,
    );
  }
  for (const route of routes) {
    await registerHttpsPinProxyRoute(route);
  }
}

export function createHttpsPinProxyServer(): http.Server {
  return http.createServer(handleProxyRequest);
}

export async function serveHttpsPinProxy(port = HTTPS_PIN_PROXY_PORT): Promise<http.Server> {
  const server = createHttpsPinProxyServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, LISTEN_HOST, () => {
      server.off("error", reject);
      resolve();
    });
  });
  return server;
}

if (process.argv[2] === "serve") {
  serveHttpsPinProxy().catch((err) => {
    process.stderr.write(
      `HTTPS pin proxy failed: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(1);
  });
}
