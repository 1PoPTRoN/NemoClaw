// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { PeerCertificate } from "node:tls";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { HttpsPinProxyRoute } from "./https-pin-proxy.js";
import type { ValidatedEndpoint } from "./ssrf.js";

// The proxy module computes its state directory from os.homedir() at import
// time, so point HOME at a throwaway temp dir before importing it.
const FAKE_HOME = mkdtempSync(join(tmpdir(), "nemoclaw-pin-proxy-test-"));
const PROXY_PORT = 21437;

vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  return { ...actual, homedir: () => FAKE_HOME };
});

// Controllable stub for the upstream HTTPS leg so the proxy's request
// forwarding can be exercised without a real TLS server.
const upstreamState = vi.hoisted(() => ({
  behavior: "success" as "success" | "error" | "timeout" | "hang",
  lastOptions: undefined as unknown,
}));

vi.mock("node:https", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:https")>();
  const { PassThrough } = await import("node:stream");
  const request = (options: unknown, cb?: (res: unknown) => void): unknown => {
    upstreamState.lastOptions = options;
    const req = new PassThrough() as PassThrough & {
      setTimeout?: (ms: number, onTimeout: () => void) => unknown;
      _onTimeout?: () => void;
    };
    req.setTimeout = (_ms: number, onTimeout: () => void) => {
      req._onTimeout = onTimeout;
      return req;
    };
    setImmediate(() => {
      if (upstreamState.behavior === "error") {
        req.emit("error", new Error("ECONNREFUSED"));
      } else if (upstreamState.behavior === "timeout") {
        req._onTimeout?.();
      } else if (upstreamState.behavior === "hang") {
        // Intentionally never responds.
      } else {
        const res = new PassThrough() as PassThrough & {
          statusCode?: number;
          headers?: Record<string, string>;
        };
        res.statusCode = 200;
        res.headers = {
          "content-type": "application/json",
          connection: "keep-alive",
          "transfer-encoding": "chunked",
        };
        cb?.(res);
        res.end('{"ok":true}');
      }
    });
    return req;
  };
  const actualDefault = (actual as { default?: Record<string, unknown> }).default ?? {};
  return { ...actual, default: { ...actualDefault, request }, request };
});

// Avoid launching a real detached proxy process.
const spawnMock = vi.hoisted(() => vi.fn(() => ({ unref: () => {}, pid: 12345 })));
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawn: spawnMock };
});

process.env.NEMOCLAW_HTTPS_PIN_PROXY_PORT = String(PROXY_PORT);
const proxy = await import("./https-pin-proxy.js");
// The module captured the port at import time; clear the env so it cannot leak
// into other test files that assert on the default port.
delete process.env.NEMOCLAW_HTTPS_PIN_PROXY_PORT;

const STATE_DIR = join(FAKE_HOME, ".nemoclaw", "state", "https-pin-proxy");
const ROUTES_PATH = join(STATE_DIR, "routes.json");
const TOKEN_PATH = join(STATE_DIR, "proxy-token");
const ROUTE_PREFIX = "/.nemoclaw/https-pin/";
const HEALTH_PATH = "/.nemoclaw/https-pin/health";
const HEALTH_TOKEN_HEADER = "x-nemoclaw-https-pin-proxy-token";

// ── Helpers ─────────────────────────────────────────────────────

const openServers: http.Server[] = [];

function track(server: http.Server): http.Server {
  openServers.push(server);
  return server;
}

async function closeAll(): Promise<void> {
  await Promise.all(
    openServers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.close(() => resolve());
        }),
    ),
  );
}

async function startServer(): Promise<{ server: http.Server; port: number }> {
  const server = track(proxy.createHttpsPinProxyServer());
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  return { server, port: (server.address() as AddressInfo).port };
}

interface ClientResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

function request(
  port: number,
  path: string,
  options: { method?: string; headers?: Record<string, string> } = {},
): Promise<ClientResponse> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, path, method: options.method ?? "GET", headers: options.headers },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          body += chunk;
        });
        res.on("end", () => {
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body });
        });
      },
    );
    req.on("error", reject);
    req.end();
  });
}

function writeToken(token = "a".repeat(64)): string {
  mkdirSync(STATE_DIR, { recursive: true });
  writeFileSync(TOKEN_PATH, `${token}\n`);
  return token;
}

function writeRoute(route: HttpsPinProxyRoute): void {
  mkdirSync(STATE_DIR, { recursive: true });
  writeFileSync(
    ROUTES_PATH,
    JSON.stringify({ [route.id]: { ...route, updatedAt: new Date().toISOString() } }),
  );
}

// Persist arbitrary (possibly malformed) route state to exercise the strict
// validation in loadRoute/isPersistedRoute.
function writeRawRoutes(routes: Record<string, unknown>): void {
  mkdirSync(STATE_DIR, { recursive: true });
  writeFileSync(ROUTES_PATH, JSON.stringify(routes));
}

const dnsRoute: HttpsPinProxyRoute = {
  id: "abcdef0123456789abcdef01",
  hostname: "api.example.com",
  port: 443,
  basePath: "/v1",
  baseSearch: "",
  resolvedAddress: "93.184.216.34",
  resolvedFamily: 4,
};

function validatedEndpoint(overrides: Partial<ValidatedEndpoint>): ValidatedEndpoint {
  return {
    url: "https://api.example.com/v1",
    pinnedUrl: "https://93.184.216.34/v1",
    protocol: "https:",
    hostname: "api.example.com",
    resolvedAddress: "93.184.216.34",
    resolvedFamily: 4,
    dnsResolved: true,
    ...overrides,
  };
}

beforeEach(() => {
  rmSync(STATE_DIR, { recursive: true, force: true });
  upstreamState.behavior = "success";
  upstreamState.lastOptions = undefined;
  spawnMock.mockClear();
});

afterEach(async () => {
  await closeAll();
});

// ── Endpoint mapping & request options ──────────────────────────

describe("endpointForValidatedEndpoint", () => {
  it("returns pinned HTTP endpoints without a proxy route", () => {
    const result = proxy.endpointForValidatedEndpoint(
      validatedEndpoint({
        url: "http://api.example.com/v1",
        pinnedUrl: "http://93.184.216.34/v1",
        protocol: "http:",
      }),
    );
    expect(result).toEqual({ endpoint: "http://93.184.216.34/v1" });
  });

  it("returns IP-literal HTTPS endpoints without a proxy route", () => {
    const result = proxy.endpointForValidatedEndpoint(
      validatedEndpoint({
        url: "https://93.184.216.34/v1",
        pinnedUrl: "https://93.184.216.34/v1",
        hostname: "93.184.216.34",
        resolvedAddress: undefined,
        resolvedFamily: undefined,
        dnsResolved: false,
      }),
    );
    expect(result).toEqual({ endpoint: "https://93.184.216.34/v1" });
  });

  it("routes DNS-backed HTTPS endpoints through a local pinned proxy", () => {
    const result = proxy.endpointForValidatedEndpoint(
      validatedEndpoint({
        url: "https://api.example.com:9443/v1?api-version=1",
        pinnedUrl: "https://93.184.216.34:9443/v1?api-version=1",
      }),
    );
    expect(result.endpoint).toMatch(
      new RegExp(`^http://127\\.0\\.0\\.1:${PROXY_PORT}/\\.nemoclaw/https-pin/[a-f0-9]{24}/v1$`),
    );
    expect(result.httpsPinRoute).toMatchObject({
      hostname: "api.example.com",
      port: 9443,
      basePath: "/v1",
      baseSearch: "?api-version=1",
      resolvedAddress: "93.184.216.34",
      resolvedFamily: 4,
    });
  });

  it("throws when a DNS-backed HTTPS endpoint lacks a resolved address", () => {
    expect(() =>
      proxy.endpointForValidatedEndpoint(
        validatedEndpoint({ resolvedAddress: undefined, resolvedFamily: undefined }),
      ),
    ).toThrow(/DNS-backed HTTPS endpoint/);
  });
});

describe("buildPinnedHttpsRequestOptions", () => {
  it("connects to the validated IP while preserving Host and TLS SNI identity", () => {
    const options = proxy.buildPinnedHttpsRequestOptions({
      route: { ...dnsRoute, port: 443 },
      method: "POST",
      path: "/v1/chat/completions",
      headers: { authorization: "Bearer token", connection: "close", host: "127.0.0.1:21437" },
    });
    expect(options.hostname).toBe("93.184.216.34");
    expect(options.host).toBe("93.184.216.34");
    expect(options.servername).toBe("api.example.com");
    expect(options.family).toBe(4);
    expect(options.method).toBe("POST");
    expect(options.path).toBe("/v1/chat/completions");
    expect(options.headers).toMatchObject({
      authorization: "Bearer token",
      host: "api.example.com",
    });
    expect(options.headers).not.toHaveProperty("connection");
  });
});

describe("sanitizeResponseHeaders", () => {
  it("strips hop-by-hop response headers before forwarding upstream responses", () => {
    expect(
      proxy.sanitizeResponseHeaders({
        connection: "keep-alive",
        "content-type": "application/json",
        "keep-alive": "timeout=5",
        "transfer-encoding": "chunked",
        upgrade: "websocket",
      }),
    ).toEqual({ "content-type": "application/json" });
  });
});

// ── Proxy server request handling ───────────────────────────────

describe("proxy server", () => {
  it("answers the health check only with the correct token", async () => {
    const token = writeToken();
    const { port } = await startServer();

    const ok = await request(port, HEALTH_PATH, { headers: { [HEALTH_TOKEN_HEADER]: token } });
    expect(ok.status).toBe(200);
    expect(ok.body).toBe(`ok:${createHash("sha256").update(token).digest("hex")}\n`);

    const wrong = await request(port, HEALTH_PATH, { headers: { [HEALTH_TOKEN_HEADER]: "nope" } });
    expect(wrong.status).toBe(404);
  });

  it("returns 404 for the health check when no token has been provisioned", async () => {
    const { port } = await startServer();
    const res = await request(port, HEALTH_PATH, {
      headers: { [HEALTH_TOKEN_HEADER]: "x".repeat(64) },
    });
    expect(res.status).toBe(404);
  });

  it("returns 404 for paths outside the route prefix", async () => {
    const { port } = await startServer();
    const res = await request(port, "/not-a-route");
    expect(res.status).toBe(404);
  });

  it("returns 404 when no route id is present", async () => {
    const { port } = await startServer();
    const res = await request(port, ROUTE_PREFIX);
    expect(res.status).toBe(404);
  });

  it("returns 404 for an unregistered route id", async () => {
    const { port } = await startServer();
    const res = await request(port, `${ROUTE_PREFIX}deadbeefdeadbeefdeadbeef/v1`);
    expect(res.status).toBe(404);
  });

  it("rejects routes that resolve to a private address", async () => {
    writeRoute({ ...dnsRoute, resolvedAddress: "10.0.0.5" });
    const { port } = await startServer();
    const res = await request(port, `${ROUTE_PREFIX}${dnsRoute.id}/v1/models`);
    expect(res.status).toBe(502);
    expect(res.body).toMatch(/private\/internal/);
  });

  it("forwards to the validated IP and strips hop-by-hop response headers", async () => {
    writeRoute(dnsRoute);
    const { port } = await startServer();

    const res = await request(port, `${ROUTE_PREFIX}${dnsRoute.id}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: "Bearer secret" },
    });

    expect(res.status).toBe(200);
    expect(res.body).toBe('{"ok":true}');
    expect(res.headers["content-type"]).toBe("application/json");

    const options = upstreamState.lastOptions as {
      hostname: string;
      servername: string;
      path: string;
      headers: Record<string, string>;
    };
    expect(options.hostname).toBe("93.184.216.34");
    expect(options.servername).toBe("api.example.com");
    expect(options.path).toBe("/v1/chat/completions");
    expect(options.headers.host).toBe("api.example.com");
  });

  it("returns 502 when the upstream request errors", async () => {
    upstreamState.behavior = "error";
    writeRoute(dnsRoute);
    const { port } = await startServer();
    const res = await request(port, `${ROUTE_PREFIX}${dnsRoute.id}/v1`);
    expect(res.status).toBe(502);
    expect(res.body).toMatch(/upstream request failed/);
  });

  it("aborts the upstream request when it times out", async () => {
    upstreamState.behavior = "timeout";
    writeRoute(dnsRoute);
    const { port } = await startServer();
    const res = await request(port, `${ROUTE_PREFIX}${dnsRoute.id}/v1`);
    expect(res.status).toBe(502);
    expect(res.body).toMatch(/timed out/);
  });
});

describe("persisted route validation", () => {
  const base: Record<string, unknown> = {
    ...dnsRoute,
    updatedAt: "2026-01-01T00:00:00.000Z",
  };

  const tamperedCases: Array<[string, Record<string, unknown>]> = [
    ["a non-IP resolvedAddress", { ...base, resolvedAddress: "api.example.com" }],
    ["a zero port", { ...base, port: 0 }],
    ["an out-of-range port", { ...base, port: 70000 }],
    ["a non-integer port", { ...base, port: 443.5 }],
    ["an invalid resolvedFamily", { ...base, resolvedFamily: 7 }],
    ["a basePath without a leading slash", { ...base, basePath: "v1" }],
    ["a baseSearch without a leading question mark", { ...base, baseSearch: "api-version=2" }],
    ["a route id that does not match the lookup key", { ...base, id: "ffffffffffffffffffffffff" }],
  ];

  it.each(tamperedCases)("returns 404 without calling upstream for %s", async (_label, route) => {
    writeRawRoutes({ [dnsRoute.id]: route });
    const { port } = await startServer();
    const res = await request(port, `${ROUTE_PREFIX}${dnsRoute.id}/v1/models`);
    expect(res.status).toBe(404);
    expect(upstreamState.lastOptions).toBeUndefined();
  });

  it("returns 404 without calling upstream for a malformed route id key", async () => {
    writeRawRoutes({ "not-hex": { ...base, id: "not-hex" } });
    const { port } = await startServer();
    const res = await request(port, `${ROUTE_PREFIX}not-hex/v1`);
    expect(res.status).toBe(404);
    expect(upstreamState.lastOptions).toBeUndefined();
  });

  it("fails closed when routes.json is corrupt", async () => {
    mkdirSync(STATE_DIR, { recursive: true });
    writeFileSync(ROUTES_PATH, "{ this is not valid json");
    const { port } = await startServer();
    const res = await request(port, `${ROUTE_PREFIX}${dnsRoute.id}/v1`);
    expect(res.status).toBe(404);
    expect(upstreamState.lastOptions).toBeUndefined();
  });
});

// ── Route registration & proxy lifecycle ────────────────────────

describe("ensureHttpsPinProxyRoutes", () => {
  it("is a no-op when there are no routes", async () => {
    await proxy.ensureHttpsPinProxyRoutes([]);
    expect(existsSync(ROUTES_PATH)).toBe(false);
  });

  it("registers routes when the proxy is already healthy", async () => {
    const server = track(await proxy.serveHttpsPinProxy(PROXY_PORT));
    expect(server.listening).toBe(true);

    await proxy.ensureHttpsPinProxyRoutes([dnsRoute]);

    const persisted = JSON.parse(readFileSync(ROUTES_PATH, "utf8")) as Record<
      string,
      HttpsPinProxyRoute
    >;
    expect(persisted[dnsRoute.id]).toMatchObject({
      hostname: "api.example.com",
      resolvedAddress: "93.184.216.34",
    });
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("spawns a proxy and fails closed when it never becomes ready", async () => {
    await expect(proxy.ensureHttpsPinProxyRoutes([dnsRoute])).rejects.toThrow(
      /did not become ready/,
    );
    expect(spawnMock).toHaveBeenCalledTimes(1);
  });

  it("spawns the detached proxy with an allowlisted env that excludes parent secrets", async () => {
    const secrets = {
      GITHUB_TOKEN: "ghp_must_not_leak",
      AWS_ACCESS_KEY_ID: "AKIA_MUST_NOT_LEAK",
      NVIDIA_API_KEY: "nvapi-must-not-leak",
      OPENAI_API_KEY: "sk-must-not-leak",
    };
    Object.assign(process.env, secrets);
    try {
      await expect(proxy.ensureHttpsPinProxyRoutes([dnsRoute])).rejects.toThrow(
        /did not become ready/,
      );
      expect(spawnMock).toHaveBeenCalledTimes(1);

      const [, , options] = spawnMock.mock.calls[0] as unknown as [
        string,
        string[],
        { env: Record<string, string> },
      ];
      const spawnEnv = options.env;
      // Parent-process secrets must not reach the detached proxy.
      for (const key of Object.keys(secrets)) {
        expect(spawnEnv).not.toHaveProperty(key);
      }
      // The proxy still receives the values it legitimately needs.
      expect(spawnEnv.NEMOCLAW_HTTPS_PIN_PROXY_PORT).toBe(String(PROXY_PORT));
      expect(spawnEnv.PATH).toBeDefined();
    } finally {
      for (const key of Object.keys(secrets)) {
        delete process.env[key];
      }
    }
  });
});

// ── Additional edge-path coverage ───────────────────────────────

describe("proxy edge paths", () => {
  it("defaults the upstream port to 443 for portless DNS endpoints", () => {
    const result = proxy.endpointForValidatedEndpoint(validatedEndpoint({}));
    expect(result.httpsPinRoute?.port).toBe(443);
  });

  it("includes the port in the Host header for non-default upstream ports", () => {
    const options = proxy.buildPinnedHttpsRequestOptions({
      route: { ...dnsRoute, port: 9443 },
      path: "/v1",
    });
    expect(options.headers?.host).toBe("api.example.com:9443");
  });

  it("verifies the upstream certificate against the original hostname", () => {
    const options = proxy.buildPinnedHttpsRequestOptions({ route: dnsRoute, path: "/v1" });
    const result = options.checkServerIdentity?.("93.184.216.34", {
      subject: { CN: "evil.example" },
      subjectaltname: "DNS:evil.example",
    } as unknown as PeerCertificate);
    expect(result).toBeInstanceOf(Error);
  });

  it("merges the route base query with the incoming request query", async () => {
    writeRoute({ ...dnsRoute, baseSearch: "?api-version=2" });
    const { port } = await startServer();
    await request(port, `${ROUTE_PREFIX}${dnsRoute.id}/v1/models?model=x`);
    const options = upstreamState.lastOptions as { path: string };
    expect(options.path).toBe("/v1/models?api-version=2&model=x");
  });

  it("uses the route base query when the request has none", async () => {
    writeRoute({ ...dnsRoute, baseSearch: "?api-version=2" });
    const { port } = await startServer();
    await request(port, `${ROUTE_PREFIX}${dnsRoute.id}/v1/models`);
    const options = upstreamState.lastOptions as { path: string };
    expect(options.path).toBe("/v1/models?api-version=2");
  });

  it("tears down the upstream when the client aborts", async () => {
    upstreamState.behavior = "hang";
    writeRoute(dnsRoute);
    const { port } = await startServer();
    await new Promise<void>((resolve) => {
      const req = http.request({
        host: "127.0.0.1",
        port,
        path: `${ROUTE_PREFIX}${dnsRoute.id}/v1`,
      });
      req.on("error", () => resolve());
      req.end();
      setTimeout(() => req.destroy(), 50);
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(upstreamState.lastOptions).toBeDefined();
  });

  it("recovers from a stale routes lock during registration", async () => {
    track(await proxy.serveHttpsPinProxy(PROXY_PORT));
    mkdirSync(STATE_DIR, { recursive: true });
    const lockPath = join(STATE_DIR, "routes.lock");
    writeFileSync(lockPath, "99999\n");
    const stale = new Date(Date.now() - 60_000);
    utimesSync(lockPath, stale, stale);

    await proxy.ensureHttpsPinProxyRoutes([dnsRoute]);

    const persisted = JSON.parse(readFileSync(ROUTES_PATH, "utf8")) as Record<string, unknown>;
    expect(persisted[dnsRoute.id]).toBeDefined();
  });
});
