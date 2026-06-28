// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TLSSocket } from "node:tls";
import { afterAll, describe, expect, it, vi } from "vitest";

// The proxy module computes its state directory from os.homedir() at import
// time, so point HOME at a throwaway temp dir before importing it.
const FAKE_HOME = mkdtempSync(join(tmpdir(), "nemoclaw-pin-integ-home-"));
vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  return { ...actual, homedir: () => FAKE_HOME };
});

// This test drives a real TLS connection to a loopback fixture, so the
// private-range guard is relaxed. The SSRF private-IP rejection itself is
// covered by the unit tests in https-pin-proxy.test.ts.
vi.mock("./private-networks.js", () => ({
  isPrivateIp: () => false,
  isPrivateHostname: () => false,
}));

const proxy = await import("./https-pin-proxy.js");

const STATE_DIR = join(FAKE_HOME, ".nemoclaw", "state", "https-pin-proxy");
const ROUTES_PATH = join(STATE_DIR, "routes.json");
const ROUTE_PREFIX = "/.nemoclaw/https-pin/";
// A non-resolvable .test hostname: connecting via DNS instead of the pinned IP
// would fail with ENOTFOUND, so a successful request proves IP pinning.
const UPSTREAM_HOSTNAME = "api.pin.test";

// Generate a throwaway self-signed cert at module load (before it.skipIf is
// evaluated). The key never leaves this temp dir and is removed in afterAll.
const certDir = mkdtempSync(join(tmpdir(), "nemoclaw-pin-integ-cert-"));
let opensslAvailable = false;
let key = "";
let cert = "";
try {
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      join(certDir, "key.pem"),
      "-out",
      join(certDir, "cert.pem"),
      "-days",
      "3650",
      "-subj",
      `/CN=${UPSTREAM_HOSTNAME}`,
      "-addext",
      `subjectAltName=DNS:${UPSTREAM_HOSTNAME}`,
    ],
    { stdio: "ignore" },
  );
  key = readFileSync(join(certDir, "key.pem"), "utf8");
  cert = readFileSync(join(certDir, "cert.pem"), "utf8");
  opensslAvailable = true;
} catch {
  opensslAvailable = false;
}

afterAll(() => {
  rmSync(certDir, { recursive: true, force: true });
  rmSync(FAKE_HOME, { recursive: true, force: true });
});

interface Observed {
  servername?: string;
  host?: string;
  remoteAddress?: string;
  path?: string;
}

function listen(server: http.Server | https.Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port));
  });
}

function closeServer(server: http.Server | https.Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}

function getThroughProxy(port: number, path: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path, method: "GET" }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

describe("https pin proxy (real TLS integration)", () => {
  it.skipIf(!opensslAvailable)(
    "connects to the validated IP while preserving original SNI and Host with real TLS",
    async () => {
      const observed: Observed = {};
      const upstream = https.createServer({ key, cert }, (req, res) => {
        const socket = req.socket as TLSSocket;
        observed.servername = typeof socket.servername === "string" ? socket.servername : undefined;
        observed.host = req.headers.host;
        observed.remoteAddress = socket.remoteAddress ?? undefined;
        observed.path = req.url;
        res.writeHead(200, { "content-type": "application/json" });
        res.end('{"ok":true}');
      });
      const upstreamPort = await listen(upstream);

      // The proxy uses the default https agent, so configure the agent CA to
      // trust the fixture cert, then restore it afterward.
      const previousCa = https.globalAgent.options.ca;
      https.globalAgent.options.ca = cert;

      const route = {
        id: "a1b2c3d4e5f6a1b2c3d4e5f6",
        hostname: UPSTREAM_HOSTNAME,
        port: upstreamPort,
        basePath: "/v1",
        baseSearch: "",
        resolvedAddress: "127.0.0.1",
        resolvedFamily: 4,
        updatedAt: new Date().toISOString(),
      };
      mkdirSync(STATE_DIR, { recursive: true });
      writeFileSync(ROUTES_PATH, JSON.stringify({ [route.id]: route }));

      const proxyServer = proxy.createHttpsPinProxyServer();
      const proxyPort = await listen(proxyServer);

      try {
        const res = await getThroughProxy(proxyPort, `${ROUTE_PREFIX}${route.id}/v1/models`);

        // The request to a non-resolvable hostname succeeded, so the proxy
        // connected to the pinned IP rather than re-resolving DNS.
        expect(res.status).toBe(200);
        expect(res.body).toBe('{"ok":true}');
        expect(observed.remoteAddress).toMatch(/127\.0\.0\.1$/);
        // Original hostname was preserved as TLS SNI and in the HTTP Host header
        // (the non-default upstream port is appended to Host, never the IP).
        expect(observed.servername).toBe(UPSTREAM_HOSTNAME);
        expect(observed.host).toBe(`${UPSTREAM_HOSTNAME}:${upstreamPort}`);
        expect(observed.path).toBe("/v1/models");
      } finally {
        https.globalAgent.options.ca = previousCa;
        await closeServer(proxyServer);
        await closeServer(upstream);
      }
    },
  );
});
