// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Shared in-memory filesystem and fixtures for the runner test suites.
// Kept out of the *.test.ts namespace so each spec can stay focused.

import type fs from "node:fs";
import { vi } from "vitest";
import YAML from "yaml";

export const FAKE_HOME = "/fakehome";

interface FsEntry {
  type: "file" | "dir";
  content?: string;
}

export const store = new Map<string, FsEntry>();

export function addFile(p: string, content: string): void {
  store.set(p, { type: "file", content });
}

export function addDir(p: string): void {
  store.set(p, { type: "dir" });
}

/** Returns a node:fs mock backed by the in-memory `store`. */
export function fsMock(original: typeof fs): typeof fs {
  return {
    ...original,
    mkdirSync: vi.fn((p: string) => {
      addDir(p);
    }),
    readFileSync: (p: string) => {
      const entry = store.get(p);
      if (entry?.type !== "file") throw new Error(`ENOENT: ${p}`);
      return entry.content ?? "";
    },
    writeFileSync: vi.fn((p: string, data: string) => {
      store.set(p, { type: "file", content: data });
    }),
    readdirSync: (p: string) => {
      const prefix = p.endsWith("/") ? p : `${p}/`;
      const entries = new Set<string>();
      for (const k of store.keys()) {
        if (k.startsWith(prefix)) {
          const first = k.slice(prefix.length).split("/")[0];
          if (first) entries.add(first);
        }
      }
      if (entries.size === 0 && !store.has(p)) throw new Error(`ENOENT: ${p}`);
      return [...entries].sort();
    },
  } as unknown as typeof fs;
}

export const mockExeca = vi.fn();
export const mockEnsureHttpsPinProxyRoutes = vi.fn(async () => {});

export function makeValidatedEndpoint(url: string, pinnedUrl = url) {
  const parsed = new URL(url);
  const pinned = new URL(pinnedUrl);
  const dnsResolved = parsed.hostname !== pinned.hostname;
  const pinnedHostname =
    pinned.hostname.startsWith("[") && pinned.hostname.endsWith("]")
      ? pinned.hostname.slice(1, -1)
      : pinned.hostname;
  return {
    url,
    pinnedUrl,
    protocol: parsed.protocol as "http:" | "https:",
    hostname: parsed.hostname,
    resolvedAddress: dnsResolved ? pinnedHostname : undefined,
    resolvedFamily: dnsResolved ? (pinnedHostname.includes(":") ? 6 : 4) : undefined,
    dnsResolved,
  };
}

export const stdoutChunks: string[] = [];

export function captureStdout(): void {
  vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
    stdoutChunks.push(String(chunk));
    return true;
  });
}

export function stdoutText(): string {
  return stdoutChunks.join("");
}

export function capturedJsonOutput<T = unknown>(): T {
  const json = stdoutText()
    .split("\n")
    .filter((line) => line && !line.startsWith("RUN_ID:") && !line.startsWith("PROGRESS:"))
    .join("\n");
  return JSON.parse(json) as T;
}

export function minimalBlueprint(overrides?: Record<string, unknown>): Record<string, unknown> {
  return {
    version: "1.0",
    components: {
      inference: {
        profiles: {
          default: {
            provider_type: "openai",
            provider_name: "my-provider",
            endpoint: "https://api.example.com/v1",
            model: "gpt-4",
            credential_env: "MY_API_KEY",
          },
        },
      },
      sandbox: { image: "openclaw", name: "test-sandbox", forward_ports: [18789] },
      policy: { additions: {} },
    },
    ...overrides,
  };
}

export function routedBlueprint(): Record<string, unknown> {
  return {
    version: "1.0",
    components: {
      inference: {
        profiles: {
          routed: {
            provider_type: "openai",
            provider_name: "nvidia-router",
            endpoint: "http://localhost:4000/v1",
            model: "routed",
            credential_env: "NVIDIA_INFERENCE_API_KEY",
            credential_default: "router-local",
            timeout_secs: 180,
          },
        },
      },
      sandbox: { image: "openclaw", name: "test-sandbox", forward_ports: [18789] },
      router: { enabled: true, port: 4000, pool_config_path: "router/pool-config.yaml" },
      policy: { additions: {} },
    },
  };
}

export function seedBlueprintFile(bp?: Record<string, unknown>): void {
  addFile("blueprint.yaml", YAML.stringify(bp ?? minimalBlueprint()));
}

export function blueprintWithPolicyAdditions(
  additions: Record<string, unknown>,
): Record<string, unknown> {
  const bp = minimalBlueprint();
  return {
    ...bp,
    components: { ...(bp.components as Record<string, unknown>), policy: { additions } },
  };
}

export function mockCurrentPolicy(stdout: string): void {
  mockExeca.mockImplementation(async (_cmd: string, args: string[]) => {
    if (
      args[0] === "policy" &&
      args[1] === "get" &&
      args[2] === "--full" &&
      args[3] === "test-sandbox"
    ) {
      return { exitCode: 0, stdout, stderr: "" };
    }
    return { exitCode: 0, stdout: "", stderr: "" };
  });
}
