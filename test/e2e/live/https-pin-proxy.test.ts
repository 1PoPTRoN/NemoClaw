// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Regression guard for #4684.
 *
 * The bug was not that SSRF validation failed; it was that DNS-backed HTTPS
 * endpoints were validated and then handed to the downstream provider as the
 * original hostname URL, letting the provider perform a second DNS lookup at
 * connection time. This scenario exercises the real blueprint runner CLI path
 * and asserts the provider receives only the loopback pin-proxy endpoint.
 */

import { spawn } from "node:child_process";
import dns from "node:dns";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import YAML from "yaml";

import { expect, test } from "../fixtures/e2e-test.ts";
import { shouldRunLiveE2E } from "../fixtures/live-project-gate.ts";

const REPO_ROOT = path.resolve(import.meta.dirname, "../../..");
const RUN_HTTPS_PIN_PROXY_TEST = shouldRunLiveE2E() ? test : test.skip;
const TEST_TIMEOUT_MS = 90_000;
const PROXY_PORT = 21437;
const VALIDATED_PUBLIC_IP = "93.184.216.34";
const REBOUND_PRIVATE_IP = "10.0.0.5";

type CommandResult = {
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
};

function runCommand(
  command: string,
  args: readonly string[],
  options: {
    readonly cwd: string;
    readonly env: NodeJS.ProcessEnv;
    readonly timeoutMs?: number;
  },
): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, [...args], {
      cwd: options.cwd,
      env: options.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 1_000).unref();
    }, options.timeoutMs ?? 30_000);
    timeout.unref();

    child.stdout?.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once("close", (exitCode) => {
      clearTimeout(timeout);
      resolve({ exitCode, stdout, stderr });
    });
  });
}

function writeBlueprint(workdir: string, sandboxName: string): void {
  fs.writeFileSync(
    path.join(workdir, "blueprint.yaml"),
    YAML.stringify({
      version: "1.0",
      components: {
        sandbox: {
          image: "openclaw",
          name: sandboxName,
        },
        inference: {
          profiles: {
            default: {
              provider_type: "openai",
              provider_name: "default",
              endpoint: "https://rebinding.example.test/v1",
              model: "e2e-model",
              credential_env: "E2E_API_KEY",
            },
          },
        },
      },
    }),
  );
}

function ensureFakeExecaModule(cleanup: { add: (name: string, fn: () => void) => void }): void {
  const execaDir = path.join(REPO_ROOT, "nemoclaw", "node_modules", "execa");
  const packageJson = path.join(execaDir, "package.json");
  if (fs.existsSync(packageJson)) return;

  fs.mkdirSync(execaDir, { recursive: true });
  fs.writeFileSync(packageJson, JSON.stringify({ type: "module", exports: "./index.js" }));
  fs.writeFileSync(
    path.join(execaDir, "index.js"),
    `import { spawn } from "node:child_process";
export function execa(command, args = [], options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ? { ...process.env, ...options.env } : process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk) => { stdout += chunk.toString("utf8"); });
    child.stderr?.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
    child.once("error", reject);
    child.once("close", (exitCode) => {
      const result = { exitCode: exitCode ?? 0, stdout, stderr };
      if (result.exitCode !== 0 && options.reject !== false) {
        const error = new Error(\`Command failed: \${command} \${args.join(" ")}\`);
        Object.assign(error, result);
        reject(error);
        return;
      }
      resolve(result);
    });
  });
}
`,
  );
  cleanup.add("remove temporary fake execa module", () => {
    fs.rmSync(execaDir, { recursive: true, force: true });
  });
}

function writeFakeOpenShell(binDir: string): string {
  const commandLogPath = path.join(binDir, "openshell-commands.jsonl");
  const scriptPath = path.join(binDir, "openshell");
  fs.writeFileSync(
    scriptPath,
    `#!/usr/bin/env node
const fs = require("node:fs");
const args = process.argv.slice(2);
const entry = { args, env: process.env };
const configIndex = args.indexOf("--config");
const configValue = configIndex >= 0 ? args[configIndex + 1] : "";
if (configValue.includes("rebinding.example.test")) {
  entry.simulatedDownstreamAddress = ${JSON.stringify(REBOUND_PRIVATE_IP)};
}
fs.appendFileSync(${JSON.stringify(commandLogPath)}, JSON.stringify(entry) + "\\n");
process.exit(0);
`,
    { mode: 0o755 },
  );
  return commandLogPath;
}

function readOpenShellCalls(commandLogPath: string): Array<{
  readonly args: string[];
  readonly env: Record<string, string | undefined>;
  readonly simulatedDownstreamAddress?: string;
}> {
  return fs
    .readFileSync(commandLogPath, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

RUN_HTTPS_PIN_PROXY_TEST(
  "https-pin-proxy: blueprint apply gives downstream only the pinned loopback endpoint",
  { timeout: TEST_TIMEOUT_MS },
  async ({ artifacts, cleanup }) => {
    ensureFakeExecaModule(cleanup);

    const root = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-https-pin-e2e-"));
    const workdir = path.join(root, "blueprint");
    const fakeBinDir = path.join(root, "bin");
    const home = path.join(root, "home");
    fs.mkdirSync(workdir, { recursive: true });
    fs.mkdirSync(fakeBinDir, { recursive: true });
    fs.mkdirSync(home, { recursive: true });

    cleanup.add(`remove HTTPS pin proxy E2E temp root ${root}`, () => {
      fs.rmSync(root, { recursive: true, force: true });
    });

    const commandLogPath = writeFakeOpenShell(fakeBinDir);
    writeBlueprint(workdir, "e2e-https-pin-proxy");
    await artifacts.writeJson("scenario.json", {
      id: "https-pin-proxy",
      runner: "vitest",
      issue: 4684,
      contract: [
        "DNS-backed HTTPS endpoint is validated once on the host",
        "downstream provider receives a loopback HTTPS pin-proxy URL, not the original hostname",
        "a DNS rebind after validation does not change the provider endpoint URL",
      ],
    });

    const runnerScript = `
import dns from "node:dns";
import { main } from ${JSON.stringify(path.join(REPO_ROOT, "nemoclaw/src/blueprint/runner.ts"))};
import { serveHttpsPinProxy } from ${JSON.stringify(path.join(REPO_ROOT, "nemoclaw/src/blueprint/https-pin-proxy.ts"))};

const originalLookup = dns.lookup;
const originalPromisesLookup = dns.promises.lookup;
dns.lookup = ((hostname, options, callback) => {
  if (hostname === "rebinding.example.test") {
    const cb = typeof options === "function" ? options : callback;
    if (typeof cb === "function") {
      process.nextTick(() => cb(null, [{ address: ${JSON.stringify(VALIDATED_PUBLIC_IP)}, family: 4 }]));
    }
    return {};
  }
  return originalLookup(hostname, options, callback);
});
dns.promises.lookup = ((hostname, options) => {
  if (hostname === "rebinding.example.test") {
    return Promise.resolve([{ address: ${JSON.stringify(VALIDATED_PUBLIC_IP)}, family: 4 }]);
  }
  return originalPromisesLookup(hostname, options);
});

async function run() {
  const proxyServer = await serveHttpsPinProxy(${PROXY_PORT});
  try {
    await main(["apply"]);
  } finally {
    await new Promise((resolve, reject) => proxyServer.close((error) => error ? reject(error) : resolve()));
  }
}

run().catch((error) => {
  console.error(error && error.stack ? error.stack : error);
  process.exit(1);
});
`;

    const result = await runCommand(
      process.execPath,
      [
        path.join(REPO_ROOT, "node_modules/tsx/dist/cli.mjs"),
        "--input-type=module",
        "--eval",
        runnerScript,
      ],
      {
        cwd: workdir,
        timeoutMs: 45_000,
        env: {
          HOME: home,
          PATH: `${fakeBinDir}${path.delimiter}${process.env.PATH ?? ""}`,
          NEMOCLAW_HTTPS_PIN_PROXY_PORT: String(PROXY_PORT),
          E2E_API_KEY: "e2e-fake-key",
        },
      },
    );

    await artifacts.writeJson("runner-result.json", result);
    await artifacts.writeText(
      "openshell-commands.jsonl",
      fs.existsSync(commandLogPath) ? fs.readFileSync(commandLogPath, "utf8") : "",
    );

    expect(result.exitCode, `${result.stdout}\n${result.stderr}`).toBe(0);

    const providerCreate = readOpenShellCalls(commandLogPath).find(
      (entry) => entry.args[0] === "provider" && entry.args[1] === "create",
    );
    expect(
      providerCreate,
      "expected blueprint apply to configure an OpenShell provider",
    ).toBeDefined();
    const configIndex = providerCreate?.args.indexOf("--config") ?? -1;
    expect(configIndex).toBeGreaterThan(-1);
    const openaiBaseUrl = providerCreate?.args[configIndex + 1] ?? "";

    expect(openaiBaseUrl).toMatch(
      new RegExp(
        `^OPENAI_BASE_URL=http://127\\.0\\.0\\.1:${PROXY_PORT}/\\.nemoclaw/https-pin/[a-f0-9]{24}/v1$`,
      ),
    );
    expect(openaiBaseUrl).not.toContain("rebinding.example.test");
    expect(openaiBaseUrl).not.toContain(REBOUND_PRIVATE_IP);
    expect(providerCreate?.simulatedDownstreamAddress).toBeUndefined();
  },
);
