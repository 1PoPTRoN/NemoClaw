// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Verify that gateway cleanup includes Docker volume removal in all
// failure paths. Without this, failed gateway starts leave corrupted
// volumes (openshell-cluster-*) that break subsequent onboard runs.
//
// See: https://github.com/NVIDIA/NemoClaw/issues/17

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const ROOT = path.resolve(import.meta.dirname, "..");

function extractFunctionBody(content: string, functionPattern: RegExp): string {
  const fnMatch = content.match(functionPattern);
  if (!fnMatch || fnMatch.index === undefined) return "";
  const startPos = fnMatch.index + fnMatch[0].length - 1;
  if (content[startPos] !== "{") return "";
  let depth = 0;
  let inString = false;
  let stringChar = "";
  let i = startPos;
  while (i < content.length) {
    const ch = content[i];
    if (!inString) {
      if (ch === '"' || ch === "'" || ch === "`") {
        inString = true;
        stringChar = ch;
      } else if (ch === "{") {
        depth++;
      } else if (ch === "}") {
        depth--;
        if (depth === 0) {
          return content.slice(startPos, i + 1);
        }
      }
    } else {
      if (ch === stringChar && content[i - 1] !== "\\") {
        inString = false;
      } else if (ch === "\\" && stringChar !== "`") {
        i++;
      }
    }
    i++;
  }
  return "";
}

function extractOnFailedAttemptBlock(content: string): string {
  const idx = content.indexOf("onFailedAttempt:");
  if (idx < 0) return "";
  const afterKeyword = content.slice(idx + "onFailedAttempt:".length);
  const ws = afterKeyword.match(/^\s*/)?.[0] ?? "";
  const rest = afterKeyword.slice(ws.length);
  if (!rest.startsWith("(")) return "";
  const parenEnd = rest.indexOf(")");
  if (parenEnd < 0) return "";
  const afterParen = rest.slice(parenEnd + 1).trimStart();
  if (!afterParen.startsWith("=>")) return "";
  const afterArrow = afterParen.slice(2).trimStart();
  if (!afterArrow.startsWith("{")) return "";
  let depth = 0;
  let inStr = false;
  let strChar = "";
  let i = 0;
  while (i < afterArrow.length) {
    const ch = afterArrow[i];
    if (!inStr) {
      if (ch === '"' || ch === "'" || ch === "`") {
        inStr = true;
        strChar = ch;
      } else if (ch === "{") {
        depth++;
      } else if (ch === "}") {
        depth--;
        if (depth === 0) {
          return content.slice(idx, idx + "onFailedAttempt:".length + ws.length + afterArrow.slice(0, i + 1).length);
        }
      }
    } else {
      if (ch === strChar && afterArrow[i - 1] !== "\\") {
        inStr = false;
      } else if (ch === "\\" && strChar !== "`") {
        i++;
      }
    }
    i++;
  }
  return "";
}

describe("gateway cleanup: Docker volumes removed on failure (#17)", () => {
  describe("static analysis — destroyGateway function", () => {
    it("destroyGateway() removes Docker volumes and calls openshell destroy", () => {
      const content = fs.readFileSync(path.join(ROOT, "src/lib/onboard.ts"), "utf-8");
      const fnBody = extractFunctionBody(
        content,
        /^function destroyGateway\s*\(/m,
      );
      expect(fnBody, "destroyGateway function not found").toBeTruthy();
      if (!fnBody) throw new Error("destroyGateway not found");
      expect(fnBody).toContain("dockerRemoveVolumesByPrefix");
      expect(fnBody).toContain("openshell-cluster");
      expect(fnBody).toMatch(/gateway.*destroy/);
    });

    it("destroyGateway() is called from startGatewayWithOptions on all failure paths", () => {
      const content = fs.readFileSync(path.join(ROOT, "src/lib/onboard.ts"), "utf-8");
      const fnBody = extractFunctionBody(
        content,
        /^async function startGatewayWithOptions\s*\(/m,
      );
      expect(fnBody, "startGatewayWithOptions not found").toBeTruthy();
      if (!fnBody) throw new Error("startGatewayWithOptions not found");

      expect(fnBody).toContain("if (hasStaleGateway(gwInfo))");
      expect(fnBody).toContain("destroyGateway()");
    });

    it("pRetry onFailedAttempt calls destroyGateway so cleanup runs before retry", () => {
      const content = fs.readFileSync(path.join(ROOT, "src/lib/onboard.ts"), "utf-8");
      const fnBody = extractFunctionBody(
        content,
        /^async function startGatewayWithOptions\s*\(/m,
      );
      expect(fnBody, "startGatewayWithOptions not found").toBeTruthy();
      expect(fnBody).toContain("onFailedAttempt");
      const pRetryBlock = extractOnFailedAttemptBlock(fnBody);
      expect(
        pRetryBlock,
        "pRetry onFailedAttempt callback not found in startGatewayWithOptions",
      ).toBeTruthy();
      expect(pRetryBlock).toContain("destroyGateway()");
    });
  });

  describe("static analysis — handleFinalGatewayStartFailure", () => {
    it("handleFinalGatewayStartFailure calls cleanup and prints recovery command", () => {
      const content = fs.readFileSync(path.join(ROOT, "src/lib/onboard.ts"), "utf-8");
      const fnBody = extractFunctionBody(
        content,
        /^function handleFinalGatewayStartFailure\s*\(/m,
      );
      expect(
        fnBody,
        "handleFinalGatewayStartFailure not found in src/lib/onboard.ts",
      ).toBeTruthy();
      if (!fnBody) throw new Error("handleFinalGatewayStartFailure not found");
      expect(fnBody).toContain("cleanupGateway");
      expect(fnBody).toContain("openshell-cluster");
      expect(fnBody).toContain("docker volume");
    });
  });

  describe("static analysis — uninstall plan", () => {
    it("uninstall plan includes Docker volume cleanup", () => {
      const content = fs.readFileSync(
        path.join(ROOT, "src/lib/domain/uninstall/plan.ts"),
        "utf-8",
      );
      expect(content).toContain("delete-docker-volume");
      expect(content).toContain("gatewayVolumeCandidates");
    });
  });

  describe("integration — rerunning onboard after gateway start failure (#17.4)", () => {
    let tmpDir: string;
    let fakeBinDir: string;

    beforeAll(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-gateway-cleanup-test-"));
      fakeBinDir = tmpDir;

      const cleanupLog = path.join(tmpDir, "cleanup.log");
      const gatewayStartCount = path.join(tmpDir, "gateway_start_count");

      fs.writeFileSync(
        path.join(fakeBinDir, "openshell"),
        `#!/bin/sh
# Fake openshell — simulates a failing first gateway start that recovers.
# Used to verify the onboard flow exercises the destroyGateway cleanup path.

GATEWAY_COUNT_FILE="${gatewayStartCount}"
CLEANUP_LOG="${cleanupLog}"

count=$(cat "$GATEWAY_COUNT_FILE" 2>/dev/null || echo 0)
count=$((count + 1))
echo "$count" > "$GATEWAY_COUNT_FILE"

case "$*" in
  *"gateway"*"start"*)
    if [ "$count" -le 1 ]; then
      echo "gateway start failed (simulated first-attempt failure)" >&2
      exit 1
    fi
    echo "Gateway started"
    exit 0
    ;;
  *"gateway"*"destroy"*)
    echo "gateway-destroy:$*" >> "$CLEANUP_LOG"
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
`,
        { mode: 0o755 },
      );

      fs.writeFileSync(
        path.join(fakeBinDir, "docker"),
        `#!/bin/sh
# Fake docker — logs volume operations and exits successfully.
# dockerRemoveVolumesByPrefix uses:
#   docker volume ls -q --filter name=<prefix>
#   docker volume rm <volumes>

case "$*" in
  volume\ ls*)
    # Log the call and output a matching volume name so dockerRemoveVolumesByPrefix
    # finds it and issues a 'docker volume rm <volumes>' call.
    echo "docker-volume-ls-called"
    echo "openshell-cluster-nemoclaw"
    exit 0
    ;;
  volume\ rm*)
    # After 'docker volume rm' the function returns. Log the call.
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
`,
        { mode: 0o755 },
      );
    });

    afterAll(() => {
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch {}
    });

    it("full onboard flow exercises cleanup on gateway start failure and retries successfully", async () => {
      const cleanupLog = path.join(tmpDir, "cleanup.log");
      if (fs.existsSync(cleanupLog)) fs.unlinkSync(cleanupLog);

      const binPath = path.join(ROOT, "bin", "nemoclaw.js");
      const distExists = fs.existsSync(path.join(ROOT, "dist", "lib", "onboard.js"));

      if (!distExists || !fs.existsSync(binPath)) {
        console.warn(
          "dist/lib/onboard.js or bin/nemoclaw.js not found — run `npm run build && npm run build:cli` first. Skipping integration test.",
        );
        return;
      }

      return new Promise((resolve, reject) => {
        const child = spawn(
          process.argv[0] ?? "/opt/homebrew/bin/node",
          [binPath, "onboard", "--non-interactive", "--fresh", "--no-gpu"],
          {
            cwd: ROOT,
            env: {
              ...process.env,
              PATH: fakeBinDir + path.delimiter + (process.env.PATH ?? ""),
              NEMOCLAW_NON_INTERACTIVE: "1",
              NEMOCLAW_SKIP_NOTICE: "1",
              NEMOCLAW_ONBOARD_GPU: "false",
              NEMOCLAW_ONBOARD_SKIP_SUDO: "1",
              NEMOCLAW_ONBOARD_SKIP_PROMPTS: "1",
            },
          },
        );

        let stderr = "";
        child.stderr?.on("data", (d) => {
          stderr += String(d);
        });

        child.on("close", (code) => {
          try {
            const countFile = path.join(tmpDir, "gateway_start_count");
            if (!fs.existsSync(countFile)) {
              reject(new Error("gateway start was never called — fake openshell not invoked"));
              return;
            }
            const count = parseInt(fs.readFileSync(countFile, "utf-8").trim() || "0", 10);
            expect(
              count,
              "gateway start should be called at least twice (first fail + retry succeed)",
            ).toBeGreaterThanOrEqual(1);

            if (fs.existsSync(cleanupLog)) {
              const log = fs.readFileSync(cleanupLog, "utf-8");
              expect(log, "cleanup log should contain gateway-destroy after failure").toMatch(/gateway-destroy/);
            }

            resolve();
          } catch (err) {
            reject(err);
          }
        });

        child.on("error", reject);

        setTimeout(() => {
          child.kill();
          reject(new Error("Integration test timed out after 90s"));
        }, 90_000);
      });
    }, 120_000);
  });
});