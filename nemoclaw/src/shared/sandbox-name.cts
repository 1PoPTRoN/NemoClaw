// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// sourceOfTruth: This is the only definition of the NemoClaw sandbox/provider
// name grammar (RFC 1035 label, letter-initial, max 63). It is compiled to the
// generated .cjs/.d.cts by build:cli before both the plugin and the root CLI
// are built.
// consumers: The ESM plugin runner (nemoclaw/src/blueprint/runner.ts) and
// migration snapshot (nemoclaw/src/blueprint/snapshot.ts) import the generated
// .cjs directly; the root CLI re-exports the same constants through
// src/lib/name-validation.ts (mirroring src/lib/policy/merge.ts). Keeping one
// definition prevents the leading-char drift already observed between
// src/lib/name-validation.ts and the copies in mcp-bridge-validation.ts /
// smoke-macos-install.sh.
// sourceBoundary: A blueprint is untrusted input. These names flow into
// `openshell ... --name <value>` argv slots, shell scripts, and Kubernetes pod
// names, so callers must validate at the ingestion boundary and fail closed.
// regressionTest: nemoclaw/src/shared/sandbox-name.test.ts plus the plugin
// runner/snapshot tests and the root name-validation consumers.
// removalCondition: remove only when no NemoClaw consumer validates a
// sandbox/provider identifier, or the grammar is enforced by a shared upstream
// contract.

export const NAME_MAX_LENGTH = 63;

// RFC 1035 label: starts with a lowercase letter, then lowercase
// letters/digits/internal hyphens, ends with a letter or digit.
export const NAME_VALID_PATTERN = /^[a-z]([a-z0-9-]*[a-z0-9])?$/;

export const NAME_ALLOWED_FORMAT =
  `1-${NAME_MAX_LENGTH} characters, lowercase, starts with a letter, ` +
  "letters/numbers/internal hyphens only, ends with letter/number";

/**
 * True when `value` is a well-formed sandbox/provider name: a non-empty
 * RFC 1035 label no longer than NAME_MAX_LENGTH characters.
 */
export function isValidName(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= NAME_MAX_LENGTH &&
    NAME_VALID_PATTERN.test(value)
  );
}

/**
 * Return `value` when it is a valid name; otherwise throw. The error message
 * previews only the first 80 characters of an offending value so a hostile,
 * over-long, or metacharacter-laden name is never echoed back in full.
 */
export function assertValidName(value: unknown, label = "name"): string {
  if (isValidName(value)) {
    return value;
  }
  const preview =
    typeof value === "string" && value.length > 80 ? `${value.slice(0, 80)}…` : String(value);
  throw new Error(`Invalid ${label}: '${preview}'. Allowed format: ${NAME_ALLOWED_FORMAT}.`);
}
