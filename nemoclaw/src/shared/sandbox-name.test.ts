// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  assertValidName,
  isValidName,
  NAME_ALLOWED_FORMAT,
  NAME_MAX_LENGTH,
  NAME_VALID_PATTERN,
} from "./sandbox-name.cjs";

describe("sandbox-name canonical validator", () => {
  describe("isValidName", () => {
    it.each([
      "openclaw",
      "nvidia-router",
      "a",
      "a1",
      "my-sandbox-1",
      "a".repeat(NAME_MAX_LENGTH),
    ])("accepts the RFC 1035 label '%s'", (name) => {
      expect(isValidName(name)).toBe(true);
    });

    it.each([
      ["empty string", ""],
      ["leading dash (flag injection)", "-x"],
      ["flag-like", "--help"],
      ["trailing dash", "foo-"],
      ["leading digit", "1box"],
      ["uppercase", "Foo"],
      ["underscore", "my_box"],
      ["space", "a b"],
      ["command substitution", "$(id)"],
      ["semicolon", "mybox;id"],
      ["over length", "a".repeat(NAME_MAX_LENGTH + 1)],
    ])("rejects %s", (_label, name) => {
      expect(isValidName(name)).toBe(false);
    });

    it("rejects non-string input", () => {
      expect(isValidName(undefined)).toBe(false);
      expect(isValidName(123)).toBe(false);
      expect(isValidName(null)).toBe(false);
    });
  });

  describe("assertValidName", () => {
    it("returns the value unchanged for a valid name", () => {
      expect(assertValidName("openclaw", "sandbox name")).toBe("openclaw");
    });

    it("throws 'Invalid <label>' for a malformed name and uses the given label", () => {
      expect(() => assertValidName("--help", "sandbox name")).toThrow(/Invalid sandbox name/);
      expect(() => assertValidName("--help", "provider name")).toThrow(/Invalid provider name/);
    });

    it("names the canonical allowed format in the error message", () => {
      expect(() => assertValidName("Bad")).toThrow(NAME_ALLOWED_FORMAT);
    });

    it("previews only the first 80 chars of an over-long name; never echoes it in full", () => {
      const longName = "a".repeat(200);
      let message = "";
      try {
        assertValidName(longName, "sandbox name");
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).toContain("…");
      expect(message).not.toContain(longName);
    });

    it("never returns a value with a shell metacharacter or leading dash (property)", () => {
      fc.assert(
        fc.property(fc.string(), (candidate) => {
          let returned: string | null = null;
          try {
            returned = assertValidName(candidate);
          } catch {
            // Rejection is always acceptable, but assert it so the property
            // still records an expectation when every candidate is rejected
            // (the plugin project enables expect.requireAssertions).
            expect(isValidName(candidate)).toBe(false);
            return;
          }
          // If it returned, the accepted value must be a safe RFC 1035 label.
          expect(returned).toBe(candidate);
          expect(NAME_VALID_PATTERN.test(returned)).toBe(true);
          expect(returned.startsWith("-")).toBe(false);
          expect(/[^a-z0-9-]/.test(returned)).toBe(false);
        }),
      );
    });
  });
});
