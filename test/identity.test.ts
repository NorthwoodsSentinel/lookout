// Regression fixtures for the v0.6 identity + judgment layers (CoE 2026-07-29).
// The load-bearing assertions: the operator can never become a candidate, a
// known contact is never re-discovered, thin evidence never alerts, and the
// calibration tripwire fires on a degraded lens.
import { describe, expect, test } from "bun:test";
import { parseSelfLogins, isSelfLogin, classify, shouldAlert, calibrationDrift } from "../src/identity";

describe("identity layer", () => {
  const self = parseSelfLogins("NorthwoodsSentinel, robert-chuvala");
  const known = new Set(["cliffhall", "mellanon"]);

  test("operator login is classified self, case-insensitive", () => {
    expect(classify("NorthwoodsSentinel", self, known)).toBe("self");
    expect(classify("northwoodssentinel", self, known)).toBe("self");
    expect(isSelfLogin("ROBERT-CHUVALA", self)).toBe(true);
  });

  test("default self set covers the org when env var is absent", () => {
    expect(isSelfLogin("NorthwoodsSentinel", parseSelfLogins(undefined))).toBe(true);
  });

  test("known contact is never a candidate again", () => {
    expect(classify("cliffhall", self, known)).toBe("known-contact");
  });

  test("stranger stays a candidate", () => {
    expect(classify("nnabeyang", self, known)).toBe("candidate");
  });
});

describe("judgment layer — alert predicate", () => {
  test("strong alignment with readable surface alerts", () => {
    expect(shouldAlert({ public_values_alignment: 9, evidence_confidence: "high", connection_actionability: 7 })).toBe(true);
    expect(shouldAlert({ public_values_alignment: 8, evidence_confidence: "medium", connection_actionability: 3 })).toBe(true);
  });

  test("thin evidence never alerts regardless of score", () => {
    expect(shouldAlert({ public_values_alignment: 10, evidence_confidence: "low", connection_actionability: 9 })).toBe(false);
  });

  test("sub-threshold alignment never alerts", () => {
    expect(shouldAlert({ public_values_alignment: 7, evidence_confidence: "high", connection_actionability: 9 })).toBe(false);
  });
});

describe("calibration layer — drift tripwire", () => {
  test("stable self-score does not trip", () => {
    expect(calibrationDrift([9, 9, 8, 9], 9).drifted).toBe(false);
  });

  test("two-point drop below trailing median trips", () => {
    const r = calibrationDrift([9, 9, 9, 8, 9], 7);
    expect(r.median).toBe(9);
    expect(r.drifted).toBe(true);
  });

  test("insufficient baseline never trips", () => {
    expect(calibrationDrift([9, 9], 5).drifted).toBe(false);
  });
});
