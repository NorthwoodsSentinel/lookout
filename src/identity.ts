// identity.ts — v0.6 Layer 0/2/3 pure helpers.
//
// The identity layer runs BEFORE the values layer (CoE 2026-07-29, unanimous):
// a discovery tool has two jobs — find values-aligned people, and know who its
// operator already is. These helpers are pure so the regression fixtures can
// pin them without a Worker runtime.

export type Classification = "self" | "known-contact" | "candidate";

export interface ScoreTriple {
  public_values_alignment: number;                  // 10 = strongest observable NON-SELF match
  evidence_confidence: "low" | "medium" | "high";   // how much public surface there was to read
  connection_actionability: number;                 // is there a real path to a real conversation
}

export function parseSelfLogins(raw: string | undefined): Set<string> {
  return new Set(
    (raw ?? "NorthwoodsSentinel")
      .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean),
  );
}

export function isSelfLogin(login: string, selfLogins: Set<string>): boolean {
  return selfLogins.has(login.toLowerCase());
}

// The operator is the positive control; known contacts have graduated out of
// discovery. Only strangers remain candidates.
export function classify(
  login: string,
  selfLogins: Set<string>,
  knownContacts: Set<string>,
): Classification {
  if (isSelfLogin(login, selfLogins)) return "self";
  if (knownContacts.has(login.toLowerCase())) return "known-contact";
  return "candidate";
}

// Alerting is a predicate over the score triple, not a single threshold:
// strong observable alignment AND enough surface to trust the read.
export function shouldAlert(t: ScoreTriple): boolean {
  return t.public_values_alignment >= 8 && t.evidence_confidence !== "low";
}

// Outcome statuses that graduate a login into the known-contact set.
export const GRADUATING_OUTCOMES = ["contacted", "replied", "collaborating"] as const;

// Calibration drift: compare today's operator self-score against the trailing
// median of prior calibration scores. A drop of >= 2 points means either the
// operator's public surface changed or the lens drifted — both worth a page.
export function calibrationDrift(
  history: number[],
  current: number,
): { drifted: boolean; median: number | null } {
  if (history.length < 3) return { drifted: false, median: null }; // not enough baseline
  const sorted = [...history].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const median = sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
  return { drifted: current <= median - 2, median };
}
