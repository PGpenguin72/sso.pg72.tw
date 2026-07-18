import { describe, expect, it } from "vitest";

import {
  ALERT_EVALUATOR_SOURCE_IDS,
  alertEvaluatorDecisionManifestDigest,
  alertEvaluatorSourceManifestDigest,
  type AlertEvaluatorDecisionProofValue,
  type AlertEvaluatorSourceProofValue,
} from "../worker/alert-run-proof";

const DIGEST = "A".repeat(43);

function sources(): AlertEvaluatorSourceProofValue[] {
  return ALERT_EVALUATOR_SOURCE_IDS.map((sourceId, observationCount) => ({
    incompleteCount: 0,
    observationCount,
    proofSha256: DIGEST,
    sourceId,
    status: "complete",
  }));
}

function decision(
  ordinal = 0,
  identitySha256 = DIGEST,
): AlertEvaluatorDecisionProofValue {
  return {
    decisionSha256: `I${"A".repeat(42)}`,
    disposition: "applied",
    evaluationSha256: `E${"A".repeat(42)}`,
    identitySha256,
    ordinal,
    sourceId: "d1.audit",
  };
}

function decisions(): AlertEvaluatorDecisionProofValue[] {
  return [
    decision(),
    {
      decisionSha256: `U${"A".repeat(42)}`,
      disposition: "no_state_change",
      evaluationSha256: `Y${"A".repeat(42)}`,
      identitySha256: `Q${"A".repeat(42)}`,
      ordinal: 1,
      sourceId: "d1.alert_runtime",
    },
  ];
}

describe("alert evaluator proof serializer", () => {
  it("fixes known vectors and separates source and decision domains", async () => {
    expect(await alertEvaluatorSourceManifestDigest(sources())).toBe(
      "gDAZQaCG9y9t8HnWnHTqhluHAB-TdHrz-DcQo_2m-RU",
    );
    const emptyDecision = await alertEvaluatorDecisionManifestDigest([]);
    expect(emptyDecision).toBe("fpdV6lJ7NJ4ig-EdtHYnc7Sgt3ZXSPyVtVAAIopRjVU");
    expect(await alertEvaluatorDecisionManifestDigest(decisions())).toBe(
      "GRdurR_ADRh5uy8fPsSeOwTbTi9uM0VXJErabnohFQ8",
    );
    expect(emptyDecision).not.toBe(await alertEvaluatorSourceManifestDigest(sources()));
  });

  it("sorts the closed source set canonically", async () => {
    expect(await alertEvaluatorSourceManifestDigest(sources().toReversed())).toBe(
      await alertEvaluatorSourceManifestDigest(sources()),
    );
  });

  it("rejects missing, duplicate, sparse, and malformed sources uniformly", async () => {
    const expected = new TypeError("invalid alert run proof");
    await expect(alertEvaluatorSourceManifestDigest(sources().slice(1)))
      .rejects.toEqual(expected);
    const duplicate = sources();
    duplicate[8] = duplicate[0];
    await expect(alertEvaluatorSourceManifestDigest(duplicate))
      .rejects.toEqual(expected);
    const sparse = sources();
    delete sparse[4];
    await expect(alertEvaluatorSourceManifestDigest(sparse))
      .rejects.toEqual(expected);
    await expect(alertEvaluatorSourceManifestDigest([
      ...sources().slice(0, 8),
      { ...sources()[8], status: "unknown" as "complete" },
    ])).rejects.toEqual(expected);
    await expect(alertEvaluatorSourceManifestDigest([
      ...sources().slice(0, 8),
      { ...sources()[8], incompleteCount: 1 },
    ])).rejects.toEqual(expected);
    await expect(alertEvaluatorSourceManifestDigest([
      ...sources().slice(0, 8),
      { ...sources()[8], proofSha256: "a".repeat(64) },
    ])).rejects.toEqual(expected);
  });

  it("requires contiguous ordered decisions and unique identities", async () => {
    const expected = new TypeError("invalid alert run proof");
    await expect(alertEvaluatorDecisionManifestDigest([decision(1)]))
      .rejects.toEqual(expected);
    await expect(alertEvaluatorDecisionManifestDigest([decision(1), decision(0)]))
      .rejects.toEqual(expected);
    await expect(alertEvaluatorDecisionManifestDigest(decisions().toReversed()))
      .rejects.toEqual(expected);
    await expect(alertEvaluatorDecisionManifestDigest([
      decision(0),
      decision(1),
    ])).rejects.toEqual(expected);
    const sparse = [decision(0), decision(1, `Q${"A".repeat(42)}`)];
    delete sparse[1];
    await expect(alertEvaluatorDecisionManifestDigest(sparse))
      .rejects.toEqual(expected);
  });

  it("rejects the removed duplicate disposition", async () => {
    await expect(alertEvaluatorDecisionManifestDigest([
      { ...decision(), disposition: "duplicate" as "applied" },
    ])).rejects.toEqual(new TypeError("invalid alert run proof"));
  });
});
