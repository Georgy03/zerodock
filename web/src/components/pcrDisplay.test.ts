import { describe, expect, it } from "vitest";
import { buildPCRDisplayRows } from "./pcrDisplay";

describe("buildPCRDisplayRows", () => {
  it("sorts indexes numerically and collapses consecutive zero PCRs", () => {
    const rows = buildPCRDisplayRows({
      "11": "0".repeat(96),
      "2": "pcr-two",
      "10": "0".repeat(96),
      "1": "pcr-one",
      "5": "0".repeat(96),
      "6": "0".repeat(96),
    });

    expect(rows.map((row) => [row.label, row.value])).toEqual([
      ["PCR1", "pcr-one"],
      ["PCR2", "pcr-two"],
      ["PCR5–6", "all zero (expected)"],
      ["PCR10–11", "all zero (expected)"],
    ]);
  });
});
