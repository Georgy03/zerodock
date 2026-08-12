import { describe, expect, it, vi } from "vitest";
import { checkPublishedPCR0, PCRVerificationError, publishedPCRsURL } from "./pcr";

const PCR0_HEX = "ab".repeat(48);
const PCR0_BYTES = new Uint8Array(48).fill(0xab);

describe("checkPublishedPCR0", () => {
  it("accepts a signed PCR0 matching the GitHub release manifest", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ PCR0: PCR0_HEX }));

    const result = await checkPublishedPCR0(PCR0_BYTES, "v1.2.3", fetchMock);

    expect(result.actualPCR0).toBe(PCR0_HEX);
    expect(result.publishedPCR0).toBe(PCR0_HEX);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://raw.githubusercontent.com/Georgy03/zerodock/v1.2.3/pcrs.json",
      expect.any(Object),
    );
    expect(new URL(result.sourceURL).origin).toBe("https://raw.githubusercontent.com");
  });

  it("rejects a correctly-shaped but different published PCR0", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ PCR0: "cd".repeat(48) }));

    const failure = checkPublishedPCR0(PCR0_BYTES, "v1.2.3", fetchMock);
    await expect(failure).rejects.toThrow(PCRVerificationError);
    await expect(failure).rejects.toThrow("does not match published ZeroDock PCR0");
  });

  it.each([
    ["missing PCR0", {}, "must contain"],
    ["short PCR0", { PCR0: "ab" }, "96 hexadecimal"],
    ["non-hex PCR0", { PCR0: "z".repeat(96) }, "96 hexadecimal"],
  ])("fails closed for a malformed manifest: %s", async (_name, body, message) => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(body));
    await expect(checkPublishedPCR0(PCR0_BYTES, "v1.2.3", fetchMock)).rejects.toThrow(message);
  });

  it("fails closed when GitHub is unavailable", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("offline"));
    await expect(checkPublishedPCR0(PCR0_BYTES, "v1.2.3", fetchMock)).rejects.toThrow("Could not fetch");
  });

  it.each([undefined, "", "main", "dev", "../v1.2.3", "v1.2.3/pcrs.json", "https://evil.example/v1.2.3"])(
    "rejects a non-release scanner version without fetching: %s",
    async (version) => {
      const fetchMock = vi.fn();
      await expect(checkPublishedPCR0(PCR0_BYTES, version, fetchMock)).rejects.toThrow(PCRVerificationError);
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it("constructs the manifest URL from an immutable tag and a fixed repository", () => {
    expect(publishedPCRsURL("v2.0.0-rc.1")).toBe(
      "https://raw.githubusercontent.com/Georgy03/zerodock/v2.0.0-rc.1/pcrs.json",
    );
  });
});

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
