import { describe, expect, it } from "vitest";
import { boundedBody, BodyLimitError } from "../../src/free/body";

describe("shared application body admission", () => {
  it("has an absolute deadline and never waits for cancellation", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      cancel() { cancelled = true; return new Promise(() => {}); },
    });
    await expect(boundedBody(body, 1024, 20)).rejects.toMatchObject({status: 408});
    expect(cancelled).toBe(true);
  });
  it("rejects streamed bytes above the cap and preserves valid bytes", async () => {
    await expect(boundedBody(new Response("12345").body!, 4)).rejects.toBeInstanceOf(BodyLimitError);
    expect(new TextDecoder().decode(await boundedBody(new Response("1234").body!, 4))).toBe("1234");
  });
});
