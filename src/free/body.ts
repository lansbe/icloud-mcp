export class BodyLimitError extends Error {
  constructor(readonly status: 408 | 413) { super("request-body-limit"); }
}

// Absolute deadline, including gaps between chunks. Cancelling a malicious
// stream is best effort and must never hold a shared application slot open.
export async function boundedBody(body: ReadableStream<Uint8Array>, max: number, timeoutMs = 10000): Promise<Uint8Array> {
  const reader = body.getReader();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new BodyLimitError(408)), timeoutMs);
  });
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const part = await Promise.race([reader.read(), deadline]);
      if (part.done) break;
      length += part.value.byteLength;
      if (length > max) throw new BodyLimitError(413);
      chunks.push(part.value);
    }
    const out = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.byteLength; }
    return out;
  } catch (error) {
    void reader.cancel().catch(() => {});
    throw error;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    reader.releaseLock();
  }
}
