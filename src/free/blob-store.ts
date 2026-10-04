import type { Env } from "../env";
import { BLOB_CHUNK_BYTES, type BlobHead, type BlobMetadata } from "./blob-vault";

export class FreeStorageError extends Error {
  constructor() { super("temporary-storage-unavailable-or-full"); }
}

export function vaultOf(env: Env) {
  if (!env.FREE_BLOBS) throw new FreeStorageError();
  return env.FREE_BLOBS.getByName("attachments-v1");
}

export async function writeBlob(env: Env, key: string, bytes: Uint8Array, metadata: BlobMetadata): Promise<void> {
  const vault = vaultOf(env);
  if (!(await vault.begin(key, bytes.byteLength, metadata))) throw new FreeStorageError();
  try {
    for (let offset = 0; offset < bytes.byteLength; offset += BLOB_CHUNK_BYTES) {
      if (!(await vault.writeChunk(key, offset / BLOB_CHUNK_BYTES, bytes.slice(offset, offset + BLOB_CHUNK_BYTES)))) {
        throw new FreeStorageError();
      }
    }
    if (!(await vault.finish(key))) throw new FreeStorageError();
  } catch {
    await vault.remove([key]).catch(() => undefined);
    throw new FreeStorageError();
  }
}

function streamBlob(env: Env, head: BlobHead): ReadableStream<Uint8Array> {
  const vault = vaultOf(env);
  let offset = 0;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (offset >= head.size) { controller.close(); return; }
      const bytes = await vault.readChunk(head.key, offset / BLOB_CHUNK_BYTES);
      if (!bytes || bytes.byteLength !== Math.min(BLOB_CHUNK_BYTES, head.size - offset)) {
        controller.error(new FreeStorageError()); return;
      }
      offset += bytes.byteLength;
      controller.enqueue(new Uint8Array(bytes));
    },
  }, { highWaterMark: 0 });
}

// A small structural port shared with the upstream storage binding. The Free
// configuration has no R2 binding and this adapter never accesses a remote API.
export function attachmentStore(env: Env) {
  if (!env.FREE_BLOBS) return env.ATTACHMENT_STAGING;
  return {
    async put(key: string, bytes: Uint8Array, options?: R2PutOptions) {
      const http = options?.httpMetadata;
      await writeBlob(env, key, bytes, {
        contentType: http instanceof Headers ? http.get("content-type") ?? undefined : http?.contentType,
        customMetadata: options?.customMetadata,
      });
    },
    head: (key: string) => vaultOf(env).head(key),
    async get(key: string) {
      const head = await vaultOf(env).head(key);
      if (!head) return null;
      return { ...head, body: streamBlob(env, head),
        arrayBuffer: () => new Response(streamBlob(env, head)).arrayBuffer() };
    },
    delete: (keys: string | string[]) => vaultOf(env).remove(typeof keys === "string" ? [keys] : keys),
    async list(options?: {prefix?: string}) {
      return { objects: await vaultOf(env).list(options?.prefix ?? ""), truncated: false as const };
    },
  };
}
