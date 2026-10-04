import { boundedBody, BodyLimitError } from "./body";
import type { Env } from "../env";
import { DEPLOYED_HOSTNAME } from "../deployed-hostname.generated";
import { isConfiguredSecret } from "../configured-secret";
import { budgetOf } from "./budget";
import { writeBlob } from "./blob-store";

const PATH = "/upload/";
const TTL = 15 * 60 * 1000;
const MAX_BYTES = 4 * 1024 * 1024;
const KEY = /^staging\/([0-9a-f]{64})\/upload-[0-9a-f]{16}-[0-9]+$/;
interface Claim { key: string; size: number; type: string; filename: string; expires: number }

function encode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function decode(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length > 16000) throw new Error("upload-invalid");
  const bytes = Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  if (encode(bytes) !== value) throw new Error("upload-invalid");
  return bytes;
}
async function signingKey(env: Env): Promise<CryptoKey> {
  if (!isConfiguredSecret(env.CONFIRM_SECRET)) throw new Error("upload-not-configured");
  return crypto.subtle.importKey("raw", new TextEncoder().encode(env.CONFIRM_SECRET),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
const signedBytes = (payload: string) => new TextEncoder().encode(`icloud-mcp:upload:v1:${payload}`);

export async function mintFreeUpload(env: Env, userId: string, input: {
  key: string; contentType: string; contentLength: number; filename: string;
}): Promise<string> {
  if (KEY.exec(input.key)?.[1] !== userId || !Number.isSafeInteger(input.contentLength) ||
      input.contentLength <= 0 || input.contentLength > MAX_BYTES ||
      input.filename.length > 1024 || input.contentType.length > 256 ||
      /[\r\n\x00]/.test(input.contentType)) throw new Error("upload-invalid");
  const claim: Claim = { key: input.key, size: input.contentLength, type: input.contentType,
    filename: encodeURIComponent(input.filename), expires: Date.now() + TTL };
  const payload = encode(new TextEncoder().encode(JSON.stringify(claim)));
  const signature = encode(new Uint8Array(await crypto.subtle.sign("HMAC", await signingKey(env), signedBytes(payload))));
  return `https://${DEPLOYED_HOSTNAME}${PATH}${payload}.${signature}`;
}

export async function handleUpload(request: Request, env: Env): Promise<Response> {
  const refuse = (status: number) => new Response(null, { status, headers: { "cache-control": "no-store" } });
  if (request.method !== "PUT") return refuse(405);
  try {
    const token = new URL(request.url).pathname.slice(PATH.length);
    if (token.length > 16000) return refuse(410);
    const [payload, signature, extra] = token.split(".");
    if (!payload || !signature || extra !== undefined) return refuse(410);
    if (!(await crypto.subtle.verify("HMAC", await signingKey(env), decode(signature), signedBytes(payload)))) return refuse(410);
    const claim = JSON.parse(new TextDecoder().decode(decode(payload))) as Claim;
    if (!KEY.test(claim.key) || !Number.isSafeInteger(claim.expires) || claim.expires <= Date.now() ||
        !Number.isSafeInteger(claim.size) || claim.size <= 0 || claim.size > MAX_BYTES) return refuse(410);
    if (request.headers.get("content-type") !== claim.type ||
        request.headers.get("content-length") !== String(claim.size) ||
        request.headers.get("x-amz-meta-filename") !== claim.filename || !request.body) return refuse(400);
    // Reserve before reading: simultaneous replays cannot replace staged bytes.
    if (!(await budgetOf(env).claim(`upload:${signature}`, claim.expires))) return refuse(410);
    const bytes = await boundedBody(request.body, claim.size);
    if (bytes.byteLength !== claim.size) return refuse(400);
    await writeBlob(env, claim.key, bytes, { contentType: claim.type,
      customMetadata: { filename: claim.filename, declaredType: encodeURIComponent(claim.type),
        declaredSize: String(claim.size), stagedAt: String(Date.now()) } });
    return refuse(201);
  } catch (error) {
    if (error instanceof BodyLimitError) return refuse(error.status);
    return refuse(503);
  }
}
