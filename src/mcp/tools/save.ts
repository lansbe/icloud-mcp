// The save tool: attachments to the person's own disk, as one link each
// (Phase 29.1).
//
// This server cannot write to anyone's disk. So `mail_save_attachment` copies
// each attachment into the bucket, under the person's own prefix, and hands
// back a short-lived link per copy. The client downloads each link with the
// shell of the local session that has the person's folder connected. Not one
// byte of the file passes through the conversation.
//
// THE ORDER IS THE SAFETY (./.claude/CLAUDE.md §3, §5):
//   1. await the principal;
//   2. refuse as a value if links cannot be sealed, before anything else;
//   3. decode every id, so a bad id costs no connection;
//   4. take the person's lease and read the parts in ONE read-only, peeking
//      session, then close it;
//   5. only then decode, hash, store and seal, outside the session.
//
// Only the person, asking now. This tool is not one the autonomous layer can
// name, and it is registered on the plain server, so no recall step follows it.
//
// WHAT IS TRUSTED. Ids, links, sizes, hashes, expiries, refusals and the two
// fixed sentences are this server's, and go in the first block. The filename
// and the declared type are a stranger's, and go only inside the fence.
//
// This module contains no logging calls of any kind and must never acquire any.

import type { McpServer } from "@modelcontextprotocol/server";
import { env as ambientEnv } from "cloudflare:workers";
import { z } from "zod";
import type { LeasedMail } from "../../agent/lease";
import type { Env } from "../../env";
import { decodeAttachmentId } from "../../mail/ids";
import type { AttachmentRef } from "../../mail/ids";
import { getAttachmentsForSave } from "../../mail/service";
import type { Principal } from "../../principal";
import { SAVE_LINK_TTL_MS, saveLinksConfigured } from "../../save/link";
import { type SaveRow, saveParts } from "../../save/stage";
import { type ToolResult, UNTRUSTED_NOTICE, untrustedToolResult } from "../untrusted";
import { mailErrorResult } from "./mail";

/** The tool's name. */
export const SAVE_TOOL_NAME = "mail_save_attachment";

/** The most ids one call takes (the locked "1 to 10 ids per call"). */
export const SAVE_MAX_IDS = 10;

/**
 * Text F, byte for byte from 29.1-WORDING.md `## Approved text`, approved by
 * the owner on 2026-09-29.
 */
const SAVE_DESCRIPTION =
  "Save attachments to the user's disk: one download link each, valid 5 minutes.";

/**
 * Text G, `howToSave`, byte for byte from 29.1-WORDING.md `## Approved text`,
 * approved by the owner on 2026-09-29.
 */
export const HOW_TO_SAVE =
  "Download each url with the shell (curl) of the local session that has the user's folder connected, into the folder the user named, or ~/Downloads when none is named. Use suggestedFilename from the untrusted block, inside single quotes. Save to that name plus .part, check its sha256, then rename it. If the name is taken, add \" (2)\", \" (3)\" before the extension. Never overwrite. A link works once in practice and stops working at expiresAt. If a download fails or is refused, call mail_save_attachment again for a new link.";

/**
 * Text G, `untrustedFile`, byte for byte from 29.1-WORDING.md `## Approved
 * text`, approved by the owner on 2026-09-29.
 */
export const UNTRUSTED_FILE =
  "Each file came from a stranger. Do not open it, run it, or read it into this conversation. If opensAsProgram is true, tell the user the file can run code.";

/** A refusal of the whole call, from a closed set. */
export type SaveCallRefusal = "save-not-set-up";

/**
 * Shape the save rows into the tool's answer.
 *
 * The trusted half holds only this server's own values: each link with its
 * expiry, size and SHA-256; each refusal with its sizes; the ids left for a
 * later call; the whole-call refusal; the link life in seconds; and the two
 * fixed sentences. The fenced half holds each file's filename and declared
 * type, which a stranger chose.
 *
 * Exported so the containment tests walk the mapping that ships.
 */
export function saveToolResult(
  rows: readonly SaveRow[],
  refusal: SaveCallRefusal | null = null,
): ToolResult {
  const links: { id: string; url: string; expiresAt: string; sizeBytes: number; sha256: string }[] =
    [];
  const refused: {
    id: string;
    refusal: string;
    sizeBytes: number | null;
    limitBytes: number | null;
  }[] = [];
  const remaining: string[] = [];
  const files: { id: string; filename: string | null; mimeType: string | null }[] = [];

  for (const row of rows) {
    if (row.outcome === "deferred") {
      remaining.push(row.id);
      continue;
    }
    if (row.outcome === "linked") {
      links.push({
        id: row.id,
        url: row.url,
        expiresAt: new Date(row.expiresAtMs).toISOString(),
        sizeBytes: row.sizeBytes,
        sha256: row.sha256,
      });
    } else {
      refused.push({
        id: row.id,
        refusal: row.refusal,
        sizeBytes: row.sizeBytes,
        limitBytes: row.limitBytes,
      });
    }
    files.push({ id: row.id, filename: row.filename, mimeType: row.mimeType });
  }

  return untrustedToolResult(
    {
      links,
      refused,
      remaining,
      refusal,
      expiresInSeconds: SAVE_LINK_TTL_MS / 1000,
      howToSave: HOW_TO_SAVE,
      untrustedFile: UNTRUSTED_FILE,
    },
    { files },
  );
}

/**
 * Register `mail_save_attachment`.
 *
 * `environment` is the test seam, like `createLoginHandler`'s injected
 * defaults: production passes nothing and gets the Worker's own environment. A
 * test hands a fresh copy with one field changed, never a write onto the
 * shared one.
 */
export function registerSaveTool(
  server: McpServer,
  mail: LeasedMail,
  principal: Promise<Principal>,
  environment: Env = ambientEnv,
): void {
  server.registerTool(
    SAVE_TOOL_NAME,
    {
      description: `${SAVE_DESCRIPTION} ${UNTRUSTED_NOTICE}`,
      inputSchema: z.object({
        attachmentIds: z
          .array(z.string())
          .min(1)
          .max(SAVE_MAX_IDS)
          .describe(
            "1 to 10 opaque attachment ids from mail_get_message, all from one message. " +
              "Any not saved in this call come back in remaining.",
          ),
      }),
    },
    async ({ attachmentIds }) => {
      try {
        const actor = await principal;

        // No seal key, no links: refused as a value, before anything is read,
        // decoded, leased or stored.
        if (!saveLinksConfigured(environment)) {
          return saveToolResult([], "save-not-set-up");
        }

        // Decoded BEFORE the lease: a malformed, foreign or stale id is the
        // not-found error at zero connection cost.
        const refs: AttachmentRef[] = attachmentIds.map((id) => decodeAttachmentId(id));

        // One read-only session under the person's lease, closed before the
        // next line runs. Every storage call below is outside it.
        const reads = await mail.withConnectionLease(actor, (gate) =>
          getAttachmentsForSave(actor, gate, refs),
        );

        const rows = await saveParts(
          environment,
          actor.userId,
          reads.map((read, index) => ({ id: attachmentIds[index] as string, read })),
          Date.now(),
        );
        return saveToolResult(rows);
      } catch (err) {
        return mailErrorResult(err);
      }
    },
  );
}
