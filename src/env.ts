// The Worker's binding surface.
//
// `Cloudflare.Env` is the type the runtime's ambient `env` (from the
// "cloudflare:workers" module) resolves to. `@cloudflare/workers-types` ships
// it as an empty interface and invites projects to merge their own
// declaration into it. Declaring it once here — rather than declaring a
// separate `Env` interface and a matching global augmentation — means the
// ambient `env` and every explicitly-passed `env` are the same type by
// construction and cannot drift apart.

import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";

declare global {
  namespace Cloudflare {
    interface Env {
      /**
       * Token, grant, and client storage for the OAuth provider.
       *
       * The binding name is NOT configurable: the library reads
       * `env.OAUTH_KV` directly in its shipped JavaScript. No Durable Object
       * is involved, which is why wrangler.jsonc carries no migrations block.
       */
      OAUTH_KV: KVNamespace;

      /**
       * Resolved CalDAV / CardDAV discovery metadata (D-58).
       *
       * A namespace of its own rather than a key prefix inside `OAUTH_KV`.
       * That binding holds the OAuth provider's own grants, clients and token
       * records, and the library owns its key prefixes in shipped JavaScript
       * this project does not control — so sharing one keyspace would make
       * isolation a convention only one of the two writers ever agreed to.
       *
       * Entries expire after 24 hours (D-59). Short enough that worst-case
       * staleness stays bounded even if the re-discovery failure path turns
       * out to have a gap, at a cost of two extra PROPFINDs a day.
       *
       * **Discovery metadata only** — the root, principal and home URLs for
       * one service, and nothing else. No event, no contact, no message body
       * is ever written here. PROJECT.md's "local caching is not a product
       * feature" constraint is what draws that line: iCloud stays the system
       * of record, and this namespace only remembers *where* the account
       * lives, never *what* is in it.
       *
       * Typed `KVNamespace`, NOT `KVNamespace | undefined`. The widening on
       * the Secret bindings — those further down, and the three in the narrow
       * interfaces at the end of this file — is a statement about what a Workers
       * Secret is at runtime — unset, deleted, and never-provisioned all
       * arrive absent — and it does not transfer to a namespace binding,
       * which either resolves at deploy time or fails the deploy.
       */
      DAV_CACHE: KVNamespace;

      /**
       * Spent-confirmation records for the calendar write gate (D5-3 option A).
       *
       * A THIRD namespace rather than a key prefix inside `DAV_CACHE`, for the
       * reason `DAV_CACHE` itself gives about `OAUTH_KV`: "just prefix the keys"
       * is a convention only one of the two writers ever agreed to. The argument
       * is weaker here than it was there — both writers are this project's own
       * code, not a library owning its prefixes in shipped JavaScript — but the
       * consequence of a collision is worse. `DAV_CACHE` holds a cache whose
       * corruption costs two extra PROPFINDs; this namespace holds the only
       * record of which capability tokens have already been spent, and a key
       * that collides with a discovery entry is a confirmation that can be
       * replayed.
       *
       * **One key per spent confirmation, and nothing else.** Key
       * `confirm:v1:<jti>`, value `"1"` — the presence of the key is the whole
       * datum, so the value carries no payload to leak and no shape to
       * misparse. The `v1` buys the hedge `DAV_CACHE_KEY_PREFIX` and
       * `TOKEN_VERSION` buy: a future change to the stored shape becomes
       * detectable rather than silently misread as the current one.
       *
       * `expirationTtl` is derived from the token's OWN absolute expiry rather
       * than from a constant, so the record outlives every token it could be
       * asked about and not one second longer, and is floored at 60 because KV
       * refuses less (the same floor `DISCOVERY_TTL_SECONDS` is checked
       * against). A record that expired before its token did would let the
       * token be spent twice.
       *
       * **The honest limitation, stated here rather than left to be
       * discovered:** KV is eventually consistent. A write is not guaranteed
       * visible to a read at another edge location for a short propagation
       * window, so two commits of the same token racing inside that window can
       * BOTH see an absent key and both pass this check. That is not a
       * hypothetical gap this docstring is hedging against; it is how KV works.
       * `If-Match` is the independent second layer that catches it: the loser of
       * the race carries an etag the first write has already invalidated, and
       * the DAV server rejects it with a 412 that no amount of KV staleness can
       * turn into a 200. Neither layer is sufficient alone — this one rejects
       * before any DAV request is issued, which is what the requirement asks
       * for; `If-Match` rejects at the server, which is what actually holds
       * under a race.
       *
       * Typed `KVNamespace`, NOT `KVNamespace | undefined`, for the reason
       * spelled out on `DAV_CACHE` above: the widening on the Secret bindings,
       * here and in the narrow interfaces at the end of this file, is a
       * statement about what a Workers Secret is at runtime, and it
       * does not transfer to a namespace binding, which either resolves at
       * deploy time or fails the deploy.
       */
      CONFIRM_KV: KVNamespace;

      /**
       * Attachment staging bucket (D-83, ATT-03).
       *
       * A bucket of its own rather than a prefix inside an existing store, for
       * the same reason `DAV_CACHE` is a second namespace rather than a key
       * prefix in the first.
       *
       * Holds attachment bytes between the call that stages them and the call
       * that attaches them to a draft — and nothing else, for no longer than it
       * takes. Objects live under a `staging/` prefix that carries a one-day
       * expiration rule; that rule is account state created out of band, is not
       * in git, and its listing is recorded in
       * .planning/phases/04-mail-write-attachments/04-UAT.md. This is a holding
       * area with a sweep behind it, not storage — PROJECT.md's "local caching
       * is not a product feature" constraint draws the same line here it draws
       * for `DAV_CACHE`.
       *
       * Typed `R2Bucket`, NOT `R2Bucket | undefined`, for the reason spelled
       * out on `DAV_CACHE` above: the widening on the Secret bindings, here and
       * in the narrow interfaces at the end of this file, is
       * a statement about what a Workers Secret is at runtime, and it does not
       * transfer to a bucket binding, which either resolves at deploy time or
       * fails the deploy.
       */
      ATTACHMENT_STAGING: R2Bucket;

      /**
       * The Cloudflare account id. A Worker var declared in wrangler.jsonc, not
       * a Secret.
       *
       * Typed `string` with no widening, and the distinction is the point: a
       * `vars` entry is part of the deployed configuration and is present
       * whenever the Worker is, so it does not have the absent-at-runtime
       * property that forces the widening on every binding below. Reading the
       * two apart is easier if the types disagree.
       *
       * Not sensitive — an opaque account handle, not a credential. It is
       * needed to build the host of a presigned upload URL.
       */
      R2_ACCOUNT_ID: string;

      /**
       * Injected by the OAuth provider on every request before it dispatches
       * to a handler. This is how the authorize form reaches
       * `parseAuthRequest` / `completeAuthorization` without the handler
       * holding a reference to the provider instance.
       */
      OAUTH_PROVIDER: OAuthHelpers;

      // The login gate's secret and the two mail secrets are NOT declared
      // here. They live in the narrow interfaces at the end of this file, so
      // code that holds the shared type cannot read them (Phase 9 D-14).

      /**
       * Access key id of the R2 S3 API token. Workers Secret.
       *
       * Source: an R2 API token scoped to the single bucket
       * `icloud-mcp-attachments` with Object Read & Write only — deliberately
       * not the account-wide token the dashboard offers by default, which would
       * be a privilege escalation buying this phase nothing.
       *
       * Admits `undefined` for the same reason the three secrets in the narrow
       * interfaces at the end of this file do, and the
       * absent case is worth naming here because it does not announce itself:
       * a signer handed an absent key produces a syntactically well-formed
       * signature over an empty credential, and the failure surfaces as a
       * rejection from R2 rather than as a missing-configuration error. The
       * compiler finding the consumer that assumes presence is the whole
       * benefit of typing it honestly.
       *
       * Consumed only through the write-only signing helper in
       * src/staging/presign.ts, which takes the value, uses it, and returns
       * nothing that carries it. No object holding either half of this pair is
       * ever constructed, so there is nothing to serialise, attach to an error,
       * or spread into a response (./.claude/CLAUDE.md §4).
       */
      R2_ACCESS_KEY_ID: string | undefined;

      /**
       * Secret access key of the R2 S3 API token. Workers Secret.
       *
       * The other half of the pair above, with the same source, the same
       * widening for the same reason, and the same write-only consumption path.
       * The two are declared together because they are useless apart: neither
       * one alone signs anything, so a check for one is a check for both.
       */
      R2_SECRET_ACCESS_KEY: string | undefined;

      /**
       * HMAC key for the calendar confirmation token (CALW-04). Workers Secret.
       *
       * **Its own Secret, deliberately not `AUTH_SECRET`.** Reusing that one
       * would work and would be one fewer thing to provision, which is exactly
       * why it needs an argument against it: the two keys have different
       * rotation consequences. `AUTH_SECRET` gates the authorize form, and
       * rotating it invalidates nothing that was already granted. This one
       * signs capabilities to write to a calendar, and rotating it must
       * invalidate every outstanding preview immediately — that is the point of
       * rotating it. Sharing one value would couple a routine credential change
       * on one path to a silent capability revocation on the other, in whichever
       * direction the rotation happened to come from. It is likewise not
       * `APPLE_APP_PASSWORD`, which is a credential belonging to Apple rather
       * than a key belonging to this server.
       *
       * Admits `undefined` for the reason `AUTH_SECRET` gives — unset, deleted,
       * and failed-to-provision all arrive absent, and nothing at runtime
       * distinguishes that from a configured value until something reads it.
       * The specific failure the widening exists to surface is worth naming,
       * because it is silent and it fails OPEN rather than closed:
       * `crypto.subtle.importKey` accepts a zero-length raw HMAC key in some
       * implementations rather than throwing, so a server that both signs and
       * verifies with the empty key verifies its own forgeries perfectly and
       * accepts anyone else's too. Every signature is valid; nothing errors;
       * the gate is simply not there. That is CR-01 one module over, on a path
       * whose consequence is a write to the user's real calendar rather than a
       * login form. `src/confirm.ts` therefore fails closed on BOTH mint and
       * verify when this is absent, rather than only on verify — minting under
       * an absent key would produce tokens that outlive the misconfiguration.
       *
       * Consumed only through `src/confirm.ts`, which imports it once as a
       * NON-EXTRACTABLE `CryptoKey` and returns nothing that carries it — the
       * same write-only consumption path `R2_ACCESS_KEY_ID` describes. No
       * object holding this value is ever constructed, so there is nothing to
       * serialise, attach to an error, or spread into a response
       * (./.claude/CLAUDE.md §4). Non-extractable is what makes that structural
       * rather than a habit: the key material cannot be read back out of the
       * `CryptoKey` even by code that holds it.
       */
      CONFIRM_SECRET: string | undefined;

      /**
       * Who may sign in, as a JSON array of Apple IDs. Workers Secret.
       *
       * **On the shared type rather than a narrow interface, and deliberately
       * so.** The three names below this block were moved off the shared type
       * precisely so the compiler would refuse a new reader. This one has TWO
       * legitimate readers by design — the login page, which decides whether a
       * person may sign in at all, and the door, which decides on every served
       * request whether the person in the grant is still permitted — so a
       * narrow interface would have to name both and would say nothing the
       * shared type does not.
       *
       * A Workers Secret rather than a `vars` entry, because `wrangler.jsonc`
       * is git-ignored while `wrangler.jsonc.example` is tracked, and a list of
       * real people's Apple IDs is personal data that should not sit next to a
       * tracked example config even by accident.
       *
       * Admits `undefined` for the reason every Secret above it does: unset,
       * deleted and failed-to-provision all arrive absent, and nothing at
       * runtime tells that apart from a configured value until something reads
       * it. The specific silent failure the widening exists to surface is worth
       * naming, because it is the one that hurts the OWNER rather than a
       * stranger: an absent secret parses as NOBODY, so the login page stops
       * issuing authorizations for everyone including the person who would fix
       * it. `src/auth/allow-list.ts` fails closed on purpose — the other
       * direction would open a server that reaches real personal mail to
       * anyone who can authenticate at Apple — and the 503 body is the channel
       * that says so, because Convention 4 forbids logging anywhere under
       * `src/` and the response is the only diagnostic a locked-out owner has.
       *
       * Consumed only through `parseAllowList` in `src/auth/allow-list.ts`,
       * which reads it, answers a three-member verdict, and hands back nothing
       * that carries the raw value.
       */
      ALLOWED_APPLE_IDS: string | undefined;
    }
  }
}

export type Env = Cloudflare.Env;

// The three narrow secret types (Phase 9 D-14).
//
// These three names used to sit on the shared type above. They were moved out
// so the compiler refuses a new reader: code that holds the shared type cannot
// spell them. They are declared OUTSIDE the global block on purpose. Inside it
// they would be back on the ambient environment object, on every explicit
// parameter of the shared type, and on the test environment, all at once.
//
// Every field is REQUIRED and admits `undefined`. It is not optional. A type
// whose fields are all optional is a weak type, and handing it the shared type
// then fails with an unhelpful "no properties in common" error. With required
// fields the error is the clear "missing the following properties".
//
// The runtime bindings did not change. This is a type change only.

/**
 * The login gate's secret. Seen only by the login gate and the entry point.
 */
export interface LoginGateSecret {
  /**
   * Shared secret for the /authorize form (D-01). Workers Secret.
   *
   * Admits `undefined` because that is what a Workers Secret binding is at
   * runtime: unset, deleted, or failed-to-provision all arrive absent. The
   * previous `string` was a claim the platform does not make, and typing it
   * honestly is what lets the compiler — rather than a reviewer — find the
   * next consumer that assumes presence.
   *
   * The absent case does not announce itself. `TextEncoder.prototype.encode`
   * is declared `encode(optional USVString input = "")`, so `encode(undefined)`
   * resolves to the empty string rather than throwing, and a comparison
   * against an unset secret quietly succeeds against an empty submission
   * (CR-01).
   */
  AUTH_SECRET: string | undefined;
}

/**
 * The two mail secrets. Seen only by the owner's constructor in
 * `src/principal.ts`, by the door that hands it the environment, and by the
 * entry point. Phase 13 removes them and this interface.
 */
export interface OwnerMailSecrets {
  /**
   * Apple ID used for IMAP authentication. Workers Secret.
   *
   * Admits `undefined` for the same reason as `AUTH_SECRET`: an unset,
   * deleted, or failed-to-provision Secret arrives absent, and nothing at
   * runtime distinguishes that from a configured value until something reads
   * it. On the mail path the absent value previously produced a `TypeError`
   * that surfaced as `connection_failed` — a permanently missing secret
   * described to the caller as a transient fault worth retrying (CR-01).
   */
  APPLE_ID: string | undefined;

  /**
   * Apple app-specific password. Workers Secret.
   *
   * Admits `undefined` for the same reason as the two above. All three are
   * widened together deliberately: the runtime fact is identical for every
   * Secret binding, and typing one honestly while leaving the others
   * claiming more than the platform guarantees would read as an oversight
   * rather than a decision (CR-01).
   */
  APPLE_APP_PASSWORD: string | undefined;
}

/**
 * What the runtime really hands the entry point: the shared type plus all
 * three secrets. Only the entry point, the OAuth provider's options and the
 * door are typed with it. Everything past them sees the shared type.
 */
export type EntryEnv = Env & OwnerMailSecrets & LoginGateSecret;
