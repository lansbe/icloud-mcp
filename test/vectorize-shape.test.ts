// SPIKE-09's two MECHANICAL findings, pinned against the dependencies this
// repository actually has installed.
//
// Three of SPIKE-09's five questions are answerable only from Cloudflare's
// documentation, and their answers are prose in
// .planning/phases/14-spike-gate/14-03-SUMMARY.md. The other two are answerable
// from node_modules, which makes them re-checkable by running this file -- and
// a verdict that can be re-checked by a command is a verdict that cannot go
// quietly stale while a phase is planned on top of it.
//
// Both pins are SET EQUALITIES rather than membership checks. A pin that would
// still pass if the set GREW is not pinning anything: the whole point of
// finding (1) is what is ABSENT from the binding, and an absence is only
// provable by an exact set.
//
// This file runs under Node rather than inside workerd (see vitest.config.ts,
// FILESYSTEM_TESTS): it reads node_modules off disk, and a Workers isolate
// resolves readFileSync against a virtual filesystem holding only the bundle,
// so every repository path is a miss. Every filesystem access lives behind
// scripts/vectorize-shape.mjs, because this project installs no Node type
// package and a `node:fs` import in a .ts file fails typecheck.

import { describe, expect, it } from "vitest";
import {
  miniflareVectorizePlugin,
  vectorizeBindingMethods,
} from "../scripts/vectorize-shape.mjs";

/** Every method the shipped `Vectorize` binding exposes, read off
 *  @cloudflare/workers-types 5.20260812.1 on 2026-09-23 and recorded here.
 *  Sorted, because the answer is a SET -- the order the types file happens to
 *  declare them in is not part of the finding. */
const RECORDED_VECTORIZE_METHODS = [
  "deleteByIds",
  "describe",
  "getByIds",
  "insert",
  "query",
  "queryById",
  "upsert",
];

/** Every service the installed miniflare's Vectorize plugin can stand up, read
 *  off miniflare 5.20260811.0-alpha on 2026-09-23. One entry, and it is a
 *  remote proxy. A local simulator would have to appear here. */
const RECORDED_VECTORIZE_SERVICES = ["vectorize:remote"];

describe("SPIKE-09 (1): the Vectorize binding cannot delete a namespace", () => {
  it("exposes exactly the recorded method set, and no more", () => {
    const { methods, className, version } = vectorizeBindingMethods();

    expect(
      methods,
      `The installed Vectorize binding's method set has changed ` +
        `(${className} in @cloudflare/workers-types ${version}). SPIKE-09's ` +
        `verdict -- "there is no delete-by-namespace, so Phase 25's per-user ` +
        `vector-id ledger is MANDATORY rather than optional" -- was read off ` +
        `this exact list on 2026-09-23. Re-read it before trusting the verdict. ` +
        `If the binding has GROWN a namespace-scoped delete, the ledger may ` +
        `become optional again and ARCHITECTURE.md section 4.6(b) should be ` +
        `re-decided rather than re-derived.`,
    ).toEqual(RECORDED_VECTORIZE_METHODS);
  });

  it("offers deletion only by an explicit list of ids", () => {
    const { methods } = vectorizeBindingMethods();

    expect(
      methods.filter((name) => /delete/i.test(name)),
      `The set of deletion verbs on the Vectorize binding has changed. ` +
        `SPIKE-09 found exactly one -- deleteByIds, which takes string[] -- and ` +
        `that single fact is what makes the per-user vector-id ledger ` +
        `mandatory: removing a user's vectors requires already knowing every ` +
        `id that user owns, and an id derived from a digest cannot be ` +
        `enumerated from the user id.`,
    ).toEqual(["deleteByIds"]);
  });

  it("offers no verb whose name mentions a namespace", () => {
    const { methods } = vectorizeBindingMethods();

    // Deliberately a SECOND reading of the same fact, by a different route.
    // The set equality above would also catch a namespace verb appearing, but
    // it would report it as "the set changed" -- this one names the specific
    // capability whose absence the whole deletion design rests on.
    expect(
      methods.filter((name) => /namespace/i.test(name)),
      `A namespace-scoped verb has appeared on the Vectorize binding. ` +
        `SPIKE-09 recorded that the namespace is a QUERY-TIME filter only, ` +
        `with no lifecycle operations of its own.`,
    ).toEqual([]);
  });
});

describe("SPIKE-09 (2): the vitest pool does not simulate Vectorize", () => {
  it("stands up exactly one service for a Vectorize binding, and it is remote", () => {
    const { services, version } = miniflareVectorizePlugin();

    expect(
      services,
      `The installed miniflare's Vectorize plugin (${version}) no longer ` +
        `stands up only a remote proxy. SPIKE-09's verdict -- "there is no ` +
        `local Vectorize simulator, so a hermetic suite cannot prove namespace ` +
        `isolation THROUGH the binding, and Phase 25's isolation proof must be ` +
        `structural instead" -- was read off this exact set on 2026-09-23. A ` +
        `new local storage or gateway service appearing here is exactly when ` +
        `that verdict stops being true.`,
    ).toEqual(RECORDED_VECTORIZE_SERVICES);
  });

  it("routes the binding itself through that remote service", () => {
    const plugin = miniflareVectorizePlugin();

    expect(
      plugin.bindingUsesRemoteService,
      `The Vectorize binding miniflare hands a test is no longer wired to ` +
        `${plugin.remoteServiceName}. SPIKE-09 read the binding's own inner ` +
        `fetcher as pointing at the remote proxy -- that is WHY "available" ` +
        `does not imply "simulated", and it is the sentence that refutes the ` +
        `research note reading pool support at 0.7.2 as local support.`,
    ).toBe(true);

    expect(
      plugin.servicesUseRemoteProxyClientWorker,
      `The Vectorize plugin's getServices no longer returns a remote proxy ` +
        `client worker. If it now returns a local worker, every call a test ` +
        `makes through a Vectorize binding may finally be hermetic, and ` +
        `Phase 25's test strategy can be re-decided.`,
    ).toBe(true);

    expect(
      plugin.nodeBindingIsProxy,
      `The Vectorize plugin's getNodeBindings no longer returns a proxy ` +
        `binding, which was the second half of the same finding.`,
    ).toBe(true);
  });
});
