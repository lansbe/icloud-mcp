// Types for scripts/vectorize-shape.mjs.
//
// The reader is plain Node ESM for the same reason scripts/forbidden-tokens.mjs
// is: it reads files off disk, and this project installs no Node type package
// (tsconfig.json pins `types` to the two Cloudflare ones), so a `node:fs`
// import inside a .ts file fails typecheck with TS2307. This declaration exists
// so test/vectorize-shape.test.ts can import it under `strict` without the
// project enabling `allowJs`, which would pull every script in scripts/ into
// the typecheck program.
//
// The shape here is not load-bearing on its own: the test asserts on runtime
// values, so a drift between this file and the implementation surfaces as a
// failing test rather than as a silent lie.

/** What the installed `Vectorize` abstract class declares. */
export interface VectorizeBindingShape {
  /** The installed @cloudflare/workers-types version the list was read from. */
  version: string;
  /** The class the list was read from — the v2 `Vectorize`, never the
   *  deprecated `VectorizeIndex`. */
  className: string;
  /** Every public method name, sorted. The finding is what is ABSENT. */
  methods: string[];
}

/** What the installed miniflare's Vectorize plugin actually builds. */
export interface MiniflareVectorizePluginShape {
  /** The installed miniflare version the reading was taken from. */
  version: string;
  /** The remote proxy service name, resolved from miniflare's own constants. */
  remoteServiceName: string;
  /** Every service name `getServices` can return, sorted. A local simulator
   *  would have to appear here. */
  services: string[];
  /** Whether the binding handed to a test points at the remote service. */
  bindingUsesRemoteService: boolean;
  /** Whether `getServices` stands up a remote proxy client worker. */
  servicesUseRemoteProxyClientWorker: boolean;
  /** Whether `getNodeBindings` returns a proxy binding. */
  nodeBindingIsProxy: boolean;
}

export declare function vectorizeBindingMethods(): VectorizeBindingShape;
export declare function miniflareVectorizePlugin(): MiniflareVectorizePluginShape;
