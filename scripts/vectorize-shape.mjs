// The disk half of SPIKE-09's two mechanical findings.
//
// SPIKE-09 asks five questions about Vectorize. Three are answerable only from
// Cloudflare's documentation and are recorded as prose in
// .planning/phases/14-spike-gate/14-03-SUMMARY.md. Two are answerable from the
// dependencies this repository already has installed, which makes them
// CHECKABLE rather than recalled -- and a fact that can be re-checked by a
// command is a fact that cannot go quietly stale.
//
// This module does the reading; test/vectorize-shape.test.ts holds the recorded
// answers and the assertions. The split is the same one
// scripts/forbidden-tokens.mjs and test/forbidden-tokens.test.ts already use:
// the module owns the extraction, the test owns the expectation.
//
// WHY A .mjs AT ALL. The test needs two files off disk and this project
// deliberately installs no Node type package -- tsconfig.json pins `types` to
// the two Cloudflare ones, so `import { readFileSync } from "node:fs"` inside a
// .ts file fails typecheck with TS2307. Filesystem access therefore lives in an
// untypechecked .mjs and is imported from the test, exactly as
// test/forbidden-tokens.test.ts explains in its own header.
//
// Both readers throw rather than returning a default. A reader that answered
// "no methods" or "no plugin" when the shape it was looking for had MOVED would
// turn a dependency rename into a silently different verdict, which is the one
// failure mode this whole module exists to prevent.

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

/** The installed types package that declares the Vectorize binding. */
const WORKERS_TYPES_PACKAGE = "@cloudflare/workers-types";

/** The installed test-runtime build whose Vectorize plugin decides whether a
 *  binding in the pool talks to a local simulator or to the real account. */
const MINIFLARE_PACKAGE = "miniflare";

/**
 * Read an installed package's version from its own package.json, so a verdict
 * can name the exact build it was measured against.
 *
 * @param {string} packageName
 * @returns {string}
 */
function installedVersion(packageName) {
  const manifestPath = require.resolve(`${packageName}/package.json`);
  const version = JSON.parse(readFileSync(manifestPath, "utf8")).version;
  if (typeof version !== "string" || version.length === 0) {
    throw new Error(`${packageName}/package.json declares no version string.`);
  }
  return version;
}

/**
 * The body of a top-level `declare abstract class <name> {` block.
 *
 * The close is found as a `}` at the START of a line, which is how every
 * top-level declaration in a .d.ts closes -- members are indented. That is
 * cheaper than a brace counter and immune to the braces a JSDoc `{@link}` would
 * otherwise contribute, and it is checked afterwards: a body that swallowed a
 * later `declare` has run past its class and throws instead of answering.
 *
 * @param {string} source
 * @param {string} className
 * @returns {string}
 */
function abstractClassBody(source, className) {
  const marker = `declare abstract class ${className} {`;
  const start = source.indexOf(marker);
  if (start === -1) {
    throw new Error(
      `${WORKERS_TYPES_PACKAGE} no longer declares \`${marker}\`. ` +
        `The Vectorize binding has been renamed, removed, or restructured, and ` +
        `SPIKE-09's delete-by-namespace verdict was read off that declaration.`,
    );
  }
  const bodyStart = start + marker.length;
  const end = source.indexOf("\n}", bodyStart);
  if (end === -1) {
    throw new Error(
      `Could not find the closing brace of \`${className}\` in ${WORKERS_TYPES_PACKAGE}.`,
    );
  }
  const body = source.slice(bodyStart, end);
  if (body.includes("declare ")) {
    throw new Error(
      `The extracted body of \`${className}\` contains another \`declare\`, ` +
        `so the close was missed and the method list would be wrong.`,
    );
  }
  return body;
}

/**
 * Every method name declared on the installed `Vectorize` abstract class.
 *
 * This is SPIKE-09 question (1), and the finding is what is ABSENT. Returned
 * sorted so the test's recorded set can be compared as a set rather than as an
 * ordering the types file happens to use today.
 *
 * `VectorizeIndex` -- the deprecated v1 class in the same file -- is
 * deliberately NOT read. The v2 class is what a binding declared today resolves
 * to, and it is the one whose method list decides the deletion design.
 *
 * @returns {{ version: string, className: string, methods: string[] }}
 */
export function vectorizeBindingMethods() {
  const source = readFileSync(
    require.resolve(`${WORKERS_TYPES_PACKAGE}/index.d.ts`),
    "utf8",
  );
  const className = "Vectorize";
  const body = abstractClassBody(source, className);

  // A member is a METHOD when a call signature or a type-parameter list opens
  // immediately after its name. A `public readonly foo: T` property would not
  // match, which is correct -- the question is what can be CALLED.
  const methods = [
    ...body.matchAll(/^\s*public\s+([A-Za-z_$][\w$]*)\s*[(<]/gm),
  ].map((match) => match[1]);

  if (methods.length === 0) {
    throw new Error(
      `\`${className}\` was found in ${WORKERS_TYPES_PACKAGE} but declares no ` +
        `public methods, which cannot be right -- the extractor has stopped matching.`,
    );
  }

  return {
    version: installedVersion(WORKERS_TYPES_PACKAGE),
    className,
    methods: [...methods].sort(),
  };
}

/**
 * The body of a top-level `var <name> = { ... };` object in a bundled build.
 *
 * Same line-anchored close as `abstractClassBody`, for the same reason: the
 * bundler emits top-level declarations closing with `};` at column zero.
 *
 * @param {string} source
 * @param {string} variableName
 * @returns {string}
 */
function topLevelObjectBody(source, variableName) {
  const marker = `var ${variableName} = {`;
  const start = source.indexOf(marker);
  if (start === -1) {
    throw new Error(
      `${MINIFLARE_PACKAGE} no longer declares \`${marker}\`. ` +
        `SPIKE-09's "the pool does not simulate Vectorize" verdict was read off ` +
        `that object, and it can no longer be re-checked.`,
    );
  }
  const bodyStart = start + marker.length;
  const end = source.indexOf("\n};", bodyStart);
  if (end === -1) {
    throw new Error(
      `Could not find the close of \`${variableName}\` in ${MINIFLARE_PACKAGE}.`,
    );
  }
  return source.slice(bodyStart, end);
}

/**
 * What the installed miniflare's Vectorize plugin actually builds.
 *
 * This is SPIKE-09 question (2). The plugin is read rather than the
 * documentation, because the question is not "does the pool support a Vectorize
 * binding" -- it does -- but "does a call through that binding reach a local
 * simulator or the real account". Those are different questions and the second
 * is the one isolation testing depends on.
 *
 * `services` is the set of service NAMES the plugin's `getServices` can return.
 * A local simulator would have to appear there as a storage or gateway service;
 * a set holding only the remote proxy is the finding.
 *
 * @returns {{
 *   version: string,
 *   remoteServiceName: string,
 *   services: string[],
 *   bindingUsesRemoteService: boolean,
 *   servicesUseRemoteProxyClientWorker: boolean,
 *   nodeBindingIsProxy: boolean,
 * }}
 */
export function miniflareVectorizePlugin() {
  const source = readFileSync(
    require.resolve(`${MINIFLARE_PACKAGE}/dist/src/index.js`),
    "utf8",
  );

  const remoteServiceMatch =
    /var VECTORIZE_REMOTE_SERVICE_NAME = `\$\{VECTORIZE_PLUGIN_NAME\}:([a-z]+)`/.exec(
      source,
    );
  const pluginNameMatch = /var VECTORIZE_PLUGIN_NAME = "([a-z-]+)"/.exec(source);
  if (!remoteServiceMatch || !pluginNameMatch) {
    throw new Error(
      `${MINIFLARE_PACKAGE} no longer declares VECTORIZE_PLUGIN_NAME and ` +
        `VECTORIZE_REMOTE_SERVICE_NAME in the shape SPIKE-09 read them in.`,
    );
  }
  const remoteServiceName = `${pluginNameMatch[1]}:${remoteServiceMatch[1]}`;

  const body = topLevelObjectBody(source, "VECTORIZE_PLUGIN");
  const getServicesStart = body.indexOf("async getServices(");
  if (getServicesStart === -1) {
    throw new Error(
      `VECTORIZE_PLUGIN no longer has an \`async getServices\`, so the set of ` +
        `services it can return cannot be read.`,
    );
  }
  const getServices = body.slice(getServicesStart);
  const getBindings = body.slice(0, body.indexOf("getNodeBindings("));

  // Every `name:` the getServices body can put on a service. A local simulator
  // would need one of its own here; the constant is a reference rather than a
  // literal, so it is matched by identifier.
  const services = [
    ...new Set(
      [...getServices.matchAll(/name:\s*([A-Za-z_$][\w$]*)/g)].map((m) =>
        m[1] === "VECTORIZE_REMOTE_SERVICE_NAME" ? remoteServiceName : m[1],
      ),
    ),
  ].sort();

  return {
    version: installedVersion(MINIFLARE_PACKAGE),
    remoteServiceName,
    services,
    bindingUsesRemoteService: getBindings.includes(
      "VECTORIZE_REMOTE_SERVICE_NAME",
    ),
    servicesUseRemoteProxyClientWorker: getServices.includes(
      "remoteProxyClientWorker()",
    ),
    nodeBindingIsProxy: body.includes("new ProxyNodeBinding()"),
  };
}
