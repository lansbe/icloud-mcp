// Known-violating sample for scanWranglerConfig's `hostname-hardcoded` check.
//
// This file deliberately hardcodes a DEPLOYED_HOSTNAME literal — the exact
// shape that check exists to reject. The test points scanWranglerConfig at
// this path and asserts it fires, so the check cannot silently match nothing.
// Nothing imports this file; it is data for the scanner, not code.
export const DEPLOYED_HOSTNAME = "icloud-mcp.hardcoded-not-derived.example";
