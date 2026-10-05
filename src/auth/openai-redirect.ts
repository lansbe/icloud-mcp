// Copy the exact URI from the OpenAI MCP connection management page. The
// documented patterns are not themselves an authorization wildcard.
export function validOpenAiRedirect(value: unknown): value is string {
  return typeof value === "string" && value === value.trim() &&
    /^https:\/\/chatgpt\.com\/(?:connector_platform_oauth_redirect|connector\/oauth\/[A-Za-z0-9_-]{1,128})$/.test(value);
}

export function matchesOpenAiRedirect(uri: string, configured: unknown): boolean {
  return validOpenAiRedirect(configured) && uri === configured;
}
