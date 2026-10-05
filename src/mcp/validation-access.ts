import type { McpServer } from "@modelcontextprotocol/server";
import { VALIDATION_READ_TOOLS } from "../validation-access";

/** Keep all schemas visible, but refuse unapproved callbacks before any work. */
export function withValidationAccess(server: McpServer, restricted: boolean, allowed = VALIDATION_READ_TOOLS): McpServer {
  if (!restricted) return server;
  return new Proxy(server, {
    get(target, property) {
      if (property === "registerTool") return (
        name: string, config: unknown, callback: (...args: unknown[]) => unknown,
      ) => target.registerTool(name, config as never, (async (...args: unknown[]) => {
        if (!allowed.has(name)) return {
          isError: true,
          content: [{ type: "text", text: JSON.stringify({
            category: "read_only_validation",
            message: "This tool is disabled during read-only validation. No action was performed.",
          }) }],
        };
        return callback(...args);
      }) as never);
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}
