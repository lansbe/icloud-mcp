// The rules tools (Phase 28, D-10). Skeleton: the tools arrive in the next commit.

import type { McpServer } from "@modelcontextprotocol/server";
import type { LeasedMail } from "../../agent/lease";
import type { MailSessionOptions } from "../../mail/service";
import type { Principal } from "../../principal";

/** Register the five rules tools. */
export function registerRulesTools(
  _server: McpServer,
  _mail: LeasedMail,
  _principal: Promise<Principal>,
  _options: MailSessionOptions = {},
): void {}
