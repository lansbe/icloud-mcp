// A deployment-level gate for the first live acceptance session. It does not
// change the tool inventory or credentials' upstream permissions. Apple app
// passwords are not read-only credentials; this server enforces the restriction.
export interface ValidationEnvironment {
  ACCESS_MODE?: string;
  FREE_APPLICATION?: unknown;
}

export function readOnlyValidation(env: ValidationEnvironment): boolean {
  // Legacy deployments without the Free binding retain their original mode.
  // A missing or misspelled mode on Free fails closed.
  return env.ACCESS_MODE !== "full" &&
    (env.ACCESS_MODE !== undefined || env.FREE_APPLICATION !== undefined);
}

export const VALIDATION_READ_TOOLS: ReadonlySet<string> = new Set([
  "account_whoami", "mail_imap_diagnose", "dav_diagnose",
  "mail_list_folders", "mail_list_messages", "mail_list_unread", "mail_find",
  "mail_get_message", "mail_get_attachment",
  "calendar_list_calendars", "calendar_list_events", "calendar_get_event",
  "calendar_search", "calendar_find_free_slots", "contacts_search", "contacts_get",
  "changes_since", "rules_list",
]);

export const VALIDATION_MAIL_TOOLS: ReadonlySet<string> = new Set([
  "account_whoami", "mail_imap_diagnose", "mail_list_folders", "mail_list_messages",
  "mail_list_unread", "mail_find", "mail_get_message", "mail_get_attachment",
]);

export function validationReadTools(env: ValidationEnvironment): ReadonlySet<string> {
  return env.ACCESS_MODE === "read-only" ? VALIDATION_READ_TOOLS : VALIDATION_MAIL_TOOLS;
}

export const VALIDATION_NOTICE = "This deployment is in read-only validation mode. " +
  "Only account diagnostics and explicit mail, calendar and contacts reads are enabled. " +
  "Writes, previews, file staging/download links, semantic indexing/search and autonomous rules are disabled. " +
  "Do not request a mode change to complete a tool call.";

export const MAIL_VALIDATION_NOTICE = "This deployment permits only iCloud Mail reads and account diagnostics. " +
  "Calendar, contacts, changes_since, all writes, staging/download links, semantic indexing/search " +
  "and autonomous rules are disabled. Do not request a mode change to complete a tool call.";
