<!--
Thanks for contributing! Before opening, please read ARCHITECTURE.md —
especially the "Safety model", which the scanner enforces on every commit.
-->

## What this changes

A short description of the change and why.

## Related issue

Closes #…

## Checklist

- [ ] `npm run typecheck` passes.
- [ ] `npm run scan` passes (the safety scanner).
- [ ] `npm test` passes (~2,400 tests).
- [ ] I did not weaken any rule in `scripts/forbidden-tokens.mjs` to make a commit pass.
- [ ] No secrets, credentials, or real personal data are in the diff.
- [ ] If I touched a safety-critical module (`src/mail/socket.ts`,
      `src/mail/service.ts`, `src/dav/transport.ts`, `src/dav/discovery.ts`, the
      confirmation flow, or OAuth/host validation), I explain why below.

## Safety-critical notes

If this touches a safety boundary, explain what changed and why it is still safe.
Otherwise, write "n/a".
