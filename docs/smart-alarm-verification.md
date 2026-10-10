# Smart Alarm verification before merge

This draft continues Steven Landau's one-off alarm and Smart Alarm work from
[#70](https://github.com/steipete/eightctl/pull/70) and
[#72](https://github.com/steipete/eightctl/pull/72). It makes thermal wake opt-in.
Automated tests exercise flag parsing, request serialization and synthetic
responses. They do **not** prove the provider contract or physical wake behavior.
No controlled-account evidence is included yet, and maintainer sponsorship of
this capability in core remains a separate decision.

The proposed flow is POST `/v1/users/{user_id}/alarms` on
`https://app-api.8slp.net`, followed by GET `/v2/users/{user_id}/alarms` for Smart
Alarm read-back. These paths are implementation assumptions awaiting verification.
Existing list/create/update/delete and alarm action routes are unchanged;
[#110](https://github.com/steipete/eightctl/issues/110) owns that migration.
Skip-next is also separate feature work.

## Authorization and preparation

Before any live test, obtain explicit authorization from the controller of a
compatible account and Pod for the target user/bed side, disposable alarm time,
vibration settings, thermal setting, and cleanup. Authorization to develop or
open this PR does not authorize account or device mutations.

1. A maintainer decides whether to sponsor the bounded core integration.
2. Use the official app to capture a private baseline of all existing alarms and
   their recurrence, vibration, thermal, audio and Smart Alarm settings. Choose a
   disposable alarm time that cannot interrupt sleep or another household member.
3. Capture and redact official-app contracts for the one-off creation, alarm
   listing and deletion needed by this feature, including host, method, path,
   required defaults, payload, status and response envelope. Confirm recurrence
   omission and nested-setting semantics. Establish cleanup before creating any
   test alarm; do not guess a deletion route or use the known-broken legacy CLI.

## Controlled test and cleanup

After the contracts and the exact actions are authorized:

1. Create one disposable alarm for the selected user with `--smart` and no
   thermal setting, using a clean test configuration with no thermal override.
   Read it back through the provider and official app. Require the matching ID,
   one-off time/recurrence, `smart.lightSleepEnabled=true`,
   `smart.sleepCapEnabled=false`, `smart.sleepCapMinutes=480`, the requested
   vibration settings, and **thermal wake disabled**.
2. If separately authorized, test an explicit thermal level and confirm that
   exact level, then `--no-thermal` with a supplied level and confirm disabled
   thermal wake. Do not infer the disabled state from the level alone.
3. Check that unrelated alarms and their nested settings match the baseline.
   Provider persistence alone does not prove light-sleep waking or device effects;
   record any authorized official-app/device observation separately.
4. Delete only the disposable alarms using the confirmed official-app flow.
   Verify they are absent from both list read-back and the app, then restore and
   compare the baseline. Preserve the local receipt and use its confirmed token
   with `--after-attempt` for each separately authorized subsequent creation.
   If creation is uncertain, stop: a POST may have succeeded even when read-back
   failed. Pending receipts and interrupted-process locks cannot be automatically
   reset. See [attempt protection and recovery limits](smart-alarm-attempts.md).

## Evidence to attach

- Tested commit, account/Pod compatibility in general terms, date and test cases.
- Sanitized request/response fixtures with consistent synthetic user/alarm IDs,
  preserving methods, paths, payload shape and relevant settings.
- Redacted before/after read-back and cleanup results, plus any observed wake
  behavior; distinguish HTTP acceptance, persistence and device effects.
- Explicit maintainer support decision and any remaining limitations.

Keep credentials, authorization headers, tokens, real account/device identifiers,
household data and raw logs private. Attach only deliberately redacted evidence.
Keep the PR draft until the provider evidence and support decision are resolved.
