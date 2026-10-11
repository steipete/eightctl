# Local one-off creation protection

`alarm create-one-off` stores an attempt receipt before sending one POST.
Creation never automatically retries HTTP failures, authentication failures,
rate limits or redirects. A timeout, unreadable response, missing ID, storage
failure after submission or interrupted process leaves the attempt blocked.
Another invocation cannot bypass an unresolved attempt by changing the payload,
credentials, OAuth client or `--config`. Separate processes share an exclusive
lock for the same provider and resolved target user. Locks have no expiry and
are not automatically removed after a crash.

A usable creation response ID records a **confirmed receipt**. This confirms
only that the response supplied an ID; it does not prove provider persistence,
Smart Alarm settings or physical wake behavior. Repeating the same request
reads the recorded ID through the proposed listing API, with no new POST. A
failed or empty read-back does not clear the receipt or permit retransmission.
Even an empty listing cannot prove that an earlier timed-out POST will never
finish committing.

To intentionally create a later alarm, pass `--after-attempt <token>` using the
latest confirmed token printed by a successful command. The new reservation
consumes that token before submission. Repeating the same acknowledged command
cannot create another alarm. A token cannot unlock a pending attempt; there is
no reset command. Interrupted attempts can remain blocked even if no POST was
sent. This conservative behavior trades availability for avoiding retransmission.

State lives in `~/.config/eightctl/alarm-attempts`, independently of the selected
configuration file. The directory is private (0700), receipts are private
regular files (0600), and updates use atomic rename and file/directory syncing
before submission. Unsupported durability operations, corrupt state, symlink
receipts/state directories and permissive modes fail closed. Receipts contain a
random attempt token, a hashed provider/target scope, a request fingerprint and, when available, an
alarm ID. They do not contain credentials or raw request/response bodies. Treat
the directory as private account metadata: fingerprints are not encryption and
alarm IDs remain sensitive. Do not publish receipts or raw account data.

Protection requires all invocations to retain and share that state directory
on a filesystem that supports its durability operations. Deleting or editing
the receipts, changing the home directory, using another machine or another
tool bypasses this local protection. This is not provider idempotency or an
exactly-once guarantee. No automatic recovery can safely resolve an unknown
submission with the currently unverified provider contract.

If blocked, stop creating alarms and inspect the official app. Keep the receipt
and lock. Controlled recovery would require explicit account-owner authorization,
verified creation/list/cleanup contracts and evidence resolving the earlier
submission before any local-state change or later creation. Do not blindly
delete state and retry. The [verification plan](smart-alarm-verification.md)
defines the separate provider and device evidence still needed before merge.
