# Human-approved blocking

The collector remains read-only. A separate constrained executor can create a new inbound block only after a specific proposal has three digest-bound specialist approvals, a human types BLOCK in the dashboard, and the human accepts Windows UAC. This feature has not executed any block during development. Windows execution is not end-to-end verified until a real user-approved action is performed.

Scope is deliberately limited to one existing .exe, TCP or UDP, one local port, one canonical unicast remote IP, one named profile and inbound direction. No Any scopes, CIDRs, program wildcards or existing-rule modifications. An inbound block does not stop all outbound activity. Rule presence verification does not prove packet-level enforcement or upstream reachability.

## Actual proposal contract

Agents may write a JSON file under data/proposals with a fresh UUID filename. It contains id, action (direction, program, protocol, localPort, remoteIP, profile), evidenceFingerprint, reason, impact, validation and reviews. All values must come from real evidence and owner-confirmed requirements; never stage sample proposals or infer maliciousness from broad rule scope. No proposal is prepopulated.

Use control.digest(proposal) to bind each review to the exact id, action, evidence fingerprint, reason, impact and validation. After receiving an actual collaboration review, the coordinator calls control.record_review with the specialist identity, verdict, summary and canonical task reference. This records an HMAC-protected receipt in the private review ledger. Self-declared review objects inside proposal JSON do not satisfy the gate. The HTTP server exposes no review-signing endpoint. This is coordinator attestation, not cryptographic proof of a model's identity. The trusted boundary includes the user's local account and these scripts; do not treat it as resistant to malware already running as that user.

The approval endpoint collects fresh evidence before accepting the digest, consumes the proposal before requesting elevation, and records an immutable execution bundle. The elevated script independently validates bounded scope and expiry and rechecks profile/executable/rule state. It creates only Palis-Block-UUID names. It never interprets proposal text as shell commands. HTTP mutations require exact loopback Host and Origin plus a session token. The browser cannot authorize firewall writes just by displaying a proposal.

## Results and rollback

Awaiting Windows does not mean blocked. Success requires rule and filter re-reads, including the ActiveStore. Cancellation, access denial, failed verification and missing results never appear as success. If creation partially succeeds, an error can indicate that the owned rule may exist. Rollback requires a separate human UNBLOCK confirmation and UAC. It removes only the exact unchanged Palis-created rule whose receipt matches; changed rules require manual investigation. Rollback restores absence of the app-created rule, not a whole old firewall configuration.

This prototype has no packet telemetry or threat feed. The dashboard's existing Block count represents configured rules, not threats automatically blocked by Palis.
