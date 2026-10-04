## [1.5.7] — 2026-10-04 — sab-attach/1: the attachment exchange protocol, written down and closed

Answers the eleven questions a partner's attachment client raised against the exchange at `eb56c5e`, and the five
findings of the review of the first draft. `PROTOCOL_VERSION` stays 1.5.0, `SCHEMA_VERSION` 1.0.0. The release number
goes from 1.5.5 to 1.5.7 (1.5.6 is taken on another line). The evidence envelope is resealed as 1.5.7, so it
describes the tree shipped here.

The changes are additive for an old client, with three deliberate exceptions where the server is now STRICTER than
`eb56c5e` (fail-closed; each is normative in §8):
- an upload chunk must carry an integer `seq` and a boolean `last` (§8.3) — a chunk without them is `bad_chunk`;
- a ranged fetch request must carry `from_seq` (§8.4) — `{"descriptor": …}` alone is `bad_range`;
- a descriptor whose `size` is not the stored length is never reported `stored` and never accepted as a hand-over
  (§8.5, §8.8) — `size_mismatch` / `attachment_not_stored`.

- **Normative text:** `docs/AGENT_BUS_SCHEMA.md` §8 — round processing order (ack → messages → attachments → fetch →
  replies), descriptor and chunk objects, fetch, upload status, a closed table of machine codes, the companion record,
  the SPEC §4 limits, idempotency, which `in_reply_to` the bus threads on, the store. The code table is held equal to
  `bus_attach.CODES` by a test.
- **Ranged fetch:** `{"descriptor", "from_seq"}` returns whole chunks up to the round budget plus `next_seq` /
  `total_chunks`; an attachment above 4 MiB can now be pulled (it could not before: the bare form was `deferred` in
  every round). The stored file is re-checked before any chunk is served.
- **Chunk hash:** served chunks carry `chunk_sha256`; on upload it is optional and, if present, checked before the bytes
  are written (`chunk_hash_mismatch`, resumable at the same `seq`).
- **Machine status:** every upload item reports `code` and `next_seq`; an empty `chunks` list is a status query.
- **Companion record:** ONE sds-envelope record with `schema: capsule-sync/attachment/v1` and the closed descriptor in
  the member `attachment` (the name the first partner client already sends; one name only, `descriptor` is refused).
  Accepted only if the bytes are already stored here (`attachment_not_stored`) and within SPEC §4 (`limit_raw_bytes`
  8192 on the whole frame, `limit_bytes` 4096 on the canonical body, record_id excluded). Other sds-envelope records
  are measured (`sds[]` in the response), not refused — the live bus holds 150 earlier records above 4096.
- **Idempotent insert:** `(sender, recipient, envelope.record_id)` already present → the existing id, `duplicates[]`,
  no second row; serialized by a file lock; a lookup error inserts nothing (`idem_unknown`).
- **`in_reply_to`:** the bus threads on the OUTER field; outer ≠ record value → `in_reply_to_mismatch`; record-only →
  accepted with the warning `in_reply_to_inner_only`.
- **Fetch is a capability:** any authenticated identity can fetch a stored attachment by its descriptor (stated in §8.11).
- **Review round (cross-family measurement of `3091f9e`), five findings closed:**
  - *The companion gate checks the stored BYTES.* It used the transfer state (`Store.status`, i.e. "a file exists under
    this hash"): a 23-byte stored file was accepted under a descriptor claiming 24, and so was a file changed on disk.
    The gate now calls `Store.verify`, which reads the stored file and compares size and sha256 with the descriptor.
    `status` no longer says `stored` for another size either (`size_mismatch`), on the status query and on the dedupe path.
  - *Idempotency is decided on the parsed `record_id`.* The lookup pre-filtered the raw body text with
    `instr(body, record_id)`; a frame spelling the id with a JSON escape (`"\u0073ha256:…"`) was inserted again on an
    identical resend. The text pre-filter is gone: every sds-envelope row of the (sender, recipient) pair is parsed.
    Measured cost: 47 ms per lookup at 1000 rows of ~3.5 KB, 261 ms at 5000 (linear; an index keyed on the parsed id
    is the follow-up if a pair ever grows past that).
  - *§8.6 is the whole code set.* `attachment_error` (a store failure that is no protocol error) and the warning
    `in_reply_to_inner_only` are rows of the table; the table is bound to `bus_attach.CODES`,
    `bus_ssh_exchange.COMPANION_CODES` and `WARNING_CODES`, and to every code literal in the exchange.
  - *§8.3 chunk member types are enforced.* `"seq": false`, `"seq": 0.0`, `"last": "false"`, `"chunk_sha256": null`
    and a missing `seq` / `last` / `data` were taken for a well-formed chunk; each is now `bad_chunk`, also when the
    content is already stored. Unknown members stay ignored.
  - *A ranged request is exactly `{descriptor, from_seq}`.* `{"descriptor": …}` alone defaulted to `from_seq` 0; it is
    now `bad_range`.
- **Evidence:** `test_attach_protocol_20261002.py` (59 tests) and `tools/attach_protocol_mutants.py` (37 code-anchored
  mutants, each killed by an assertion; control all-pass). Every new negative control fails on `3091f9e`.

## [1.5.5] — 2026-09-26 — translation-only release

Translation-only release: all Hungarian text translated to English, internal notes moved to `docs/internal-hu/`; no behaviour change. `PROTOCOL_VERSION` stays 1.5.0, `SCHEMA_VERSION` 1.0.0; the wire contract, the signed shape and every conformance vector are byte-identical.

- **Scope of "no behaviour change":** code tokens are identical to 1.5.4 (checked mechanically per file, together with the order of every `%`/`{}` format placeholder). What changed is the language of comments, docstrings, docs and user-visible strings: CLI messages, the poke prompt, the feed's `adat=` marker (now `data=`), the Telegram button texts. Tests that asserted on the old wording assert on the new wording; their logic is unchanged.
- **Kept byte-identical on purpose:** the 27 partner-written and joint-review-line tests (outside authorship is what makes them evidence), and Hungarian test vectors / match strings whose bytes matter (the signed conformance vector, Unicode-normalization inputs, the leak scanner's Hungarian case-ending patterns, the matrix row keywords read by `docs_bind_probe.py`). One verbatim partner test asserts on a Hungarian token (the word for "its parent"), so `agent_wake`'s two parent-directory warnings carry it as a bracketed tag.
- **Language gate:** `tools/english_gate.py` fails on any Hungarian line outside `docs/internal-hu/`, with an exact, per-file allowlist for the literals above.
- **The seal:** re-sealed as a NEW version — 1.5.4 is not resealed in place, so each version names exactly one byte set.

## [1.5.3] — 2026-09-21 — the packer and the seal agree on what "shipped" means; the floor is 9/9, honestly

Fix release: EXACTLY the two findings of the full post-release check of the published 1.5.2, nothing else. `PROTOCOL_VERSION` stays 1.5.0, `SCHEMA_VERSION` 1.0.0. The 1.5.2 tag is frozen; this branch starts from that commit, with three changed files.

- **THE PUBLISHED REPO BUILT A DIFFERENT ARTIFACT THAN THE ONE WE SIGNED.** The verifier had learned that the landing files added at publish time (`README.md`, `SECURITY.md`, `assets/sab.png`) are outside the seal — but the PACKER did not know. So the published repo produced 160 files and a different artifact hash, the development tree 157 and the signed hash. A buyer rebuilding from the published repo **would not have got the archive we signed** — although that is the product's only promise about itself.
  Fix: the packer READS the seal's list instead of keeping a copy; a test requires this to be **one** list, not two matching ones. The decisive probe clones the repo, commits the furniture onto it (as publishing does), and requires the shipped file list to stay unchanged. **Exact names, not a directory pattern**: an exception shaped like `assets/**` grows by itself as the directory fills up.
- **THE FLOOR IS 9/9 — HONESTLY, WITHOUT LOOSENING THE THRESHOLD.** The mutation of `log-write-failure-blocks` replaced the `raise` with `pass`, which left a variable unassigned, and the tests died with `UnboundLocalError`: the tree collapsed, the claim did not fail. 1.5.2 **stated** this as WEAK, and it shipped that way. The recipe now gives `return` — that is the real fail-open, the log is skipped, the operation continues — and the claim is proven by **six assertion kills**, not collateral damage.

## [1.5.2] — 2026-09-21 — the silence of the channel between the two machines, and the 09-17 hardening round

The product branch forked on 09-15 and has not received the development branch's rounds since. This release brings them in. `PROTOCOL_VERSION` stays 1.5.0, `SCHEMA_VERSION` 1.0.0.

- **THE CHANNEL BETWEEN THE TWO MACHINES HAD BEEN DEAF SINCE 09-19.** The receiving side dropped rows with the reason `enforce_reject:unsigned-pinned` — 25 + 7064 rows, **without a trace**: the sender got no signal, the receiver did not log it visibly. Fix: the **sender signs its own row on its own machine** (`agent_bus.sign_for_send` / `check_presigned`, the exchange passes the pre-signed row on, client `sign_outgoing`), the bus checks it against the registry and **stores exactly that**; an unsigned row arriving under a pinned name bounces at admission **with a named reason**. Verified with a live probe. 15 tests, with a mutant probe.
- **Pull direction (09-20):** the client requests descriptors, the content-addressed store returns the chunks, with per-round limits.
- **The 09-17 hardening round:** pid reuse in single-flight (process identity, not TTL); **HIGH** — a remote endpoint cannot write in the name of a local agent (sender namespace, and a bare row under a pinned name is a separate class); an abandoned partial transfer no longer blocks the content forever; the supervisor watcher's WAITING branch also gets the stuck recipe; the product-mode marker is looked up on the REAL path (a symlink does not give dev mode); `AUTO_SIGN` is no longer process-global; `_audit_cross` pairs BY KEY and is two-way.
- **Two deliberately red probes STATED, not silenced.** The partner's two `ClampLiedFields` probes measure that the round entry's `pending`/`next_id` field is the accused's self-report, which the notary log alone does not refute. The probe measures the truth, so **we did not rewrite it** (evidence shipped verbatim); the runner states that their red is EXPECTED, in `strict` mode — should they ever pass, the suite turns red and asks. Closing the limit is measured one layer up: with the bus's own hash-chained `cursor_audit` export both lies are `audit_skipped_contradicts_log`.
- **THE FLOOR ENGINE STRENGTHENED — the evidence for our evidence was weak.** An independent arm did not read this chapter but ATTACKED it, and measured four real gaps. The engine (1) looked only at the exit code, so a claim whose run was `16 failed / 17 passed` both before AND after the mutation carried **zero signal**, and still counted as proven; (2) did not distinguish whether a test DECIDED against the mutation or the tree collapsed with an `UnboundLocalError`; (3) never looked the other way, where the mutation **revives** failing tests; (4) measured with `unittest` while the package advertises pytest — two different collectors. All four closed: a diff of per-test outcome **sets**, classification of every new red (assertion = decision / exception = collateral damage), failure on revival, and the shipped collector.
  A new, third state: **WEAK** — the mutation applied and went red, but no one decided. Not a pass and not a crash. Gate item 6 now writes `floor N/M PROVEN (+k weak: <names>)`, so "9/9" can no longer stand for a set that contains a row measured only collaterally.
  **MEASURED on this machine, as root: 8 proven, 1 WEAK** (`a log-write failure stops the operation` — its mutation kills only with an exception).
- **The floor's strength depends on WHO runs it — and the envelope says so.** The shipped tests assume a root-owned key registry (this guard prevents a local user from planting a key in someone else's name), so for a non-root buyer ~19 tests are red from the start, and the set diff carries no signal on a test that fails from the start. A non-root run will report FEWER proven claims than the number in the envelope — that is a property of the evidence, not a flaw, and the README says so, instead of the more flattering number.
- **The published envelope failed its OWN verifier.** The files added to the landing page after publishing (`README.md`, `SECURITY.md`, `assets/`) are not in the manifest, and the verifier said "not in the manifest" about them — the public v1.5.1 fails its own check today. Fix: these are exceptions by **exact NAMES** (never by directory pattern: a directory-shaped exception grows by itself as the directory fills up), and the verifier **prints** what the seal does not cover, instead of silently skipping it. Every other unlisted file is still a failure, and if a furniture file GETS INTO the manifest, it is hash-checked from then on — all three directions pinned by tests.
  The manifest's `source_commit` belongs to the BUILD repo; in a squash-published mirror that object does not exist, and an independent arm rightly tried to resolve it ("bad object"). The verifier now states that the seal rests on the **hashes**, not on the commit.
- **SPEC: a NORMATIVE description of the signed row (`signed shape v:2`) in the schema document** (`docs/AGENT_BUS_SCHEMA.md` §2b). The hotfix had changed ONLY code and tests: a mandatory protocol element for an interop partner had no description, and the independent arm had to reverse-engineer it from the shipped test and a docstring. The section gives the eight signed fields in order and the defaults, the two exclusions (`id`, `thread_id`) with the reason, the canonicalization, the verdict vocabulary, the client-signed exchange, and a runnable **conformance vector** (seed + byte image + sha256 + pubkey + signature).
  One interop trap is stated separately, because we MEASURED it: `ts` in nanoseconds is above 2⁵³, so whoever writes the numbers per the RFC 8785 JCS number rule (ECMAScript `Number::toString`, IEEE-754 double) gets `…552` instead of `…544` — a different byte image, a different signature, a silent verify failure, and the length does NOT change, so the usual check will not catch it either. Our canonicalization is deliberately not JCS on this one point; in everything else it coincides with it.
  The doc is not believed but measured: `test_schema_doc_signed_shape.py` recomputes the vector with the shipped code, derives the field list from the actual output of `_a2_content_bytes`, and measures the trap too — if the code moves and the doc does not, this test is red.
- **Label guard fixed — the meter was blind, not the code.** We derive the set of verdict labels from the AST; when the module moved the decision into `_builtin_verify`, the extractor did not follow the delegation and reported a "vanished status" while every label was in place. Following now walks the call chain — and it immediately found a REAL gap: the code gives an `unverifiable(no-config-binding)` reason that was missing from the pinned list. An independent review had also missed the same reason from an outbound document on 09-19; the hand-typed set dropped the same thing twice.
- **Provenance — a new `joint-review-line` origin.** For the 22 test files of the joint review line it cannot be determined from the file name which is the partner's probe verbatim and which is our answer. We do not guess a licence claim: the new label states what is true (a joint line, one business, the same relicensing right), instead of showing false precision.
- **Packaging cleanup on the imported round:** absolute paths pointing to the operator's secret files moved from the merge-button tool's defaults into the user's own config directory (and are expanded at use); internal actor names were removed from the development docs; test-fixture addresses moved into the documentation range (RFC 5737), and the leak finder now knows that a documentation address cannot be ours.

## [1.5.1] — 2026-09-21 — release gate: a check is worth as much as it walks

Packaging and release gate; the bus contract and the code's behaviour are UNCHANGED. `PROTOCOL_VERSION` stays 1.5.0, `SCHEMA_VERSION` 1.0.0.

- **The leak scan's scope is the whole archive.** The gate used to walk 72 of the 87 shipped files: it re-derived the list with its own filter and skipped the generated `product/evidence/` — which held a stale suite log that still named deleted private file names. Now there is ONE definition of what goes out (`make_release.shipped_names`), and both the scan and the provenance inventory ask it. There is no directory-level skip; the only exception is a named file list (the pattern holders themselves).
- **The number is part of the verdict:** "85 of 87 shipped files walked, 2 exempt as pattern holders". If no walk reaches a shipped file, the item fails by name — a test shrinks the walked set back and requires the gate to notice.
- **The provenance inventory also covers the whole archive** (87 files): a new `generated-here` origin for envelope files produced by our own machinery. Labels are counted BY NAME — the earlier counter shaped "partner = everything that is not first-party" would have silently swallowed the new category; a test requires the sum of labels = total.
- **The release version is separate from the protocol version** (`product/version.py`). The protocol version goes out on the wire, so a packaging fix must not bump it: gate item 3 now requires the release version to match the argument and the envelope manifest exactly, and of the protocol only that it be on the same MAJOR.MINOR line.

## [1.5.0] — 2026-09-14 — notary log

v1.4's two open residuals: backdating WITHIN the window, and the matrix (rewriting the log must be detectable, and the check must run regularly — at two parties).

- **New: `bus_notary.py` + `test_bus_notary.py` (20 tests).** Append-only, hash-chained JSONL: `{seq, prev_hash, received_at_ms, envelope_sha256, sender_identity, sender_auth, recipient, kind, decision, reason, claimed_ts_ms}`, `entry_hash = sha256(JCS(entry))`; a signed checkpoint every N entries `{seq, head_hash, ts_ms, notary_pub, sig}` (Ed25519). Serialized across processes with flock, fsync.
- **Export / offline verify / compare:** `export --from SEQ` (+ the latest signed checkpoint); `verify` recomputes the chain (rewrite → wrong hash at that seq; full re-chaining → the signed head does not match; deletion → gap; reordering), checks the signature and the trusted key; `compare` byte for byte over the shared seq range, with the first differing seq.
- **Backdating:** the sender's claimed time (message `ts`, SDS record `ts`, relay envelope `ts`; s/ms/µs/ns → ms) measured against the receive time; anything older than the window → `backdated` (it stays in the log as evidence, we do not drop it).
- **Integration:** `bus_ssh_exchange` per message and per attachment (`sender_auth=ssh-key`); `bus_relay` `/deliver` (`unauthenticated-claim` — `from` is not authenticated there, and is labelled so) and `/pickup` (`pickup-sig` / rejected). A sealed `ct` and a plaintext body never enter the log (tested).
- **Mode:** mandatory in product mode, cannot be switched off; fail-closed without cryptography or a key (exchange: `notary unavailable (fail-closed)`, write error → `notary write failed (fail-closed)`, the remaining items do not go through; relay: start refused, write error → 503 and the envelope does not stay in the spool). Off by default in dev mode (v1.4 behaviour unchanged), `AGENT_BUS_NOTARY=on`.
- A separate log file → **SCHEMA_VERSION stays 1.0.0**; `PROTOCOL_VERSION` 1.5.0.
- **Fix — 23Z):** without `--pub`, `verify` returned `ok:true` even for a self-consistent fake chain signed with a foreign key, and the report did not show the signer. Now: per checkpoint `notary_pub` + `trusted`; at the top level `trusted` (can only be true with a trusted `--pub`), `signer_unverified`, `signers`. CLI without `--pub`: a stderr warning in dev mode; **refusal in product mode (rc=2)**. 3 new tests.
- **Fix — 25Z):** a slice without a checkpoint (<N entries of a fresh log, or an export before the next checkpoint) got `trusted:true`, `signer_unverified:false` with the CORRECT `--pub`, although no signature was verified (in product mode too). Now `trusted` is true only if at least one checkpoint was actually verified with the trusted key and binds to an exported entry; new fields: `checkpoint_count`, `verified_checkpoint_count`, `covered_to_seq`, `unverified_tail`, `no_checkpoint_in_range`. CLI: for such a slice a warning in dev mode (rc=0, `trusted:false`), **refusal in product mode (rc=3)**; a stderr note about an unverified tail. 3 new tests (`test_M6b_*`).
- Tests: **205 passed, 1 skipped** (after the v1.4 + fix merge and the fixes).

## [1.4.0] — 2026-09-14 — enforcement (product mode)

Based on the main finding of an independent attack matrix (v0): the weakness is not cryptographic but one of enforcement (the bus annotated, and the default allowed omitting the signature).

- **New: `bus_enforce.py` + `test_bus_enforce.py` (15 tests).** Product mode: `AGENT_BUS_MODE=product` or `.product_mode.on`. recv REJECTS: unsigned (`unsigned-downgrade`, ), forged / key mismatch (`forged`, ), ts outside the window (`stale-ts` / `future-ts`, ; default −300 s / +60 s), replayed content (`replay`, — durable seen-store, also across processes), incomplete attachment descriptor (`attachment-descriptor`, ). In product mode the sds-envelope is mandatorily checked, only valid ones remain.
- **Default: dev** (v1.3 behaviour byte-identical) — the live fleet does not break. **The product/release profile sets product mode.** `abus doctor`: a loud warning in dev mode, rc=1.
- **Nothing is deleted:** a rejected row stays in the DB; the reason is in `enforce/rejected.jsonl`. The seen-store is a separate append-only file → **SCHEMA_VERSION stays 1.0.0**.
- **`bus_relay`: durable pickup nonce store** (next to the spool) — v1.2's "one-time replay after restart" risk closed . 2 new tests.
- **`sce_hook`: a documented mapping** bus row → `sce-arm-envelope/v1` (the SDS record's `payload` field) + `decide_rows`; an end-to-end test (8) with a fake decider and optionally the real external adapter .
- **`agent_duty`:** a visible running background shell counts as work (1 new test).
- `PROTOCOL_VERSION` 1.4.0 (MINOR). Tests: **128 passed** (102 + 26).
- **review fixes (2026-09-14):**
  - enforcement runs INSIDE recv's cursor transaction, before the cursor; a rejected row does not raise `delivered_id`, `read_at` stays NULL, it gets an `enforce_reject:<reason>` audit row → `reconcile`/`replay` see it. Default ts window **−7 days / +300 s** (the replay store catches duplicates even without a window).
  - in product mode the JSON mirror runs only for a signed row and carries `sig`/`pubkey`; `tools/inbox_watch.sh` refuses to run in product mode (rc=3).
  - the marker is looked up next to the DB file and under `/etc/agent-bus/product_mode.on` too (union) — it cannot be switched back with env (AGENT_BRIDGE_DIR/AGENT_BUS_DIR/AGENT_BUS_MODE=dev); the window env can only narrow. An unknown `AGENT_BUS_MODE` value → product.
  - /the delivering recv's seen-store is in the DB (`enforce_seen`, lazy table, atomic with the cursor) — deleting the file does not reopen replay, another UID does not hit file permissions; `rejected.jsonl` is best-effort. Relay: with a missing nonce store, a request before start is rejected.
  - `recv_mark` audit `skipped` = number rejected. A stderr summary (on peek too). `bus_enforce` is an optional import (fail-closed on a product signal). `agent_duty` SHELLS only on the `⏵⏵` status line, ≥1. A recv integration peek test + window pin. An enforcement error → fail-closed, the cursor does not move, no traceback.
  - Tests: **174 passed, 1 skipped** (+21 regression tests).

## [1.3.1] — fixes

- **** a missing/damaged duty assignment is `unknown` (rc=2, alert hourly), a deliberate "no one on duty" is `no-duty` — neither is the same as the "all fine" `none`.
- **** evidence of change alongside the "working" text pattern: if the busy pane stays byte-identical for `busy_stuck_min` (default 60) minutes → `alert` ("stuck?").
- **** a monotonic-clock comparison against wall-clock jumps; on a jump the stored timestamps shift, the elapsed time is preserved.
- **/ ** exact boundary tests for the enter cooldown (240 s), the done threshold (5 minutes), the alert threshold and the dead-pane alert (20 minutes).
- **** agent/topic switch tested (the history is cleared).
- **** the default `count_reports_inbox` (the supervisor's JSON mirror inbox) and a real `bus_send` in `__main__`.
Tests: `test_agent_duty.py::MateReviewPR3` (11) — 7 failed before the fix.

## [1.3.0] — 2026-09-14 — duty (agent_duty)

- **New: `agent_duty.py` + `test_agent_duty.py` (11 tests).** Watches the active agent of the work queue: is it working.
  - its OWN wake-up text stuck in the prompt → one Enter (prefix match; other text is sacred);
  - idle, empty prompt ≥10 minutes → one fixed-text poke (`agent_wake.safe_send`);
  - still not started ≥20 minutes after the poke, or no pane → alert (at most one per hour, with a swappable notifier);
  - if it has reported since the wake-up and is idle → the supervisor gets a signal to advance the queue — a finished agent is not poked;
  - silent under sleep-safe; does not touch a pane awaiting approval; does not advance the queue by itself.
- **Why:** on the morning of 2026-09-14 the fleet's wake-up text got stuck in the tmux prompt (the Enter was lost), and no one worked for hours, although per the queue one agent should have.
- `PROTOCOL_VERSION` 1.3.0 (MINOR: new module, bus contract unchanged).

# CHANGELOG — AgentBus

## [1.2.1] — fixes

- **HIGH — `/deliver` flood:** built-in, fail-closed limits in the relay EVEN before the proxy: accepts only recipients in the registry (unknown → 404), a per-recipient per-minute rate (`AGENT_BUS_RELAY_MAX_PER_MIN`, default 120), a per-recipient pending ceiling (`AGENT_BUS_RELAY_MAX_PENDING`, default 200), a total spool ceiling (`AGENT_BUS_RELAY_MAX_SPOOL`, default 5000) → 429. Tests: `test_bus_relay.py::test_H_deliver_*` (with the external review's 500 repro; 3 tests failed before the fix).
- **Public exposure:** the relay may still be exposed ONLY behind a proxy that terminates TLS and rate-limits; the built-in limit protects deliverability, it does not replace the proxy (README).
- LOW (nonce-cache persistence) → closed by v1.4; LOW (forward secrecy) and INFO (CI, mixed test style) → open, see the v1.4 development log.

## v1.2.0 — 2026-09-14 (protocol MINOR; DB schema unchanged: 1.0.0)

### New
- **`bus_ssh_exchange.py` / `bus_ssh_enroll.py` / `bus_ssh_client.py`** — transport between machines over SSH:
  - the remote machine SSHes OUTWARD (through NAT, no port opened on the remote side);
  - on the bus machine the key is bound to a `command="… bus_ssh_exchange.py <identity>",restrict,no-pty,…` line —
    the identity comes from the command argument, the payload's `from`/`sender` field is ignored;
  - size ceiling (stdin, message/round), per-message rejection, sds-envelope passes and the replies get an `sds` label;
  - at-least-once delivery: the reply is a peek, the cursor steps on the client's `ack` in the next round; the client
    dedupes by remote id;
  - enroll ONLY produces a line / writes to the given file, it does not touch the sshd configuration.
- **`bus_relay.py`** — a blind store-and-forward relay, when there is no direct SSH:
  - E2E enveloping (X25519 → HKDF-SHA256 → ChaCha20-Poly1305), the relay stores only an opaque envelope;
  - **signed pickup** (`/pickup`): Ed25519, purpose-bound (`pickup`/`events`), ±120 s ts window, nonce replay cache;
  - **SSE** (`/events`): authenticated subscription, only an "N pending" signal, never content; the client falls back to polling;
  - fail-closed: does not start without `cryptography` or with an empty registry; a picked-up envelope goes under `.picked/` (no deletion).
- **`bus_attach.py`** — large content as an attachment: a content-addressed, write-once store; the bus's `attachment` kind
  carries only the descriptor (`sha256`, `size`, `media_type`, `locator`); hash+size check on read; chunked
  transport over SSH and the relay, it enters the store only after the full hash check.
- **`sce_hook.py`** — a hook point for the Silent Consensus Engine (`AGENT_BUS_SCE_DECIDER=module:function`);
  no engine code; no decider → no decision; a faulty decider → ABORT.

### Changed
- `agent_bus.py`: `PROTOCOL_VERSION = "1.2.0"`; `send` rejects a non-descriptor body for the `attachment` kind.
  The 64 KB body ceiling is unchanged.

### Deliberately left out
- **ICE / WebRTC:** outbound SSH solves the same NAT problem without external STUN/TURN servers and a large
  attack surface.

### Tests
- 31 new (SSH 11, relay 9, attachment 7, SCE hook 4); the full suite 91 green.

## [1.1.1] — fixes

- **B1 (BLOCKER) — `bus_singleflight`:** the `acquire` CLI is a one-shot process, its own pid is not the owner. Now: (1) the check→stale→reclaim sequence is atomic under a `flock` held on a side file; (2) by default the CLI takes the CALLER's (parent) pid as the owner if there is no `--owner-pid`/`--target`; (3) a fresh lock of a non-pid-shaped instance lives until the TTL (previously it immediately looked dead); (4) identity recovery is granted only to the same owner. Tests: `test_bus_singleflight.py` (with real OS processes, with both repros of the external review — 4 tests failed before the fix).
- **H1 — tmux target + dead explicit owner pid:** the lock no longer gets stuck (with `pid_src=owner` the pid's death is the lock's death too).
- **H2 — watcher DoS:** agent names in the JSON body get the same strict `[A-Za-z0-9._-]{1,64}` rule; the watcher's dispatcher cannot stop on an exception from an operator command.
- **H3:** `bus_singleflight` got a dedicated test suite.
- **M1:** the full suite runs ONLY with `python3 -m pytest -q`; `test_runner_guard.py` fails loudly under unittest (the earlier "or `python3 -m unittest`" was wrong).
- **M2 — operator without a key:** rejected by default (`ignored:operator-no-key`); a developer exception only with `AGENT_WAKE_ALLOW_KEYLESS_OPERATOR=1`.

## v1.1.0 — 2026-09-14 (protocol MINOR; DB schema unchanged: 1.0.0)

### Fix — 29Z)
- **B1-var:** `acquire --target <non-live pane>` refused (`target-not-live`, rc=4, no lock write) — previously the other caller
  immediately saw a lock written with a never-live target as stale → two `acquired` in 9/15 rounds. Regression:
  `test_B1var_owner_pid_vs_nonexistent_target_never_double_acquired` (15 rounds), `test_B1var_acquire_with_dead_target_is_refused_and_writes_nothing`.
- **WAKE_DIR:** `agent_bus_watcher.wake_dir()` at call time: `AGENT_WAKE_DIR` or `<AGENT_BRIDGE_DIR>/wake` (previously frozen at
  import time, the install-default `wake` directory). The tests' `Env` base points all three directories under tmp.
- README: the `AGENT_WAKE_ALLOW_KEYLESS_OPERATOR` dev switch documented.

### New
- **`agent_wake.py`** — the wake-up rules in one place:
  - *sacred typing*: never writes into, and never clears, a prompt containing live unsent text (no C-u);
    a dim (faded) suggestion is not typing; when in doubt, "typing";
  - does not poke a working agent;
  - *sleep-safe*: a global or per-agent marker; no poke goes into a sleeping agent's pane and no headless wake starts;
  - *operator wake*: `operator-wake` / `operator-sleep-safe` kind, only from an authorized (and, if it has a key, signed)
    operator; an agent cannot wake itself; WAKE moves the marker under `history/` (no deletion).
- **`sds_envelope.py`** + `agent_bus` wiring (the external review's three steps):
  - `send --kind sds-envelope`: only a SPEC §5.5 framed `{record, envelope}` pair;
  - `recv --verify-sds [--strict-sds] [--sds-admission PATH]`: `valid | invalid(<ok>) | unsigned | unverifiable(<ok>)`;
    swappable validator (`AGENT_BUS_SDS_VALIDATOR` / `CAPSULE2_SDS_VALIDATOR`);
  - governance bridge: local admission file + A2 key registry → `not-admitted`, `key-mismatch`, `forged-sender`.
- **`bus_singleflight.py`** — only one instance per agent identity drains at a time (session lock + atomic claim).
- Tests: `test_agent_wake.py`, `test_sds_envelope.py`, `test_agent_bus_security.py`, `test_bus_poke_pin.py`.

### Changed
- `bus_poke.py`: injection goes through `agent_wake`'s rules; if the module is missing, it **does not inject** (fail-closed).
  New `Poker.on_new` results: `sleep-safe`, `typed`, `busy`, `stuck`.
- `agent_bus_watcher.py`: does not wake a sleeping agent; applies operator WAKE/SLEEP commands addressed to the recipient.
- `agent_bus.py`: `PROTOCOL_VERSION = "1.1.0"`; `SCHEMA_VERSION` deliberately stays `1.0.0` (`verify` flags a pin mismatch as
  DRIFT, and the schema did not change).

## v1.0.0 — 2026-06-21
Frozen wire contract (see `docs/AGENT_BUS_SCHEMA.md`).

