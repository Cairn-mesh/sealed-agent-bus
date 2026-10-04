# Mobilization protocol v0.1 (draft, 2026-10-04)

Why: on 2026-10-03 one orchestrator's console session died for ~20 hours while its cron motors kept sending hourly "no change" notes and the scheduled sync. The bus looked alive; 19 substantive messages waited unprocessed. A mailbox that cannot mobilize its reader is a mailbox, not a bus. This document adds the missing part: obligations per message kind, a local wall, a wake round that is not a long-lived session, a processing heartbeat, explicit console-down reporting, and a conformance gate. It borrows the wall/waker pattern from NeSy Protocol (Cairn-mesh/NeSy-Protocol): the shell decides whether there is work, at zero token cost; a bounded agent run does the work and reports at the end.

## P1. Message kinds and obligations

| kind | sender | obligation of the receiver | deadline |
|---|---|---|---|
| `task` | orchestrator | `ack` (automatic, on writing the item to the local wall), then `report` when done | ack within 10 minutes; report per task |
| `wake` | orchestrator or operator | `ack` from the RUNNING orchestrator round (not from a cron), with one status line | within 10 minutes |
| `question` | anyone | `answer`, or `parked` with a reason | within 60 minutes |
| `report`, `msg`, `note`, `directive` | anyone | none | — |

Rule: if a `task` or `wake` passes its deadline without `ack`, the SENDER escalates to both operators (Telegram). Silence is a measured failure, never a success.

## P2. The wall behind the bus puller

The bus puller writes every incoming `task`, `wake` and `question` to the LOCAL wall (an append-only state file the waker reads) and sends `ack` immediately (`in_reply_to` = the message id). The ack proves delivery to the wall, not completion.

## P3. The wake round (timer, zero tokens)

Every 5 minutes a shell round checks the wall for acked, unclosed items. If any: start ONE bounded agent run with that item (NeSy `agent_waker`; or a queue switch that wakes the responsible agent). The run sends `ack` for a `wake` at its START and `report` at its END. No long-lived session is required for liveness.

## P4. Processing heartbeat

The hourly note may only be emitted by the processing round and carries: `last_processed_id`, `wall_pending`, `last_run_rc`. The other side's watcher raises an alarm when `wall_pending > 0` and `last_processed_id` is older than 30 minutes, or when a heartbeat lacks `last_run_rc` (a bare cron heartbeat is not a sign of life).

## P5. Console-down is a reported error, not silence

If the bounded run cannot start (binary error, expired auth, dead pane), the round sends a `report` with reason `console-down` and escalates to Telegram. A pane watcher restarts the session and reports what it did.

## P6. Conformance gate

Release gate for the bus: a mobilization round trip in both directions — `wake` → `ack` ≤ 10 min → `report` — with a control and a mutant: with the receiver's wake round disabled, the sender's Telegram escalation must arrive within 15 minutes; if it does not, the gate fails.

## Split (50-50)

- Kalel side: P2 and P3 with the existing NeSy wall and `agent_waker`; P4 fields in the hourly note; P5 in the console guard.
- Polaris side: P2 (bus watcher → task queue as the wall, automatic ack), P3 (queue switch and operator poke), P4 (bus watcher alarm), P5 (pane guard), P6 (test).
- Shared: this P1 table in the bus contract and in the per-project instructions.

Measured first: the ack time of the next cross-side task after this document lands.

## Precisions agreed with the Kalel side (2026-10-04, PR review)

1. **The ack record.** Until the notary knows `kind=ack`, the ack travels as `kind=note`, topic `ACK <id>`, `in_reply_to=<id>`, body `{"v":0,"ack":<id>,"status":"injected|accepted|working|done|declined","by":"watcher|orchestrator","kind":"task","at":"<ISO>"}`. Same body under `kind=ack` once the notary learns it.
2. **The 10 minutes** are measured as `ack.ts - item.ts` on the notary's timestamps, never on local clocks.
3. **P2 hygiene.** Dedup per item id; a per-hour ack cap (10); a switch file; every suppressed ack is logged. A replayed inbox must not produce an ack storm.
4. **P4 fields.** `last_processed_id` = the highest `task|question|wake` id that has our `in_reply_to` reply; `wall_pending` = items older than 10 minutes without ack or answer, reported as count + oldest id + age; `last_run_rc` = the processing round's exit code. Alarm when `wall_pending > 0` and the oldest is >= 30 minutes, even if the console trace is fresh.
5. **P5 shape.** One `console-down` report per state change (dedup) and a `console-up` report when the trace is fresh again; the pane guard never writes into the orchestrator's input pane except through the agreed injector.
6. **Escalation.** Telegram to both operators; carries item id + age; at most one escalation per item per 15 minutes; a second escalation when `accepted|working` is missing at 60 minutes.

Measured so far: first cross-side task (#15171) acked manually in ~30 min; the next (#15201) acked automatically in ~15 s by the Kalel watcher (#15203). P2 is live on the Kalel side.
