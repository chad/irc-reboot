# S2S Sync Audit — Architectural Flaws

## The Core Problem

**Each server maintains independent `ChannelState` with no shared truth.**

When User A on Server 1 creates `#test`, Server 1's `ChannelState` has:
- `members: {A}`, `ops: {A}`, `founder_did: None` (guest)

When User B on Server 2 joins `#test`, Server 2 checks its OWN `ChannelState`.
If `#test` doesn't exist on Server 2 yet, `is_new_channel = true`, so:
- `members: {B}`, `ops: {B}`, `founder_did: None`

**Both servers independently think their user is the channel creator and op.**
The S2S JOIN message arrives AFTER the local JOIN has already completed.

## Specific Bugs Found

### Bug 1: Both Users Get Ops (The Reported Bug)

**Flow:**
1. User A on Server 1: `JOIN #test` → `is_new_channel=true` → gets ops
2. Server 1 sends S2S `Join { nick: "A", channel: "#test" }`
3. User B on Server 2: `JOIN #test`
4. Server 2 checks `channels.contains_key("#test")` — **may or may not exist**
   depending on whether the S2S Join from step 2 arrived first
5. If S2S Join arrived: channel exists, `is_new_channel=false`, B is NOT op ✓
6. If S2S Join has NOT arrived: `is_new_channel=true`, B GETS OPS ✗

This is a **race condition**. With network latency between servers,
step 3 often wins the race against step 2.

### Bug 2: Mode Changes Not Enforced Cross-Server

Even with the new Mode S2S message, enforcement is wrong:

- **+t is enforced at the receiving server.** If Server 2 hasn't received
  the Mode message yet, it allows the topic change.
- **Topic change is then relayed to Server 1** via S2S Topic message,
  which Server 1 blindly accepts (the comment says "trust the originating
  server's enforcement").

So: Set +t on Server 1 → Server 2 hasn't gotten the Mode msg yet →
User on Server 2 changes topic → topic change relayed to Server 1.
**+t is bypassed.**

### Bug 3: NAMES Shows Inconsistent Op Status

`send_names_update` determines remote user op status by checking:
```rust
let is_op = rm.did.as_ref().is_some_and(|d| {
    ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d)
});
```

For **guest users (no DID)**, remote ops are NEVER shown. Guest users
who are op on their home server appear as regular users on the remote.

Session-based ops (`ch.ops`) are local only — they contain session IDs
that are meaningless on the remote server.

### Bug 4: Channel Created Notification Race

`handle_join` broadcasts `ChannelCreated` only for new channels:
```rust
if is_new_channel {
    s2s_broadcast(state, S2sMessage::ChannelCreated { ... });
}
```

But if BOTH servers create the channel simultaneously (the race in Bug 1),
both send `ChannelCreated`. The `first-write-wins` merge in the handler
means whichever `ChannelCreated` arrives first on each server wins —
**each server may have a DIFFERENT founder**.

### Bug 5: Sync Response Mode Merge is One-Way Additive

```rust
if info.topic_locked { ch.topic_locked = true; }
```

Modes can only be ADDED via sync, never removed. If Server 1 sets +t
then -t, the sync response still shows `topic_locked: true` on Server 2
if the Mode S2S message for -t was lost. There's no way to correct this
other than a new sync.

Actually worse: the sync always sends the current state, so if Server 1
has -t, the sync shows `topic_locked: false`. But the merge code only
adopts `true`, never `false`. So the mode gets stuck on.

### Bug 6: No Origin Tracking on Ops

The `ops` field is `HashSet<String>` of **session IDs**. These are
server-local identifiers like `stream-42`. They mean nothing on the
remote server. There's no S2S message for granting/revoking ops to
remote users.

A user opped on Server 1 has no op status on Server 2 unless they
have a DID that's in `did_ops`.

### Bug 7: S2S Privmsg Bypasses +n and +m

`process_s2s_message` for Privmsg:
```rust
deliver_to_channel(state, &target, &line);
```

No check for +n (no external messages) or +m (moderated). A remote
user who is not in the channel (from the local server's perspective)
can send messages to a +n channel via S2S relay.

### Bug 8: S2S Topic Bypasses +t

As noted in Bug 2 — the S2S Topic handler never checks `topic_locked`.
The comment says "trust the originating server" but the originating
server may be running old code, or may not have received the +t mode
change yet.

### Bug 9: Bans Not Enforced on S2S Join

When a remote user joins via S2S, there's no ban check:
```rust
ch.remote_members.insert(nick.clone(), RemoteMember { ... });
```

A user banned on Server 1 can still appear in the channel if they
join from Server 2.

### Bug 10: No S2S Ban Propagation

Bans are local only. Setting `+b nick!*@*` on Server 1 has zero
effect on Server 2.

## Architectural Root Cause

The fundamental issue is **split-brain state**. Each server has its
own `ChannelState` and makes independent decisions. S2S messages are
fire-and-forget with no ordering guarantees, no acknowledgment, and
no convergent merge strategy for most fields.

The CRDT (Automerge) exists in the codebase but is **not wired to
live S2S**. The `ClusterDoc` in `crdt.rs` defines a flat-key schema
but `process_s2s_message` uses ad-hoc JSON messages with in-memory
first-write-wins logic.

## Recommended Fixes (Priority Order)

### P0: Fix the "both get ops" race

**Option A (simple):** On new channel creation, DON'T grant ops immediately.
Wait for a configurable window (e.g., 2 seconds) for S2S sync to arrive.
If no conflicting `ChannelCreated` arrives, grant ops. This is fragile.

**Option B (correct):** Only the channel **as it exists on the server**
determines authority. A channel is "new" only if it doesn't exist on ANY
server. This requires a handshake:
1. Server sends `ChannelCreated` to S2S
2. Waits for ACK/NACK from all peers
3. Only then grants ops

This is complex and adds latency.

**Option C (pragmatic, recommended):**
- Guest users on an existing-on-any-server channel do NOT get auto-op
- `is_new_channel` should check both local state AND recent S2S sync
- When S2S Join arrives for a channel that doesn't exist locally,
  create it but mark it as `created_remotely = true`
- When a local user joins a `created_remotely` channel, don't auto-op
- Only auto-op if the channel truly didn't exist anywhere

**Option D (simplest, good enough):**
- When we receive S2S `ChannelCreated`, if we have local ops granted
  to a user with no DID (guest), and the remote founder has a DID,
  revoke the local guest ops and adopt the remote founder.
- When we create a channel locally, immediately send `ChannelCreated`
  BEFORE completing the JOIN response.

### P1: Fix mode enforcement

**All S2S incoming messages must be subject to the same channel mode
checks as local messages.** Specifically:
- S2S Topic: check +t, reject if set (or at least don't relay locally)
- S2S Privmsg: check +n, +m
- S2S Join: check bans, +i

### P2: Fix NAMES consistency

- Include op status in S2S Join messages (new field: `is_op: bool`)
- Track which remote users are ops in `RemoteMember`
- When showing NAMES, use this info instead of only DID-based op check

### P3: Fix mode sync

- Replace one-way additive merge with full state replacement:
  `ch.topic_locked = info.topic_locked` (not `if info.topic_locked`)
- Mode S2S messages must include a logical timestamp or sequence number
  to resolve conflicts (most recent write wins)

### P3: Wire up CRDT

The Automerge CRDT was designed for exactly this problem. The flat-key
schema (`founder:{channel}`, `mode:{channel}:t`, etc.) provides
convergent merge. The work to wire it to live S2S would solve most
of these issues permanently.
