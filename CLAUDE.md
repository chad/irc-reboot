**Requirements:**
- `session_id` must be unique per TCP connection
- `nonce` must be cryptographically random
- Timestamp validity window: **≤ 60 seconds**
- Challenge must be invalidated after use

---

### 3.6 Signature Verification

The server must:

1. Resolve the DID document
2. Extract acceptable verification keys
3. Verify the signature over the exact challenge bytes

#### Key Rules

- Accept keys listed under:
  - `authentication`
  - (optional fallback) `assertionMethod`
- Do **not** accept delegation keys
- Supported curves:
  - `secp256k1` (MUST)
  - `ed25519` (SHOULD)

#### Signature Encoding

- Signature is `base64url` (unpadded)
- Signature is over raw challenge bytes
- No hashing unless explicitly required by key type

---

### 3.7 Post-Authentication Behavior

On success:

- Bind the connection to the DID
- Treat the IRC nick as a **display alias**
- Internal account identity = DID
- Emit standard IRC numeric `903`

On failure:

- Emit numeric `904`
- Terminate SASL flow cleanly
- Allow fallback to guest auth

---

### 3.8 Backward Compatibility

- Clients that do not request SASL must still connect
- Clients that do not support `ATPROTO-CHALLENGE` must still connect
- No existing IRC behavior may break

---

## 4. Deliverable B: Minimal TUI Client

### 4.1 Purpose

The client exists to:
- Prove the SASL mechanism works
- Demonstrate a realistic user flow
- Serve as a reference implementation

This is **not** a full IRC client.

---

### 4.2 Base Requirements

- Language: Go **or** Rust
- Runs in a terminal
- Uses a simple text UI (no mouse, no GUI toolkit required)
- Connects to the custom IRC server

---

### 4.3 Client Capabilities

The client must:

- Perform IRC registration
- Negotiate IRCv3 capabilities
- Perform SASL authentication using `ATPROTO-CHALLENGE`
- Join a channel
- Send and receive plain text messages

---

### 4.4 AT Authentication Flow (Client-Side)

The client must:

1. Ask the user for:
   - AT identifier (DID or handle)
2. Resolve handle → DID (if needed)
3. Authenticate to the user’s AT identity provider
   - OAuth or app-password is acceptable
4. Receive server challenge
5. Sign challenge with the user’s private key
6. Send signature via SASL
7. Complete IRC registration

Private keys **must never** be sent to the IRC server.

---

### 4.5 UX Expectations

Minimal but clear:

- Status line showing:
  - connection state
  - authenticated DID
- Clear error messages on auth failure
- No crashes on malformed server responses

---

## 5. Testing & Validation

### 5.1 Required Tests

- Successful auth with valid DID
- Failure on:
  - expired challenge
  - replayed nonce
  - invalid signature
  - unsupported key type
- Connection without SASL still works
- Standard IRC client can connect in guest mode

---

### 5.2 Manual Demo Scenario

Contractor must be able to demonstrate:

1. Start server locally
2. Connect with:
   - a standard IRC client (guest)
   - the custom TUI client (authenticated)
3. Join the same channel
4. Exchange messages

---

## 6. Documentation Deliverables

The contractor must provide:

1. **README**
   - How to build server
   - How to run server
   - How to run client
2. **Protocol Notes**
   - Any deviations or assumptions
3. **Known Limitations**
   - Explicit list

---

## 7. Acceptance Criteria

This project is complete when:

- Server successfully authenticates users via AT-backed SASL
- Client completes full auth flow without hacks
- System behaves as a normal IRC server for non-AT clients
- Code is readable, commented, and auditable
- The implementation could plausibly be referenced in an IRCv3 WG proposal

---

## 8. Philosophy (Context for the Implementer)

This project treats IRC as **infrastructure**, not a product.

The goal is to modernize identity without:
- centralization
- UX regressions
- protocol breakage

If something feels “too clever,” it’s probably wrong.

---

**End of document**
