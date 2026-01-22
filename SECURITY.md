# Security Analysis

## Secure Multi-Client Communication Protocol

This document analyzes the security properties of our protocol and demonstrates how it defends against various attacks.

---

## 1. Threat Model

### Adversary Capabilities

The attacker (MITM proxy) can:

| Capability | Description | Demonstrated By |
|------------|-------------|-----------------|
| **Intercept** | See all encrypted traffic | All messages pass through attacker |
| **Replay** | Resend old messages | `[r]` Replay option |
| **Modify** | Alter ciphertext, MAC, headers | `[m]` Modify option |
| **Drop** | Prevent message delivery | `[d]` Drop option |
| **Reorder** | Deliver messages out of order | `[d]` + `[r]` combination |
| **Reflect** | Send message back to sender | `[e]` Reflect option |

### Adversary Limitations

The adversary **cannot**:
- Break AES-128 encryption (computationally infeasible)
- Forge HMAC-SHA256 without the key (requires master key)
- Access pre-shared master keys (provisioned out-of-band)

---

## 2. Security Properties

### 2.1 Confidentiality

| Mechanism | Implementation |
|-----------|----------------|
| Encryption | AES-128-CBC with fresh random IV per message |
| Key Separation | Different keys for C2S and S2C directions |
| Key Evolution | Keys change after each round |

**Why it's secure:**
- Attacker sees only ciphertext
- Cannot decrypt without keys derived from master secret
- Even if one round's key is compromised, past/future rounds use different keys

---

### 2.2 Integrity

| Mechanism | Implementation |
|-----------|----------------|
| Authentication | HMAC-SHA256 over (Header \|\| Ciphertext) |
| Verify-then-Decrypt | HMAC checked BEFORE any decryption |
| Fail-Fast | Any HMAC failure → immediate session termination |

**Why it's secure:**
- Any modification to header or ciphertext invalidates HMAC
- Attacker cannot forge valid HMAC without MAC key
- No information leaked through error messages (silent disconnect)

---

### 2.3 Replay Prevention

| Mechanism | Implementation |
|-----------|----------------|
| Round Numbers | Each message tagged with round number |
| Strict Validation | Message rejected if round ≠ expected |
| Key Evolution | Keys change each round, old messages can't decrypt |

**Attack scenario:**
```
Attacker replays Round 1 CLIENT_DATA during Round 3
```

**Defense:**
1. **Round check fails**: Server expects round 3, message has round 1
2. **Even if round is modified**: HMAC was computed with Round 1 keys, won't verify with Round 3 keys

---

### 2.4 Reordering Prevention

Packet reordering is a special case of replay attack in our protocol.

**Attack scenario:**
```
Round 1: Attacker drops CLIENT_DATA, forwards later messages
Round 2: Attacker replays Round 1's CLIENT_DATA
```

**Defense:**
1. **Round mismatch**: Server at Round 2 rejects Round 1 message
2. **Key evolution**: Even with modified round number, HMAC computed with old keys fails

**Why reordering = replay:**
- Our protocol is strictly synchronous (request-response)
- Each round has exactly 2 messages in fixed order
- Any out-of-order delivery is effectively a replay of a past message

---

### 2.5 Reflection Prevention

| Mechanism | Implementation |
|-----------|----------------|
| Direction Byte | Each message has direction indicator (0=C2S, 1=S2C) |
| Separate Keys | C2S keys ≠ S2C keys |
| Direction Validation | Receiver checks expected direction |

**Attack scenario:**
```
Attacker reflects CLIENT_DATA back to client
```

**Defense:**
1. **Direction check fails**: Client expects S2C (1), receives C2S (0)
2. **Key mismatch**: Message encrypted with C2S keys, client tries S2C keys → HMAC fails

---

### 2.6 Desynchronization Detection

| Mechanism | Implementation |
|-----------|----------------|
| Stateful Protocol | Both sides track round number and keys |
| Synchronized Evolution | Keys evolve only after successful round |
| Silent Failure | On error, disconnect without sending messages |

**Attack scenario:**
```
Attacker drops SERVER_AGGR_RESPONSE
- Server: evolved keys to Round N+1
- Client: still at Round N (didn't receive response)
```

**Defense:**
1. Client times out, may retry or disconnect
2. If client sends new message with Round N keys, server's HMAC verification fails
3. Server silently disconnects → client times out

---

### 2.7 Opcode Validation

| Mechanism | Implementation |
|-----------|----------------|
| Phase-based Validation | Each opcode valid only in specific phase |
| Direction-based Validation | Each opcode valid only in specific direction |

**Valid Opcode Matrix:**

| Opcode | INIT C2S | INIT S2C | ACTIVE C2S | ACTIVE S2C |
|--------|:--------:|:--------:|:----------:|:----------:|
| CLIENT_HELLO | ✅ | ❌ | ❌ | ❌ |
| SERVER_CHALLENGE | ❌ | ✅ | ❌ | ❌ |
| CLIENT_DATA | ❌ | ❌ | ✅ | ❌ |
| SERVER_AGGR_RESPONSE | ❌ | ❌ | ❌ | ✅ |
| TERMINATE | ✅ | ✅ | ✅ | ✅ |

**Attack scenario:**
```
Attacker replays CLIENT_HELLO during ACTIVE phase
```

**Defense:**
```
InvalidOpcodeError: Opcode CLIENT_HELLO not valid in ACTIVE phase.
Valid opcodes: ['CLIENT_DATA', 'TERMINATE']
```

---

## 3. Attack Demonstrations & Mitigations

### 3.1 Incorrect HMAC Attack

| Step | Action | Result |
|------|--------|--------|
| 1 | Attacker intercepts message | Message captured |
| 2 | Attacker corrupts HMAC (`[m]` → `[2]`) | Last byte flipped |
| 3 | Message forwarded to receiver | Delivered |
| 4 | Receiver verifies HMAC | **FAILS** |
| 5 | Receiver terminates session | Silent disconnect |

**Log output:**
```
[HMAC-VERIFY] Expected: cc8d33d14fe39661...2e
[HMAC-VERIFY] Computed: cc8d33d14fe39661...d1
[HMAC-VERIFY] Result: INVALID
[DECRYPT] HMAC VERIFICATION FAILED!
[SERVER] Client 1 TERMINATED (silent disconnect): HMAC verification failed
```

---

### 3.2 Replay Attack

| Step | Action | Result |
|------|--------|--------|
| 1 | Round 1: Attacker forwards CLIENT_DATA normally | Stored as message #1 |
| 2 | Round 2: Attacker intercepts new CLIENT_DATA | Message captured |
| 3 | Attacker replays message #1 (`[r]` → `1`) | Old message sent |
| 4 | Server checks round number | Expected 2, got 1 |
| 5 | Server terminates session | **Round mismatch** |

**Alternative scenario (modified round):**
| Step | Action | Result |
|------|--------|--------|
| 1 | Attacker replays old message with modified round | Round changed to 2 |
| 2 | Server verifies HMAC | HMAC was computed with round=1 |
| 3 | HMAC verification fails | **Tampering detected** |

---

### 3.3 Message Reordering Attack

Reordering in our protocol is equivalent to selective replay:

| Step | Action | Result |
|------|--------|--------|
| 1 | Attacker drops message A (`[d]`) | A not delivered |
| 2 | Attacker forwards message B (`[f]`) | B delivered |
| 3 | Attacker replays message A (`[r]`) | A delivered late |
| 4 | Receiver checks round | A has old round number |
| 5 | Session terminated | **Round mismatch** |

**Why this works:**
- Protocol is strictly synchronous
- Each side expects specific round number
- Out-of-order = wrong round = rejection

---

### 3.4 Key Desynchronization Attack

| Step | Action | Result |
|------|--------|--------|
| 1 | Client sends CLIENT_DATA | Server receives |
| 2 | Server sends SERVER_AGGR_RESPONSE | Attacker intercepts |
| 3 | Attacker drops response (`[d]`) | Client doesn't receive |
| 4 | Server evolved keys to Round N+1 | Server at new keys |
| 5 | Client times out, retries with Round N keys | Key mismatch |
| 6 | Server HMAC verification fails | **Desync detected** |

**Key state after drop:**
```
Server: Round N+1, Keys_{N+1}
Client: Round N, Keys_N (waiting for response)

Client's next message uses Keys_N
Server tries to verify with Keys_{N+1}
→ HMAC mismatch → Silent disconnect
```

---

## 4. Protocol State Machine

```
                    ┌─────────────────────────┐
                    │          INIT           │
                    │    (Round 0, Initial    │
                    │         Keys)           │
                    └───────────┬─────────────┘
                                │
                     CLIENT_HELLO + SERVER_CHALLENGE
                          (both successful)
                                │
                                ▼
                    ┌─────────────────────────┐
                    │         ACTIVE          │◄─────────┐
                    │   (Round N, Evolved     │          │
                    │        Keys)            │          │
                    └───────────┬─────────────┘          │
                                │                        │
              ┌─────────────────┼─────────────────┐      │
              │                 │                 │      │
        Any Error          CLIENT_DATA +      User       │
        - HMAC fail       SERVER_RESPONSE     "quit"     │
        - Round wrong      (successful)                  │
        - Bad opcode            │                        │
        - Timeout               └────────────────────────┘
              │                    (Keys evolve,
              │                     Round++)
              ▼
    ┌─────────────────────────────────────────────────┐
    │                   TERMINATED                     │
    │             (Silent disconnect, no              │
    │              TERMINATE message sent)            │
    └─────────────────────────────────────────────────┘
```

---

## 5. Key Evolution Diagram

```
Initial Keys (from Master Key K_i):
    K_i ──┬── SHA256(K_i || "C2S-ENC")[:16] ──► C2S_Enc_0
          ├── SHA256(K_i || "C2S-MAC")      ──► C2S_Mac_0
          ├── SHA256(K_i || "S2C-ENC")[:16] ──► S2C_Enc_0
          └── SHA256(K_i || "S2C-MAC")      ──► S2C_Mac_0

After Round R:
    C2S_Enc_{R+1} = SHA256(C2S_Enc_R || Ciphertext_R)[:16]
    C2S_Mac_{R+1} = SHA256(C2S_Mac_R || Nonce_R)
    S2C_Enc_{R+1} = SHA256(S2C_Enc_R || AggregatedData_R)[:16]
    S2C_Mac_{R+1} = SHA256(S2C_Mac_R || StatusCode_R)
```

**Security benefit:** Each round uses different keys, so:
- Compromising Round N keys doesn't reveal Round N-1 or N+1 keys
- Replay of old messages fails (wrong keys)

---

## 6. Message Format

```
┌─────────┬───────────┬─────────┬───────────┬────────┬────────────┬──────────┐
│ Opcode  │ Client ID │  Round  │ Direction │   IV   │ Ciphertext │   HMAC   │
│ (1 B)   │  (1 B)    │ (4 B)   │  (1 B)    │ (16 B) │ (variable) │  (32 B)  │
└─────────┴───────────┴─────────┴───────────┴────────┴────────────┴──────────┘
│◄──────────────────── HEADER (23 B) ────────────────►│

HMAC = HMAC-SHA256(MAC_key, Header || Ciphertext)
```

**Why HMAC covers header:**
- Protects round number from modification
- Protects direction byte from modification
- Protects opcode from modification
- Any header tampering invalidates HMAC

---

## 7. Design Decisions

### 7.1 Silent Disconnect on Errors

**Decision:** Server does not send TERMINATE message when detecting errors.

**Rationale:**
1. If keys are desynchronized, client can't decrypt TERMINATE anyway
2. After detecting tampering, channel is not trusted
3. Simpler error handling, fewer edge cases
4. Client will timeout and handle disconnection

### 7.2 Verify-then-Decrypt

**Decision:** Always verify HMAC before decryption.

**Rationale:**
1. Prevents padding oracle attacks
2. Fails fast on tampering
3. No information leaked through decryption errors

### 7.3 Pre-Shared Keys

**Decision:** Master keys are provisioned out-of-band.

**Rationale:**
1. Assignment constraint (no public-key crypto)
2. Simulates industrial/embedded systems
3. Focus on symmetric protocol security

---

## 8. Known Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| **DoS possible** | Attacker can drop all messages | Network-level protection needed |
| **No forward secrecy** | Master key compromise reveals all sessions | Regular key rotation in deployment |
| **Handshake replay** | Old CLIENT_HELLO could be replayed across sessions | Timestamp validation (future enhancement) |
| **Clock not required** | No timestamp validation currently | Could add timestamp + nonce cache |

### Handshake Replay Note

Currently, if an attacker captures a CLIENT_HELLO from Session 1, they could replay it in Session 2 (after server restart). This works because:
- Round 0 is expected
- Same master key → same initial keys
- HMAC verifies correctly

**Possible mitigations (not implemented):**
1. Timestamp validation with acceptable window
2. Server-side nonce cache
3. Session counters persisted across restarts

---

## 9. Cryptographic Compliance

### Allowed (Used):
- ✅ AES-128-CBC (via `cryptography` library)
- ✅ HMAC-SHA256 (via `hmac` module)
- ✅ Manual PKCS#7 padding implementation
- ✅ `os.urandom()` for secure randomness

### Forbidden (NOT Used):
- ❌ ECB mode
- ❌ Automatic padding functions
- ❌ AES-GCM or other authenticated encryption
- ❌ Fernet or high-level encryption APIs

---

## 10. Summary

| Attack | Detection Mechanism | Result |
|--------|---------------------|--------|
| HMAC corruption | HMAC verification | Silent disconnect |
| Ciphertext modification | HMAC verification | Silent disconnect |
| Replay (same session) | Round number check | Silent disconnect |
| Replay (cross-session) | Currently vulnerable | See limitations |
| Reordering | Round number check | Silent disconnect |
| Reflection | Direction check + key separation | Silent disconnect |
| Desynchronization | HMAC with evolved keys | Silent disconnect |
| Invalid opcode | Phase-based validation | Silent disconnect |

**All attacks by the MITM adversary (within a session) result in detection and silent session termination.**
