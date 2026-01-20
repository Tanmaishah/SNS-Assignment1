# Security Analysis

## Secure Multi-Client Communication Protocol

---

## 1. Threat Model

### Adversary Capabilities

The attacker (MITM proxy) can:

| Capability | How It's Demonstrated |
|------------|----------------------|
| **Replay** old messages | `[r]` option - select stored message |
| **Modify** ciphertexts and MACs | `[m]` option - flip bits, corrupt HMAC |
| **Drop** packets | `[d]` option - message not delivered |
| **Reorder** packets | Replay old message at wrong time |
| **Reflect** messages | `[e]` option - send back to sender |

### Adversary Limitations

The adversary **cannot**:
- Break AES-128 encryption
- Forge HMAC-SHA256 without the key
- Access pre-shared master keys

---

## 2. Security Properties & Defenses

### 2.1 Confidentiality

| Property | Implementation |
|----------|----------------|
| **Encryption** | AES-128-CBC with random IV per message |
| **Key Separation** | Different keys for C2S and S2C directions |

**Attack Scenario**: Attacker captures ciphertext  
**Defense**: Cannot decrypt without encryption key derived from master secret

---

### 2.2 Integrity

| Property | Implementation |
|----------|----------------|
| **Authentication** | HMAC-SHA256 over (Header \|\| Ciphertext) |
| **Verify-then-Decrypt** | HMAC checked BEFORE any decryption |

**Attack Scenario**: Attacker modifies ciphertext  
```
[m] -> [1] Flip bits in ciphertext
```
**Defense**: HMAC verification fails → Session TERMINATED

**Why Verify-then-Decrypt?**
- Prevents padding oracle attacks
- Detects tampering before any processing
- Fail-fast security

---

### 2.3 Replay Prevention

| Property | Implementation |
|----------|----------------|
| **Round Numbers** | Each message includes round number |
| **Key Evolution** | Keys change after each round |

**Attack Scenario**: Attacker replays Round 1 message during Round 3
```
[r] -> Select message #2 (from Round 1)
```
**Defense**: 
1. Round number mismatch (expects 3, gets 1)
2. Even if round modified, HMAC fails (keys evolved)

**Key Evolution Formula**:
```
C2S_Enc_{R+1} = SHA256(C2S_Enc_R || Ciphertext_R)
C2S_Mac_{R+1} = SHA256(C2S_Mac_R || Nonce_R)
```

---

### 2.4 Reflection Prevention

| Property | Implementation |
|----------|----------------|
| **Direction Byte** | Each message has direction indicator (0=C2S, 1=S2C) |
| **Separate Keys** | C2S_Mac ≠ S2C_Mac |

**Attack Scenario**: Attacker reflects client message back to client
```
[e] -> Reflect back to sender
```
**Defense**:
1. Client expects direction=1 (S2C), receives direction=0 (C2S) → Reject
2. Even if direction modified, HMAC computed with C2S_Mac won't verify with S2C_Mac

---

### 2.5 Desynchronization Detection

| Property | Implementation |
|----------|----------------|
| **Stateful Protocol** | Both sides track round number and keys |
| **Fail-Fast** | Any mismatch → TERMINATE |

**Attack Scenario**: Attacker drops server response
```
[d] -> Drop SERVER_AGGR_RESPONSE
```
**Result**:
- Server: Keys evolved to Round N+1
- Client: Keys still at Round N (didn't receive response)
- Client's next message: Uses Round N keys
- Server: HMAC verification FAILS → TERMINATE

---

## 3. Attack Analysis Summary

| Attack | Attacker Action | Protocol Detection | Result |
|--------|-----------------|-------------------|--------|
| **Replay** | `[r]` replay old message | Round mismatch or HMAC fail | TERMINATE |
| **Modify Ciphertext** | `[m]` -> `[1]` | HMAC verification fails | TERMINATE |
| **Corrupt HMAC** | `[m]` -> `[2]` | HMAC verification fails | TERMINATE |
| **Change Round** | `[m]` -> `[3]` | Round mismatch or HMAC fail | TERMINATE |
| **Change Direction** | `[m]` -> `[4]` | Direction mismatch or HMAC fail | TERMINATE |
| **Drop Message** | `[d]` | Key desynchronization | TERMINATE |
| **Reflect** | `[e]` | Direction mismatch | TERMINATE |

**All attacks are detected and result in session termination.**

---

## 4. Protocol State Machine

```
                    ┌─────────────────────────┐
                    │          INIT           │
                    │    (Round 0, Initial    │
                    │         Keys)           │
                    └───────────┬─────────────┘
                                │
                     CLIENT_HELLO/SERVER_CHALLENGE
                          (successful)
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
        Any Error          CLIENT_DATA/       User Quit  │
        (HMAC fail,       SERVER_RESPONSE        │       │
        Round mismatch,   (successful)           │       │
        Timeout)              │                  │       │
              │               │                  │       │
              │               └──────────────────┼───────┘
              │                  (Keys evolve,   │
              │                   Round++)       │
              ▼                                  ▼
    ┌─────────────────────────────────────────────────┐
    │                   TERMINATED                     │
    │             (Disconnect, Remove State)           │
    └─────────────────────────────────────────────────┘
```

---

## 5. Key Evolution Visualization

```
Round 0 (Initial):
    Master Key K
         │
         ├──► C2S_Enc_0 = SHA256(K || "C2S-ENC")[:16]
         ├──► C2S_Mac_0 = SHA256(K || "C2S-MAC")
         ├──► S2C_Enc_0 = SHA256(K || "S2C-ENC")[:16]
         └──► S2C_Mac_0 = SHA256(K || "S2C-MAC")

Round 0 → Round 1 (after handshake):
    C2S_Enc_1 = SHA256(C2S_Enc_0 || CLIENT_HELLO_ciphertext)[:16]
    C2S_Mac_1 = SHA256(C2S_Mac_0 || client_nonce)
    S2C_Enc_1 = SHA256(S2C_Enc_0 || challenge_data)[:16]
    S2C_Mac_1 = SHA256(S2C_Mac_0 || status_code)

Round N → Round N+1 (after data exchange):
    C2S_Enc_{N+1} = SHA256(C2S_Enc_N || CLIENT_DATA_ciphertext)[:16]
    C2S_Mac_{N+1} = SHA256(C2S_Mac_N || client_nonce)
    S2C_Enc_{N+1} = SHA256(S2C_Enc_N || aggregate_data)[:16]
    S2C_Mac_{N+1} = SHA256(S2C_Mac_N || status_code)
```

---

## 6. Message Format

```
┌─────────┬───────────┬─────────┬───────────┬────────┬────────────┬──────────┐
│ Opcode  │ Client ID │  Round  │ Direction │   IV   │ Ciphertext │   HMAC   │
│ (1 B)   │  (1 B)    │ (4 B)   │  (1 B)    │ (16 B) │ (variable) │  (32 B)  │
└─────────┴───────────┴─────────┴───────────┴────────┴────────────┴──────────┘
│◄──────────────────── HEADER (23 B) ─────────────────►│

HMAC = HMAC-SHA256(MAC_key, Header || Ciphertext)
```

---

## 7. Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| **DoS Possible** | Attacker can drop all messages | Network-level protection needed |
| **No Forward Secrecy** | Master key compromise reveals all sessions | Regular key rotation |
| **No Session Recovery** | Any error = disconnect | By design (fail-fast security) |
| **Fixed Clients** | Server expects fixed number | Could be made dynamic |

---

## 8. Cryptographic Compliance

### Allowed (Used):
- ✅ AES-128-CBC (via `cryptography` library)
- ✅ HMAC-SHA256 (via `hmac` module)
- ✅ Manual PKCS#7 padding
- ✅ `os.urandom()` for randomness

### Forbidden (NOT Used):
- ❌ ECB mode
- ❌ Automatic padding
- ❌ AES-GCM, Fernet, or authenticated encryption modes

---

## 9. Conclusion

The protocol provides robust security against the specified threat model:

| Property | Status |
|----------|--------|
| Confidentiality | ✅ AES-128-CBC encryption |
| Integrity | ✅ HMAC-SHA256 |
| Replay Prevention | ✅ Round numbers + key evolution |
| Reflection Prevention | ✅ Direction byte + separate keys |
| Tampering Detection | ✅ HMAC verification before decryption |

**All attacks by the MITM adversary result in detection and session termination.**
