# Secure Multi-Client Communication Protocol

## Lab Assignment 1 - System and Network Security (CS5.470)

A stateful, symmetric-key-based secure communication protocol with interactive MITM attack demonstration.

---

## Architecture

```
┌──────────┐          ┌──────────┐          ┌──────────┐
│ Client 1 │◄────────►│          │◄────────►│          │
└──────────┘          │ ATTACKER │          │  SERVER  │
┌──────────┐          │  (MITM)  │          │          │
│ Client 2 │◄────────►│          │◄────────►│          │
└──────────┘          └──────────┘          └──────────┘
   :7000                 :7000 ──► :6000       :6000
```

**All traffic flows through the attacker**, allowing interactive attack demonstrations.

---

## Quick Start

Open 4 terminal windows:

### Terminal 1: Start the Server

```bash
python server.py --port 6000 --clients 2 --timeout 60
```

### Terminal 2: Start the Attacker (MITM Proxy)

```bash
python attacks.py --listen-port 7000 --server-port 6000
```

### Terminal 3: Start Client 1

```bash
python client.py --id 1 --port 7000
```

### Terminal 4: Start Client 2

```bash
python client.py --id 2 --port 7000
```

---

## File Structure

| File | Lines | Description |
|------|-------|-------------|
| `crypto_utils.py` | 338 | AES-CBC, PKCS#7 padding, HMAC-SHA256 |
| `protocol_fsm.py` | 387 | Message format, session state, key evolution |
| `server.py` | 540 | Interactive server with aggregation |
| `client.py` | 415 | Interactive client |
| `attacks.py` | 480 | MITM proxy with attack options |
| `README.md` | - | This file |
| `SECURITY.md` | 255 | Security analysis |

---

## Client Commands

```
send <value>   - Send numeric value for this round
quit           - Disconnect and exit
```

Example:
```
[Client 1 | Round 1] > send 42.5
[Client 1 | Round 1] > send 100
[Client 1 | Round 2] > quit
```

---

## Attacker Options

For each intercepted message, the attacker chooses:

| Key | Action | Description |
|-----|--------|-------------|
| `f` | Forward | Pass message unchanged |
| `d` | Drop | Don't deliver message |
| `m` | Modify | Tamper with ciphertext/MAC/header |
| `r` | Replay | Replay a previously captured message |
| `e` | Reflect | Send message back to sender |

### Modification Sub-options

When you press `m`:
```
[1] Flip bits in ciphertext
[2] Corrupt HMAC
[3] Change round number
[4] Change direction byte
[5] Cancel
```

---

## Verbose Output

The system displays detailed cryptographic operations:

```
[ENCRYPT] Plaintext (24 bytes): 87aaaedcb1f63be424c8a1aa...
[PADDING] Padding added: 8 bytes (0x08)
[AES-ENC] Ciphertext: 21c0ebb2e5eeab8c88ce71f8...
[HMAC] Tag: 08f61c69f10822134032999d...

[DECRYPT] Verifying HMAC before decryption...
[HMAC-VERIFY] Result: VALID
[AES-DEC] Plaintext (padded): 87aaaedcb1f63be424c8a1aa...
[UNPADDING] Padding removed: 8 bytes

[KEY-EVOLUTION] Round 0 -> 1
[KEY-EVOLUTION] C2S_Enc: f473bd37... -> f0a7da40...
```

---

## Protocol Flow

### Handshake (Round 0)

```
Client                    Attacker                    Server
   │                         │                           │
   │── CLIENT_HELLO ────────>│                           │
   │                         │ [Action?] f               │
   │                         │── CLIENT_HELLO ─────────>│
   │                         │                           │
   │                         │<── SERVER_CHALLENGE ─────│
   │                         │ [Action?] f               │
   │<── SERVER_CHALLENGE ────│                           │
   │                         │                           │
   │         [Keys evolve, advance to Round 1]           │
```

### Data Exchange (Round N)

```
Client                    Attacker                    Server
   │                         │                           │
   │── CLIENT_DATA ─────────>│                           │
   │                         │ [Action?] f               │
   │                         │── CLIENT_DATA ──────────>│
   │                         │                           │
   │                         │    [Wait for all         │
   │                         │     clients or timeout]  │
   │                         │                           │
   │                         │<── SERVER_AGGR_RESP ─────│
   │                         │ [Action?] f               │
   │<── SERVER_AGGR_RESP ────│                           │
   │                         │                           │
   │         [Keys evolve, advance to Round N+1]         │
```

---

## Attack Demonstrations

### 1. Replay Attack

1. Forward messages normally through the handshake
2. When `CLIENT_DATA` appears, press `f` to forward (gets stored as message #N)
3. On the next round, when a new `CLIENT_DATA` appears, press `r`
4. Enter the stored message number
5. **Result**: Server detects round mismatch or HMAC failure → TERMINATE

### 2. Modification Attack

1. When a message appears, press `m`
2. Choose `[1] Flip bits in ciphertext`
3. **Result**: Receiver's HMAC verification fails → TERMINATE

### 3. Drop Attack (Causes Desynchronization)

1. When `SERVER_AGGR_RESPONSE` appears, press `d` to drop
2. Server has evolved keys, client didn't receive response
3. Client's next message uses old keys
4. **Result**: Server sees HMAC mismatch → TERMINATE

### 4. Reflection Attack

1. When `CLIENT_DATA` appears, press `e` to reflect
2. Message goes back to client instead of server
3. **Result**: Client sees wrong direction or HMAC fails → TERMINATE

---

## Termination Rules

Any of these causes **immediate session termination**:

| Condition | Detection Method |
|-----------|------------------|
| HMAC verification failure | `verify_hmac()` returns False |
| Round number mismatch | Expected round ≠ received round |
| Invalid direction | Expected direction ≠ received direction |
| Client timeout | Didn't send data within timeout period |
| User quit | User typed `quit` command |

After termination, client must reconnect to start a new session.

---

## Default Configuration

| Setting | Value |
|---------|-------|
| Server port | 6000 |
| Attacker port | 7000 |
| Expected clients | 2 |
| Round timeout | 30 seconds |
| Registered client IDs | 1, 2, 3 |

---

## Command Line Options

### Server
```bash
python server.py --host HOST --port PORT --clients N --timeout SECS --quiet
```

### Attacker
```bash
python attacks.py --listen-host HOST --listen-port PORT --server-host HOST --server-port PORT
```

### Client
```bash
python client.py --host HOST --port PORT --id CLIENT_ID --quiet
```

---

## Authors

- Group Number: 33
- Members: Tanmai, Keyur, Prakarsh
