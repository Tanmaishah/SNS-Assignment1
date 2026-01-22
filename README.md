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
python server.py --port 6000 --clients 2 --timeout 30 --handshake-timeout 60
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

| File | Description |
|------|-------------|
| `crypto_utils.py` | AES-128-CBC, manual PKCS#7 padding, HMAC-SHA256 |
| `protocol_fsm.py` | Message format, session state, key evolution, opcode validation |
| `server.py` | Multi-client server with round-based aggregation |
| `client.py` | Interactive client |
| `attacks.py` | MITM proxy with interactive attack options |
| `README.md` | This file |
| `SECURITY.md` | Security analysis |

---

## Protocol Overview

### Phases

| Phase | Description | Valid Opcodes (C2S) | Valid Opcodes (S2C) |
|-------|-------------|---------------------|---------------------|
| INIT | Handshake (Round 0) | CLIENT_HELLO, TERMINATE | SERVER_CHALLENGE, TERMINATE |
| ACTIVE | Data exchange (Round 1+) | CLIENT_DATA, TERMINATE | SERVER_AGGR_RESPONSE, TERMINATE |
| TERMINATED | Session ended | None | None |

### Protocol Flow

```
INIT Phase (Round 0):
    Client ─── CLIENT_HELLO ──────► Server
    Client ◄── SERVER_CHALLENGE ─── Server
    [Keys evolve, transition to ACTIVE]

ACTIVE Phase (Round 1, 2, 3, ...):
    Client ─── CLIENT_DATA ───────► Server
                                    [Server waits for all clients]
    Client ◄── SERVER_AGGR_RESP ─── Server
    [Keys evolve, round increments]
```

### Key Evolution

After each successful round:
```
C2S_Enc_{R+1} = SHA256(C2S_Enc_R || Ciphertext_R)[:16]
C2S_Mac_{R+1} = SHA256(C2S_Mac_R || Nonce_R)
S2C_Enc_{R+1} = SHA256(S2C_Enc_R || AggregatedData_R)[:16]
S2C_Mac_{R+1} = SHA256(S2C_Mac_R || StatusCode_R)
```

---

## Client Commands

```
send <value>   - Send numeric value for this round
quit           - Disconnect and exit
```

Example session:
```
[Client 1 | Round 1] > send 42.5
>>> Aggregate: total=92.50, count=2

[Client 1 | Round 2] > send 100
>>> Aggregate: total=200.00, count=2

[Client 1 | Round 3] > quit
```

---

## Attacker Options

For each intercepted message, the attacker chooses an action:

| Key | Action | Description |
|-----|--------|-------------|
| `f` | Forward | Pass message unchanged |
| `d` | Drop | Don't deliver message (causes timeout) |
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

### Queue Display

The attacker shows how many messages are waiting:
```
[INTERCEPTED] Client -> Server (2 more in queue)
```

---

## Server Behavior

### Handshake Phase
- Waits for clients to connect (with `--handshake-timeout`)
- If timeout reached, starts rounds with whoever connected
- If no clients connected, shuts down

### Round Phase
- Waits for CLIENT_DATA from all active clients (with `--timeout`)
- Clients who don't send data are silently disconnected
- Computes aggregate (sum, count) from received values
- Sends aggregate to all participating clients
- Evolves keys and advances to next round

### Error Handling
- On any protocol error (HMAC fail, round mismatch, invalid opcode): **silent disconnect**
- Server does NOT send TERMINATE message on errors
- Client will timeout waiting for response

---

## Command Line Options

### Server
```bash
python server.py [options]

Options:
  --host HOST                Server host (default: 127.0.0.1)
  --port PORT                Server port (default: 6000)
  --clients N                Expected number of clients (default: 2)
  --timeout SECS             Round timeout in seconds (default: 30)
  --handshake-timeout SECS   Handshake timeout in seconds (default: 60)
  --quiet                    Disable verbose output
```

### Client
```bash
python client.py [options]

Options:
  --host HOST    Server/Attacker host (default: 127.0.0.1)
  --port PORT    Server/Attacker port (default: 7000)
  --id ID        Client ID (required, 1-3)
  --quiet        Disable verbose output
```

### Attacker
```bash
python attacks.py [options]

Options:
  --listen-host HOST    Listen host (default: 127.0.0.1)
  --listen-port PORT    Listen port for clients (default: 7000)
  --server-host HOST    Real server host (default: 127.0.0.1)
  --server-port PORT    Real server port (default: 6000)
```

---

## Pre-Shared Keys

Master keys are pre-provisioned (hardcoded for demonstration):

| Client ID | Master Key |
|-----------|------------|
| 1 | `client_1_master_key_32_bytes_!!` |
| 2 | `client_2_master_key_32_bytes_!!` |
| 3 | `client_3_master_key_32_bytes_!!` |

In a real deployment, these would be securely provisioned out-of-band.

---

## Attack Demonstrations

### 1. HMAC Corruption Attack
```
1. Wait for CLIENT_DATA message
2. Press [m] → [2] Corrupt HMAC
3. Server detects HMAC mismatch → silent disconnect
4. Client times out waiting for response
```

### 2. Ciphertext Modification Attack
```
1. Wait for any message
2. Press [m] → [1] Flip bits in ciphertext
3. Receiver's HMAC verification fails → disconnect
```

### 3. Replay Attack
```
1. Forward messages normally (they get stored)
2. On a later round, press [r]
3. Select an old message to replay
4. Server detects round mismatch → silent disconnect
```

### 4. Drop Attack (Desynchronization)
```
1. Wait for SERVER_AGGR_RESPONSE
2. Press [d] to drop
3. Server evolved keys, client didn't
4. Client's next message uses old keys → HMAC fails
```

### 5. Reflection Attack
```
1. Wait for CLIENT_DATA
2. Press [e] to reflect back to client
3. Client receives wrong direction → rejects
```

### 6. Reordering Attack
```
Reordering is equivalent to replay in our protocol:
1. Drop a message [d]
2. Forward subsequent messages [f]
3. Replay the dropped message later [r]
4. Fails due to round number mismatch or key evolution
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

## Termination Rules

| Condition | Server Action | Client Result |
|-----------|---------------|---------------|
| HMAC verification fails | Silent disconnect | Timeout |
| Round number mismatch | Silent disconnect | Timeout |
| Invalid opcode for phase | Silent disconnect | Timeout |
| Invalid direction | Silent disconnect | Timeout |
| Client timeout | Silent disconnect | Already gone |
| Client sends TERMINATE | Remove session | Voluntary exit |

**Note:** Server never sends TERMINATE on errors. This is by design - once tampering is detected, the channel is not trusted.

---

## Authors

- Group Number: 33
- Members: Keyur,Tanmai, Prakarsh
