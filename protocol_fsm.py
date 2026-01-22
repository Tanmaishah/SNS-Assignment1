"""
protocol_fsm.py
Protocol logic including:
- Message format and parsing
- Session state management
- Key evolution (ratcheting)
- Opcode definitions

NO networking logic in this file.
"""

import struct
from enum import IntEnum
from dataclasses import dataclass, field
from typing import Tuple, Optional

from crypto_utils import (
    derive_initial_keys,
    evolve_key,
    encrypt_message,
    decrypt_message,
    compute_hmac,
    generate_nonce,
    HMACVerificationError,
    PaddingError,
    CryptoError,
    AES_KEY_SIZE,
    HMAC_SIZE,
    IV_SIZE
)


# ==============================================================================
# Protocol Constants
# ==============================================================================

class Opcode(IntEnum):
    CLIENT_HELLO = 10
    SERVER_CHALLENGE = 20
    CLIENT_DATA = 30
    SERVER_AGGR_RESPONSE = 40
    TERMINATE = 60


class Direction(IntEnum):
    CLIENT_TO_SERVER = 0
    SERVER_TO_CLIENT = 1


class Phase(IntEnum):
    INIT = 1
    ACTIVE = 2
    TERMINATED = 3


# Valid opcodes for each phase and direction
# Format: {Phase: {Direction: [valid_opcodes]}}
VALID_OPCODES = {
    Phase.INIT: {
        Direction.CLIENT_TO_SERVER: [Opcode.CLIENT_HELLO, Opcode.TERMINATE],
        Direction.SERVER_TO_CLIENT: [Opcode.SERVER_CHALLENGE, Opcode.TERMINATE],
    },
    Phase.ACTIVE: {
        Direction.CLIENT_TO_SERVER: [Opcode.CLIENT_DATA, Opcode.TERMINATE],
        Direction.SERVER_TO_CLIENT: [Opcode.SERVER_AGGR_RESPONSE, Opcode.TERMINATE],
    },
    Phase.TERMINATED: {
        Direction.CLIENT_TO_SERVER: [],
        Direction.SERVER_TO_CLIENT: [],
    },
}


def validate_opcode(opcode: Opcode, phase: Phase, direction: Direction) -> bool:
    """
    Check if opcode is valid for current phase and direction.
    
    Returns True if valid, False otherwise.
    """
    if phase not in VALID_OPCODES:
        return False
    if direction not in VALID_OPCODES[phase]:
        return False
    return opcode in VALID_OPCODES[phase][direction]


def get_valid_opcodes(phase: Phase, direction: Direction) -> list:
    """Get list of valid opcodes for given phase and direction."""
    if phase in VALID_OPCODES and direction in VALID_OPCODES[phase]:
        return VALID_OPCODES[phase][direction]
    return []


# Header: Opcode(1) + ClientID(1) + Round(4) + Direction(1) + IV(16) = 23 bytes
HEADER_SIZE = 1 + 1 + 4 + 1 + IV_SIZE  # 23 bytes


# ==============================================================================
# Exceptions
# ==============================================================================

class ProtocolError(Exception):
    """Base protocol error."""
    pass


class InvalidMessageError(ProtocolError):
    """Message format is invalid."""
    pass


class RoundMismatchError(ProtocolError):
    """Round number mismatch."""
    pass


class InvalidOpcodeError(ProtocolError):
    """Invalid opcode for current phase."""
    pass


class DirectionError(ProtocolError):
    """Wrong message direction."""
    pass


# ==============================================================================
# Session State
# ==============================================================================

@dataclass
class SessionState:
    """
    Session state for one client-server connection.
    """
    client_id: int
    master_key: bytes
    phase: Phase = Phase.INIT
    round_number: int = 0
    
    # Keys (initialized in __post_init__)
    c2s_enc: bytes = field(default=b'', repr=False)
    c2s_mac: bytes = field(default=b'', repr=False)
    s2c_enc: bytes = field(default=b'', repr=False)
    s2c_mac: bytes = field(default=b'', repr=False)
    
    def __post_init__(self):
        if not 0 <= self.client_id <= 255:
            raise ValueError("Client ID must be 0-255")
        self._init_keys()
    
    def _init_keys(self, verbose: bool = False):
        """Initialize/reset keys from master key."""
        keys = derive_initial_keys(self.master_key, verbose=verbose)
        self.c2s_enc = keys['c2s_enc']
        self.c2s_mac = keys['c2s_mac']
        self.s2c_enc = keys['s2c_enc']
        self.s2c_mac = keys['s2c_mac']
    
    def reset(self, verbose: bool = False):
        """Reset session to initial state (for reconnection)."""
        self.phase = Phase.INIT
        self.round_number = 0
        self._init_keys(verbose=verbose)
        if verbose:
            print(f"[SESSION] Reset to INIT, round 0")
    
    def get_enc_key(self, direction: Direction) -> bytes:
        """Get encryption key for direction."""
        return self.c2s_enc if direction == Direction.CLIENT_TO_SERVER else self.s2c_enc
    
    def get_mac_key(self, direction: Direction) -> bytes:
        """Get MAC key for direction."""
        return self.c2s_mac if direction == Direction.CLIENT_TO_SERVER else self.s2c_mac
    
    def evolve_keys(self, c2s_ciphertext: bytes, c2s_nonce: bytes,
                    s2c_data: bytes, s2c_status: bytes, verbose: bool = False):
        """
        Evolve all keys after successful round.
        
        C2S_Enc_{R+1} = H(C2S_Enc_R || Ciphertext_R)
        C2S_Mac_{R+1} = H(C2S_Mac_R || Nonce_R)
        S2C_Enc_{R+1} = H(S2C_Enc_R || AggregatedData_R)
        S2C_Mac_{R+1} = H(S2C_Mac_R || StatusCode_R)
        """
        old_keys = {
            'c2s_enc': self.c2s_enc.hex()[:16],
            'c2s_mac': self.c2s_mac.hex()[:16],
            's2c_enc': self.s2c_enc.hex()[:16],
            's2c_mac': self.s2c_mac.hex()[:16]
        }
        
        self.c2s_enc = evolve_key(self.c2s_enc, c2s_ciphertext)[:AES_KEY_SIZE]
        self.c2s_mac = evolve_key(self.c2s_mac, c2s_nonce)
        self.s2c_enc = evolve_key(self.s2c_enc, s2c_data)[:AES_KEY_SIZE]
        self.s2c_mac = evolve_key(self.s2c_mac, s2c_status)
        
        self.round_number += 1
        
        if verbose:
            print(f"\n[KEY-EVOLUTION] Round {self.round_number - 1} -> {self.round_number}")
            print(f"[KEY-EVOLUTION] C2S_Enc: {old_keys['c2s_enc']}... -> {self.c2s_enc.hex()[:16]}...")
            print(f"[KEY-EVOLUTION] C2S_Mac: {old_keys['c2s_mac']}... -> {self.c2s_mac.hex()[:16]}...")
            print(f"[KEY-EVOLUTION] S2C_Enc: {old_keys['s2c_enc']}... -> {self.s2c_enc.hex()[:16]}...")
            print(f"[KEY-EVOLUTION] S2C_Mac: {old_keys['s2c_mac']}... -> {self.s2c_mac.hex()[:16]}...")


# ==============================================================================
# Message Building
# ==============================================================================

def build_header(opcode: Opcode, client_id: int, round_num: int, 
                 direction: Direction, iv: bytes) -> bytes:
    """
    Build message header.
    Format: Opcode(1) | ClientID(1) | Round(4) | Direction(1) | IV(16)
    """
    return struct.pack('!BBIB', opcode, client_id, round_num, direction) + iv


def build_message(opcode: Opcode, client_id: int, round_num: int,
                  direction: Direction, payload: bytes,
                  enc_key: bytes, mac_key: bytes, verbose: bool = False) -> Tuple[bytes, bytes, bytes]:
    """
    Build a complete encrypted message.
    
    Returns: (complete_message, ciphertext, nonce)
             nonce is first 16 bytes of payload (for key evolution)
    """
    if verbose:
        print(f"\n[BUILD] Opcode: {opcode.name}, Client: {client_id}, Round: {round_num}, Dir: {direction.name}")
    
    # Extract nonce (first 16 bytes of payload) for key evolution tracking
    nonce = payload[:16] if len(payload) >= 16 else payload
    
    # Encrypt (header without IV first, we'll add IV after)
    temp_header = struct.pack('!BBIB', opcode, client_id, round_num, direction)
    iv, ciphertext, _ = encrypt_message(enc_key, mac_key, payload, temp_header, verbose=verbose)
    
    # Build full header with IV
    header = build_header(opcode, client_id, round_num, direction, iv)
    
    # Compute HMAC over header + ciphertext
    hmac_tag = compute_hmac(mac_key, header + ciphertext, verbose=verbose)
    
    message = header + ciphertext + hmac_tag
    
    if verbose:
        print(f"[BUILD] Total message size: {len(message)} bytes")
    
    return message, ciphertext, nonce


# ==============================================================================
# Message Parsing
# ==============================================================================

def parse_header(data: bytes) -> Tuple[Opcode, int, int, Direction, bytes]:
    """
    Parse message header.
    Returns: (opcode, client_id, round_num, direction, iv)
    """
    if len(data) < HEADER_SIZE:
        raise InvalidMessageError(f"Message too short: {len(data)} < {HEADER_SIZE}")
    
    opcode, client_id, round_num, direction = struct.unpack('!BBIB', data[:7])
    iv = data[7:7 + IV_SIZE]
    
    try:
        opcode = Opcode(opcode)
    except ValueError:
        raise InvalidMessageError(f"Invalid opcode: {opcode}")
    
    try:
        direction = Direction(direction)
    except ValueError:
        raise InvalidMessageError(f"Invalid direction: {direction}")
    
    return opcode, client_id, round_num, direction, iv


def parse_message(data: bytes, enc_key: bytes, mac_key: bytes,
                  expected_round: int, expected_direction: Direction,
                  expected_phase: Phase = None,
                  verbose: bool = False) -> Tuple[Opcode, int, bytes, bytes, bytes]:
    """
    Parse and decrypt a message.
    
    Validates round number, direction, opcode (if phase provided), and HMAC before decryption.
    
    Args:
        data: Raw message bytes
        enc_key: Encryption key
        mac_key: MAC key
        expected_round: Expected round number
        expected_direction: Expected message direction
        expected_phase: If provided, validates opcode is valid for this phase
        verbose: Enable verbose output
    
    Returns: (opcode, client_id, payload, ciphertext, nonce)
    Raises: ProtocolError on any validation failure (including HMAC/padding errors)
    """
    if len(data) < HEADER_SIZE + HMAC_SIZE:
        raise InvalidMessageError("Message too short")
    
    # Parse header
    opcode, client_id, round_num, direction, iv = parse_header(data)
    
    if verbose:
        print(f"\n[PARSE] Opcode: {opcode.name}, Client: {client_id}, Round: {round_num}, Dir: {direction.name}")
    
    # Validate round number
    if round_num != expected_round:
        raise RoundMismatchError(f"Expected round {expected_round}, got {round_num}")
    
    # Validate direction
    if direction != expected_direction:
        raise DirectionError(f"Expected {expected_direction.name}, got {direction.name}")
    
    # Validate opcode for phase (if phase provided)
    if expected_phase is not None:
        if not validate_opcode(opcode, expected_phase, direction):
            valid_opcodes = get_valid_opcodes(expected_phase, direction)
            valid_names = [op.name for op in valid_opcodes]
            raise InvalidOpcodeError(
                f"Opcode {opcode.name} not valid in {expected_phase.name} phase. "
                f"Valid opcodes: {valid_names}"
            )
        if verbose:
            print(f"[PARSE] Opcode {opcode.name} valid for {expected_phase.name} phase")
    
    # Extract parts
    header = data[:HEADER_SIZE]
    hmac_tag = data[-HMAC_SIZE:]
    ciphertext = data[HEADER_SIZE:-HMAC_SIZE]
    
    if len(ciphertext) == 0:
        raise InvalidMessageError("Empty ciphertext")
    
    # Verify HMAC and decrypt
    # Catch crypto errors and convert to protocol errors for consistent handling
    try:
        payload = decrypt_message(enc_key, mac_key, iv, ciphertext, header, hmac_tag, verbose=verbose)
    except HMACVerificationError as e:
        raise InvalidMessageError(f"HMAC verification failed: {e}")
    except PaddingError as e:
        raise InvalidMessageError(f"Padding error (possible tampering): {e}")
    
    # Extract nonce (first 16 bytes of payload)
    nonce = payload[:16] if len(payload) >= 16 else payload
    
    return opcode, client_id, payload, ciphertext, nonce


# ==============================================================================
# Payload Builders
# ==============================================================================

def build_client_hello_payload(nonce: bytes = None, timestamp: int = None) -> bytes:
    """Build CLIENT_HELLO payload: Nonce(16) | Timestamp(8)"""
    import time
    nonce = nonce or generate_nonce()
    timestamp = timestamp or int(time.time())
    return nonce + struct.pack('!Q', timestamp)


def build_server_challenge_payload(nonce: bytes = None, challenge: bytes = None) -> bytes:
    """Build SERVER_CHALLENGE payload: Nonce(16) | Challenge(32)"""
    nonce = nonce or generate_nonce()
    challenge = challenge or generate_nonce(32)
    return nonce + challenge


def build_client_data_payload(nonce: bytes = None, data: str = "") -> bytes:
    """Build CLIENT_DATA payload: Nonce(16) | Data(variable)"""
    nonce = nonce or generate_nonce()
    return nonce + data.encode('utf-8')


def build_server_response_payload(status: int, aggregate_data: str) -> bytes:
    """Build SERVER_AGGR_RESPONSE payload: Status(1) | Data(variable)"""
    return struct.pack('!B', status) + aggregate_data.encode('utf-8')


def build_terminate_payload(reason: str) -> bytes:
    """Build TERMINATE payload."""
    return reason.encode('utf-8')


# ==============================================================================
# Payload Parsers
# ==============================================================================

def parse_client_hello_payload(payload: bytes) -> Tuple[bytes, int]:
    """Parse CLIENT_HELLO payload. Returns: (nonce, timestamp)"""
    if len(payload) < 24:
        raise InvalidMessageError("CLIENT_HELLO payload too short")
    nonce = payload[:16]
    timestamp = struct.unpack('!Q', payload[16:24])[0]
    return nonce, timestamp


def parse_server_challenge_payload(payload: bytes) -> Tuple[bytes, bytes]:
    """Parse SERVER_CHALLENGE payload. Returns: (nonce, challenge)"""
    if len(payload) < 16:
        raise InvalidMessageError("SERVER_CHALLENGE payload too short")
    nonce = payload[:16]
    challenge = payload[16:]
    return nonce, challenge


def parse_client_data_payload(payload: bytes) -> Tuple[bytes, str]:
    """Parse CLIENT_DATA payload. Returns: (nonce, data_string)"""
    if len(payload) < 16:
        raise InvalidMessageError("CLIENT_DATA payload too short")
    nonce = payload[:16]
    data = payload[16:].decode('utf-8')
    return nonce, data


def parse_server_response_payload(payload: bytes) -> Tuple[int, str]:
    """Parse SERVER_AGGR_RESPONSE payload. Returns: (status, aggregate_string)"""
    if len(payload) < 1:
        raise InvalidMessageError("SERVER_AGGR_RESPONSE payload too short")
    status = payload[0]
    data = payload[1:].decode('utf-8')
    return status, data


def parse_terminate_payload(payload: bytes) -> str:
    """Parse TERMINATE payload. Returns: reason"""
    return payload.decode('utf-8', errors='replace')


# ==============================================================================
# Utility
# ==============================================================================

def get_opcode_name(opcode: int) -> str:
    """Get opcode name from value."""
    try:
        return Opcode(opcode).name
    except ValueError:
        return f"UNKNOWN({opcode})"


def message_summary(data: bytes) -> str:
    """Get a one-line summary of a message (without decryption)."""
    try:
        opcode, client_id, round_num, direction, iv = parse_header(data)
        return f"{opcode.name} | Client {client_id} | Round {round_num} | {direction.name} | {len(data)} bytes"
    except:
        return f"Invalid message ({len(data)} bytes)"