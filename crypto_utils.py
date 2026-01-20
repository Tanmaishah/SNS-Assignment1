"""
crypto_utils.py
Cryptographic primitives only:
- AES-128-CBC encryption/decryption
- Manual PKCS#7 padding/unpadding
- HMAC-SHA256 computation and verification
- Key derivation using SHA-256

NO protocol or networking logic in this file.
"""

import os
import hmac
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# Constants
AES_BLOCK_SIZE = 16
AES_KEY_SIZE = 16  # AES-128
HMAC_SIZE = 32     # SHA-256 output
IV_SIZE = 16


# ==============================================================================
# Exceptions
# ==============================================================================

class CryptoError(Exception):
    """Base exception for cryptographic errors."""
    pass


class PaddingError(CryptoError):
    """Invalid padding detected."""
    pass


class HMACVerificationError(CryptoError):
    """HMAC verification failed."""
    pass


# ==============================================================================
# PKCS#7 Padding (Manual Implementation)
# ==============================================================================

def pkcs7_pad(data: bytes, verbose: bool = False) -> bytes:
    """
    Apply PKCS#7 padding.
    
    Padding is always applied. Each padding byte equals the padding length.
    """
    padding_length = AES_BLOCK_SIZE - (len(data) % AES_BLOCK_SIZE)
    padding = bytes([padding_length] * padding_length)
    padded = data + padding
    
    if verbose:
        print(f"[PADDING] Original length: {len(data)} bytes")
        print(f"[PADDING] Padding added: {padding_length} bytes (0x{padding_length:02X})")
        print(f"[PADDING] Padded length: {len(padded)} bytes")
    
    return padded


def pkcs7_unpad(padded_data: bytes, verbose: bool = False) -> bytes:
    """
    Remove PKCS#7 padding.
    
    Raises PaddingError if padding is invalid (indicates tampering).
    """
    if not padded_data:
        raise PaddingError("Empty data cannot be unpadded")
    
    if len(padded_data) % AES_BLOCK_SIZE != 0:
        raise PaddingError("Data length is not a multiple of block size")
    
    padding_length = padded_data[-1]
    
    if padding_length < 1 or padding_length > AES_BLOCK_SIZE:
        raise PaddingError(f"Invalid padding length: {padding_length}")
    
    if padding_length > len(padded_data):
        raise PaddingError("Padding length exceeds data length")
    
    # Verify all padding bytes
    for i in range(1, padding_length + 1):
        if padded_data[-i] != padding_length:
            raise PaddingError("Invalid padding bytes")
    
    if verbose:
        print(f"[UNPADDING] Padded length: {len(padded_data)} bytes")
        print(f"[UNPADDING] Padding removed: {padding_length} bytes (0x{padding_length:02X})")
        print(f"[UNPADDING] Original length: {len(padded_data) - padding_length} bytes")
    
    return padded_data[:-padding_length]


# ==============================================================================
# AES-128-CBC Encryption/Decryption
# ==============================================================================

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes, verbose: bool = False) -> bytes:
    """
    Encrypt plaintext using AES-128-CBC.
    Plaintext must already be padded.
    """
    if len(key) != AES_KEY_SIZE:
        raise CryptoError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
    
    if len(iv) != IV_SIZE:
        raise CryptoError(f"IV must be {IV_SIZE} bytes, got {len(iv)}")
    
    if len(plaintext) % AES_BLOCK_SIZE != 0:
        raise CryptoError("Plaintext must be padded to block size")
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    if verbose:
        print(f"[AES-ENC] Key: {key.hex()[:32]}...")
        print(f"[AES-ENC] IV: {iv.hex()}")
        print(f"[AES-ENC] Plaintext (padded): {plaintext.hex()}")
        print(f"[AES-ENC] Ciphertext: {ciphertext.hex()}")
    
    return ciphertext


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes, verbose: bool = False) -> bytes:
    """
    Decrypt ciphertext using AES-128-CBC.
    Returns padded plaintext.
    """
    if len(key) != AES_KEY_SIZE:
        raise CryptoError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
    
    if len(iv) != IV_SIZE:
        raise CryptoError(f"IV must be {IV_SIZE} bytes, got {len(iv)}")
    
    if len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise CryptoError("Ciphertext length must be multiple of block size")
    
    if len(ciphertext) == 0:
        raise CryptoError("Ciphertext cannot be empty")
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    if verbose:
        print(f"[AES-DEC] Key: {key.hex()[:32]}...")
        print(f"[AES-DEC] IV: {iv.hex()}")
        print(f"[AES-DEC] Ciphertext: {ciphertext.hex()}")
        print(f"[AES-DEC] Plaintext (padded): {plaintext.hex()}")
    
    return plaintext


# ==============================================================================
# HMAC-SHA256
# ==============================================================================

def compute_hmac(key: bytes, data: bytes, verbose: bool = False) -> bytes:
    """Compute HMAC-SHA256."""
    tag = hmac.new(key, data, hashlib.sha256).digest()
    
    if verbose:
        print(f"[HMAC] Key: {key.hex()[:32]}...")
        print(f"[HMAC] Data length: {len(data)} bytes")
        print(f"[HMAC] Tag: {tag.hex()}")
    
    return tag


def verify_hmac(key: bytes, data: bytes, expected_hmac: bytes, verbose: bool = False) -> bool:
    """Verify HMAC-SHA256 using constant-time comparison."""
    computed = compute_hmac(key, data, verbose=False)
    result = hmac.compare_digest(computed, expected_hmac)
    
    if verbose:
        print(f"[HMAC-VERIFY] Expected: {expected_hmac.hex()}")
        print(f"[HMAC-VERIFY] Computed: {computed.hex()}")
        print(f"[HMAC-VERIFY] Result: {'VALID' if result else 'INVALID'}")
    
    return result


# ==============================================================================
# Key Derivation
# ==============================================================================

def derive_key(master_key: bytes, context: str) -> bytes:
    """Derive a key from master key and context string using SHA-256."""
    return hashlib.sha256(master_key + context.encode()).digest()


def derive_initial_keys(master_key: bytes, verbose: bool = False) -> dict:
    """
    Derive all four initial session keys from master key.
    
    Returns dict with keys: c2s_enc, c2s_mac, s2c_enc, s2c_mac
    """
    keys = {
        'c2s_enc': derive_key(master_key, "C2S-ENC")[:AES_KEY_SIZE],
        'c2s_mac': derive_key(master_key, "C2S-MAC"),
        's2c_enc': derive_key(master_key, "S2C-ENC")[:AES_KEY_SIZE],
        's2c_mac': derive_key(master_key, "S2C-MAC")
    }
    
    if verbose:
        print(f"[KEY-DERIVE] Master key: {master_key.hex()[:32]}...")
        print(f"[KEY-DERIVE] C2S_Enc: {keys['c2s_enc'].hex()}")
        print(f"[KEY-DERIVE] C2S_Mac: {keys['c2s_mac'].hex()}")
        print(f"[KEY-DERIVE] S2C_Enc: {keys['s2c_enc'].hex()}")
        print(f"[KEY-DERIVE] S2C_Mac: {keys['s2c_mac'].hex()}")
    
    return keys


def evolve_key(current_key: bytes, data: bytes) -> bytes:
    """
    Evolve a key using ratcheting.
    New key = SHA256(current_key || data)
    """
    return hashlib.sha256(current_key + data).digest()


# ==============================================================================
# Random Number Generation
# ==============================================================================

def generate_random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes."""
    return os.urandom(length)


def generate_iv() -> bytes:
    """Generate random IV for AES-CBC."""
    return generate_random_bytes(IV_SIZE)


def generate_nonce(length: int = 16) -> bytes:
    """Generate random nonce."""
    return generate_random_bytes(length)


# ==============================================================================
# High-Level Encrypt/Decrypt with Transparency
# ==============================================================================

def encrypt_message(enc_key: bytes, mac_key: bytes, plaintext: bytes, 
                    header: bytes, verbose: bool = False) -> tuple:
    """
    Encrypt plaintext and compute HMAC.
    
    Returns: (iv, ciphertext, hmac_tag)
    """
    if verbose:
        print("\n" + "="*50)
        print("[ENCRYPT] Starting encryption")
        print("="*50)
        print(f"[ENCRYPT] Plaintext ({len(plaintext)} bytes): {plaintext.hex()}")
        try:
            print(f"[ENCRYPT] Plaintext (ASCII): {plaintext.decode('utf-8', errors='replace')}")
        except:
            pass
    
    # Pad
    padded = pkcs7_pad(plaintext, verbose=verbose)
    
    # Generate IV
    iv = generate_iv()
    if verbose:
        print(f"[ENCRYPT] Generated IV: {iv.hex()}")
    
    # Encrypt
    ciphertext = aes_cbc_encrypt(enc_key, iv, padded, verbose=verbose)
    
    # Compute HMAC over (header || ciphertext)
    hmac_data = header + ciphertext
    hmac_tag = compute_hmac(mac_key, hmac_data, verbose=verbose)
    
    if verbose:
        print(f"[ENCRYPT] Final ciphertext ({len(ciphertext)} bytes): {ciphertext.hex()}")
        print("="*50 + "\n")
    
    return iv, ciphertext, hmac_tag


def decrypt_message(enc_key: bytes, mac_key: bytes, iv: bytes, ciphertext: bytes,
                    header: bytes, received_hmac: bytes, verbose: bool = False) -> bytes:
    """
    Verify HMAC and decrypt ciphertext.
    
    CRITICAL: HMAC is verified BEFORE decryption.
    
    Returns: plaintext
    Raises: HMACVerificationError, PaddingError
    """
    if verbose:
        print("\n" + "="*50)
        print("[DECRYPT] Starting decryption")
        print("="*50)
        print(f"[DECRYPT] Ciphertext ({len(ciphertext)} bytes): {ciphertext.hex()}")
        print(f"[DECRYPT] IV: {iv.hex()}")
        print(f"[DECRYPT] Received HMAC: {received_hmac.hex()}")
    
    # VERIFY HMAC FIRST (before any decryption!)
    hmac_data = header + ciphertext
    if verbose:
        print("[DECRYPT] Verifying HMAC before decryption...")
    
    if not verify_hmac(mac_key, hmac_data, received_hmac, verbose=verbose):
        if verbose:
            print("[DECRYPT] HMAC VERIFICATION FAILED!")
        raise HMACVerificationError("HMAC verification failed")
    
    if verbose:
        print("[DECRYPT] HMAC verified successfully, proceeding with decryption")
    
    # Decrypt
    padded_plaintext = aes_cbc_decrypt(enc_key, iv, ciphertext, verbose=verbose)
    
    # Unpad
    plaintext = pkcs7_unpad(padded_plaintext, verbose=verbose)
    
    if verbose:
        print(f"[DECRYPT] Final plaintext ({len(plaintext)} bytes): {plaintext.hex()}")
        try:
            print(f"[DECRYPT] Plaintext (ASCII): {plaintext.decode('utf-8', errors='replace')}")
        except:
            pass
        print("="*50 + "\n")
    
    return plaintext
