"""
attacks.py
Interactive Man-in-the-Middle (MITM) Attacker

All traffic between clients and server passes through this proxy.
For each message, the attacker can choose to:
- [f]orward  : Pass message unchanged
- [d]rop     : Don't deliver message
- [m]odify   : Modify ciphertext or MAC
- [r]eplay   : Replay a previously captured message
- r[e]flect  : Send message back to sender
"""

import socket
import threading
import struct
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum, auto

from crypto_utils import HMAC_SIZE
from protocol_fsm import (
    HEADER_SIZE, parse_header, message_summary, Opcode, Direction
)


# ==============================================================================
# Configuration
# ==============================================================================

@dataclass
class AttackerConfig:
    listen_host: str = '127.0.0.1'
    listen_port: int = 7000       # Clients connect here
    server_host: str = '127.0.0.1'
    server_port: int = 6000       # Forward to server here


# ==============================================================================
# Message Store for Replay
# ==============================================================================

class MessageStore:
    """Stores captured messages for replay attacks."""
    
    def __init__(self):
        self.messages: List[Tuple[str, int, bytes]] = []  # (direction, client_id, data)
        self.lock = threading.Lock()
    
    def add(self, direction: str, client_id: int, data: bytes):
        """Add a captured message."""
        with self.lock:
            self.messages.append((direction, client_id, data))
            idx = len(self.messages)
            print(f"    [STORED] Message #{idx}")
    
    def list_messages(self):
        """List all captured messages."""
        with self.lock:
            if not self.messages:
                print("    No stored messages")
                return
            
            print("\n    Stored Messages:")
            print("    " + "-"*50)
            for i, (direction, client_id, data) in enumerate(self.messages, 1):
                summary = message_summary(data)
                print(f"    [{i}] {direction} Client {client_id}: {summary}")
            print("    " + "-"*50)
    
    def get(self, index: int) -> Optional[bytes]:
        """Get message by index (1-based)."""
        with self.lock:
            if 1 <= index <= len(self.messages):
                return self.messages[index - 1][2]
            return None


# ==============================================================================
# Attack Functions
# ==============================================================================

def modify_message(data: bytes) -> bytes:
    """
    Interactively modify a message.
    """
    print("\n    Modification Options:")
    print("    [1] Flip bits in ciphertext")
    print("    [2] Corrupt HMAC")
    print("    [3] Change round number")
    print("    [4] Change direction byte")
    print("    [5] Cancel")
    
    choice = input("    Choice: ").strip()
    
    if choice == '1':
        # Flip ciphertext bits
        if len(data) <= HEADER_SIZE + HMAC_SIZE:
            print("    No ciphertext to modify!")
            return data
        
        header = data[:HEADER_SIZE]
        ciphertext = bytearray(data[HEADER_SIZE:-HMAC_SIZE])
        hmac_tag = data[-HMAC_SIZE:]
        
        # Flip first byte of ciphertext
        if len(ciphertext) > 0:
            old_byte = ciphertext[0]
            ciphertext[0] ^= 0xFF
            print(f"    Flipped ciphertext[0]: 0x{old_byte:02X} -> 0x{ciphertext[0]:02X}")
        
        return header + bytes(ciphertext) + hmac_tag
    
    elif choice == '2':
        # Corrupt HMAC
        modified = bytearray(data)
        old_byte = modified[-1]
        modified[-1] ^= 0xFF
        print(f"    Corrupted HMAC last byte: 0x{old_byte:02X} -> 0x{modified[-1]:02X}")
        return bytes(modified)
    
    elif choice == '3':
        # Change round number
        header = bytearray(data[:HEADER_SIZE])
        old_round = struct.unpack('!I', header[2:6])[0]
        new_round = old_round + 1
        header[2:6] = struct.pack('!I', new_round)
        print(f"    Changed round: {old_round} -> {new_round}")
        return bytes(header) + data[HEADER_SIZE:]
    
    elif choice == '4':
        # Change direction
        header = bytearray(data[:HEADER_SIZE])
        old_dir = header[6]
        header[6] ^= 1
        dir_names = {0: "C2S", 1: "S2C"}
        print(f"    Changed direction: {dir_names.get(old_dir, '?')} -> {dir_names.get(header[6], '?')}")
        return bytes(header) + data[HEADER_SIZE:]
    
    else:
        print("    Cancelled")
        return data


# ==============================================================================
# Client Handler
# ==============================================================================

class ClientHandler:
    """Handles one client connection through the MITM proxy."""
    
    def __init__(self, client_conn: socket.socket, client_addr: Tuple[str, int],
                 server_host: str, server_port: int, message_store: MessageStore,
                 user_interaction_lock: threading.Lock):
        self.client_conn = client_conn
        self.client_addr = client_addr
        self.server_host = server_host
        self.server_port = server_port
        self.message_store = message_store
        self.user_interaction_lock = user_interaction_lock
        self.server_conn: Optional[socket.socket] = None
        self.client_id: Optional[int] = None
        self.running = False
        self.lock = threading.Lock()
    
    def log(self, msg: str):
        """Print log message."""
        cid = self.client_id if self.client_id else "?"
        print(f"[ATTACKER] [Client {cid}] {msg}")
    
    def connect_to_server(self) -> bool:
        """Connect to the real server."""
        try:
            self.server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_conn.connect((self.server_host, self.server_port))
            return True
        except Exception as e:
            self.log(f"Failed to connect to server: {e}")
            return False
    
    def recv_from_client(self) -> Optional[bytes]:
        """Receive message from client."""
        try:
            self.client_conn.settimeout(1.0)
            header = b''
            while len(header) < HEADER_SIZE:
                chunk = self.client_conn.recv(HEADER_SIZE - len(header))
                if not chunk:
                    return None
                header += chunk
            
            self.client_conn.settimeout(1.0)
            rest = self.client_conn.recv(4096)
            return header + rest if rest else None
        except socket.timeout:
            return None
        except:
            return None
    
    def recv_from_server(self) -> Optional[bytes]:
        """Receive message from server."""
        try:
            self.server_conn.settimeout(1.0)
            header = b''
            while len(header) < HEADER_SIZE:
                chunk = self.server_conn.recv(HEADER_SIZE - len(header))
                if not chunk:
                    return None
                header += chunk
            
            self.server_conn.settimeout(1.0)
            rest = self.server_conn.recv(4096)
            return header + rest if rest else None
        except socket.timeout:
            return None
        except:
            return None
    
    def send_to_server(self, data: bytes) -> bool:
        """Send to server."""
        try:
            self.server_conn.sendall(data)
            return True
        except:
            return False
    
    def send_to_client(self, data: bytes) -> bool:
        """Send to client."""
        try:
            self.client_conn.sendall(data)
            return True
        except:
            return False
    
    def prompt_action(self, direction: str, data: bytes) -> Optional[bytes]:
        """
        Prompt attacker for action on this message.

        Returns: data to forward, or None to drop
        """
        # Acquire global lock to serialize user interactions across all handlers
        with self.user_interaction_lock:
            summary = message_summary(data)

            # Extract client ID from message
            try:
                _, client_id, round_num, dir_enum, _ = parse_header(data)
                self.client_id = client_id
            except:
                client_id = self.client_id or "?"
                round_num = "?"

            print(f"\n{'='*60}")
            print(f"[INTERCEPTED] {direction}")
            print(f"{'='*60}")
            print(f"    {summary}")
            print(f"    Raw ({len(data)} bytes): {data[:32].hex()}...")
            print()
            print("    Actions:")
            print("    [f] Forward unchanged")
            print("    [d] Drop message")
            print("    [m] Modify message")
            print("    [r] Replay stored message")
            print("    [e] Reflect back to sender")
            print()

            while True:
                action = input("    Action: ").strip().lower()

                if action == 'f':
                    print("    -> Forwarding")
                    self.message_store.add(direction, client_id, data)
                    return data

                elif action == 'd':
                    print("    -> DROPPED")
                    self.message_store.add(direction, client_id, data)
                    return None

                elif action == 'm':
                    modified = modify_message(data)
                    if modified != data:
                        print("    -> Forwarding MODIFIED message")
                    else:
                        print("    -> Forwarding unchanged")
                    self.message_store.add(direction, client_id, data)  # Store original
                    return modified

                elif action == 'r':
                    self.message_store.list_messages()
                    try:
                        idx = int(input("    Replay message #: ").strip())
                        replay_data = self.message_store.get(idx)
                        if replay_data:
                            print(f"    -> REPLAYING message #{idx}")
                            print(f"       {message_summary(replay_data)}")
                            self.message_store.add(direction, client_id, data)  # Store original
                            return replay_data
                        else:
                            print("    Invalid index")
                    except ValueError:
                        print("    Invalid input")

                elif action == 'e':
                    print("    -> REFLECTING back to sender")
                    self.message_store.add(direction, client_id, data)
                    # Return special marker - caller will handle reflection
                    return "REFLECT"

                else:
                    print("    Invalid action. Use: f/d/m/r/e")
    
    def run(self):
        """Run the MITM handler."""
        self.running = True
        
        # Connect to server
        if not self.connect_to_server():
            self.client_conn.close()
            return
        
        self.log("Proxy established")
        
        while self.running:
            # Check for client -> server messages
            c2s_data = self.recv_from_client()
            if c2s_data:
                result = self.prompt_action("Client -> Server", c2s_data)
                
                if result == "REFLECT":
                    # Reflect back to client
                    if not self.send_to_client(c2s_data):
                        break
                elif result is not None:
                    if not self.send_to_server(result):
                        break
                # If None (dropped), just continue
            
            # Check for server -> client messages
            s2c_data = self.recv_from_server()
            if s2c_data:
                result = self.prompt_action("Server -> Client", s2c_data)
                
                if result == "REFLECT":
                    # Reflect back to server
                    if not self.send_to_server(s2c_data):
                        break
                elif result is not None:
                    if not self.send_to_client(result):
                        break
                # If None (dropped), just continue
        
        self.cleanup()
    
    def cleanup(self):
        """Clean up connections."""
        self.running = False
        try:
            self.client_conn.close()
        except:
            pass
        try:
            if self.server_conn:
                self.server_conn.close()
        except:
            pass
        self.log("Connection closed")


# ==============================================================================
# MITM Attacker
# ==============================================================================

class MITMAttacker:
    """Man-in-the-Middle attacker proxy."""
    
    def __init__(self, config: AttackerConfig):
        self.config = config
        self.socket: Optional[socket.socket] = None
        self.running = False
        self.message_store = MessageStore()
        self.handlers: List[ClientHandler] = []
        # Global lock to serialize user interactions across all handlers
        self.user_interaction_lock = threading.Lock()
    
    def log(self, msg: str):
        """Print log message."""
        print(f"[ATTACKER] {msg}")
    
    def start(self):
        """Start the MITM proxy."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.config.listen_host, self.config.listen_port))
        self.socket.listen(5)
        self.running = True
        
        print("="*60)
        print("MITM ATTACKER")
        print("="*60)
        print(f"Listening on: {self.config.listen_host}:{self.config.listen_port}")
        print(f"Forwarding to: {self.config.server_host}:{self.config.server_port}")
        print()
        print("All client-server traffic will pass through this proxy.")
        print("For each message, you can choose to:")
        print("  [f]orward  - Pass unchanged")
        print("  [d]rop     - Don't deliver")
        print("  [m]odify   - Tamper with message")
        print("  [r]eplay   - Replay old message")
        print("  r[e]flect  - Send back to sender")
        print()
        print("Waiting for connections...")
        print("="*60)
        
        while self.running:
            try:
                self.socket.settimeout(1.0)
                conn, addr = self.socket.accept()
                self.log(f"New client connection from {addr}")
                
                handler = ClientHandler(
                    conn, addr,
                    self.config.server_host,
                    self.config.server_port,
                    self.message_store,
                    self.user_interaction_lock
                )
                self.handlers.append(handler)
                
                thread = threading.Thread(target=handler.run)
                thread.daemon = True
                thread.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.log(f"Accept error: {e}")
    
    def stop(self):
        """Stop the attacker."""
        self.running = False
        
        for handler in self.handlers:
            handler.running = False
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        self.log("Stopped")


# ==============================================================================
# Main
# ==============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='MITM Attacker')
    parser.add_argument('--listen-host', default='127.0.0.1', help='Listen host')
    parser.add_argument('--listen-port', type=int, default=7000, help='Listen port (clients connect here)')
    parser.add_argument('--server-host', default='127.0.0.1', help='Real server host')
    parser.add_argument('--server-port', type=int, default=6000, help='Real server port')
    args = parser.parse_args()
    
    config = AttackerConfig(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        server_host=args.server_host,
        server_port=args.server_port
    )
    
    attacker = MITMAttacker(config)
    
    try:
        attacker.start()
    except KeyboardInterrupt:
        print("\nInterrupted")
        attacker.stop()


if __name__ == '__main__':
    main()
