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
import queue
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
# Pending Message (for queue)
# ==============================================================================

@dataclass
class PendingMessage:
    """A message waiting to be processed by the attacker."""
    direction: str              # "Client -> Server" or "Server -> Client"
    client_id: int              # Which client this belongs to
    data: bytes                 # Raw message bytes
    handler: 'ClientHandler'    # Reference to handler for sending


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
                 server_host: str, server_port: int, 
                 message_queue: queue.Queue, message_store: MessageStore):
        self.client_conn = client_conn
        self.client_addr = client_addr
        self.server_host = server_host
        self.server_port = server_port
        self.message_queue = message_queue  # Centralized queue
        self.message_store = message_store
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
            self.client_conn.settimeout(0.5)
            header = b''
            while len(header) < HEADER_SIZE:
                chunk = self.client_conn.recv(HEADER_SIZE - len(header))
                if not chunk:
                    return None
                header += chunk
            
            self.client_conn.settimeout(0.5)
            rest = self.client_conn.recv(4096)
            return header + rest if rest else None
        except socket.timeout:
            return None
        except:
            return None
    
    def recv_from_server(self) -> Optional[bytes]:
        """Receive message from server."""
        try:
            self.server_conn.settimeout(0.5)
            header = b''
            while len(header) < HEADER_SIZE:
                chunk = self.server_conn.recv(HEADER_SIZE - len(header))
                if not chunk:
                    return None
                header += chunk
            
            self.server_conn.settimeout(0.5)
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
    
    def run(self):
        """Run the MITM handler - just receives and enqueues messages."""
        self.running = True
        
        # Connect to server
        if not self.connect_to_server():
            self.client_conn.close()
            return
        
        # self.log("Proxy established")
        
        while self.running:
            # Check for client -> server messages
            c2s_data = self.recv_from_client()
            if c2s_data:
                # Extract client ID from message
                try:
                    _, client_id, _, _, _ = parse_header(c2s_data)
                    self.client_id = client_id
                except:
                    client_id = self.client_id or 0
                
                # Enqueue for processing
                pending = PendingMessage(
                    direction="Client -> Server",
                    client_id=client_id,
                    data=c2s_data,
                    handler=self
                )
                self.message_queue.put(pending)
            
            # Check for server -> client messages
            s2c_data = self.recv_from_server()
            if s2c_data:
                # Extract client ID from message
                try:
                    _, client_id, _, _, _ = parse_header(s2c_data)
                    self.client_id = client_id
                except:
                    client_id = self.client_id or 0
                
                # Enqueue for processing
                pending = PendingMessage(
                    direction="Server -> Client",
                    client_id=client_id,
                    data=s2c_data,
                    handler=self
                )
                self.message_queue.put(pending)
        
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
        self.message_queue: queue.Queue = queue.Queue()  # Centralized queue
        self.handlers: List[ClientHandler] = []
    
    def log(self, msg: str):
        """Print log message."""
        print(f"[ATTACKER] {msg}")
    
    def prompt_action(self, pending: PendingMessage) -> None:
        """
        Prompt attacker for action on a message and execute it.
        """
        direction = pending.direction
        data = pending.data
        client_id = pending.client_id
        handler = pending.handler
        
        summary = message_summary(data)
        queue_size = self.message_queue.qsize()
        
        print(f"\n{'='*60}")
        if queue_size > 0:
            print(f"[INTERCEPTED] {direction} ({queue_size} more in queue)")
        else:
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
                self._send_message(pending, data)
                return
            
            elif action == 'd':
                print("    -> DROPPED")
                self.message_store.add(direction, client_id, data)
                # Don't send anything
                return
            
            elif action == 'm':
                modified = modify_message(data)
                if modified != data:
                    print("    -> Forwarding MODIFIED message")
                else:
                    print("    -> Forwarding unchanged")
                self.message_store.add(direction, client_id, data)  # Store original
                self._send_message(pending, modified)
                return
            
            elif action == 'r':
                self.message_store.list_messages()
                try:
                    idx = int(input("    Replay message #: ").strip())
                    replay_data = self.message_store.get(idx)
                    if replay_data:
                        print(f"    -> REPLAYING message #{idx}")
                        print(f"       {message_summary(replay_data)}")
                        self.message_store.add(direction, client_id, data)  # Store original
                        self._send_message(pending, replay_data)
                        return
                    else:
                        print("    Invalid index")
                except ValueError:
                    print("    Invalid input")
            
            elif action == 'e':
                print("    -> REFLECTING back to sender")
                self.message_store.add(direction, client_id, data)
                self._reflect_message(pending, data)
                return
            
            else:
                print("    Invalid action. Use: f/d/m/r/e")
    
    def _send_message(self, pending: PendingMessage, data: bytes) -> bool:
        """Send message in the original direction."""
        handler = pending.handler
        
        if pending.direction == "Client -> Server":
            return handler.send_to_server(data)
        else:
            return handler.send_to_client(data)
    
    def _reflect_message(self, pending: PendingMessage, data: bytes) -> bool:
        """Reflect message back to sender."""
        handler = pending.handler
        
        if pending.direction == "Client -> Server":
            # Was going to server, reflect back to client
            return handler.send_to_client(data)
        else:
            # Was going to client, reflect back to server
            return handler.send_to_server(data)
    
    def prompt_thread_func(self):
        """Thread that processes messages from the queue one at a time."""
        while self.running:
            try:
                # Wait for a message (with timeout so we can check self.running)
                pending = self.message_queue.get(timeout=0.5)
                
                # Process this message (blocks until user responds)
                self.prompt_action(pending)
                
                self.message_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.log(f"Prompt thread error: {e}")
    
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
        
        # Start the prompt thread (single thread handles all prompts)
        prompt_thread = threading.Thread(target=self.prompt_thread_func)
        prompt_thread.daemon = True
        prompt_thread.start()
        
        while self.running:
            try:
                self.socket.settimeout(1.0)
                conn, addr = self.socket.accept()
                # self.log(f"New client connection from {addr}")
                
                handler = ClientHandler(
                    conn, addr,
                    self.config.server_host,
                    self.config.server_port,
                    self.message_queue,  # Pass the centralized queue
                    self.message_store
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