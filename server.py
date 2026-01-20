"""
server.py
Interactive Secure Server

- Waits for all clients to send data each round (with timeout)
- Computes aggregate and sends to participating clients
- Non-participating clients are TERMINATED
"""

import socket
import threading
import time
import struct
from typing import Dict, Optional, Tuple
from dataclasses import dataclass

from crypto_utils import generate_nonce, HMAC_SIZE
from protocol_fsm import (
    SessionState, Phase, Opcode, Direction,
    HEADER_SIZE, build_message, parse_message, parse_header, message_summary,
    build_server_challenge_payload, build_server_response_payload,
    build_terminate_payload,
    parse_client_hello_payload, parse_client_data_payload,
    ProtocolError, RoundMismatchError, InvalidMessageError
)


# ==============================================================================
# Configuration
# ==============================================================================

@dataclass
class ServerConfig:
    host: str = '127.0.0.1'
    port: int = 6000          # Server listens here (attacker connects to this)
    num_clients: int = 2      # Expected number of clients
    round_timeout: float = 300  # Seconds to wait for all clients
    verbose: bool = True


# ==============================================================================
# Client Session
# ==============================================================================

class ClientSession:
    """Manages one client's session on the server side."""
    
    def __init__(self, client_id: int, master_key: bytes, conn: socket.socket, 
                 addr: Tuple[str, int], verbose: bool = True):
        self.client_id = client_id
        self.conn = conn
        self.addr = addr
        self.verbose = verbose
        self.state = SessionState(client_id=client_id, master_key=master_key)
        
        # Data for current round
        self.current_round_data: Optional[float] = None
        self.current_round_ciphertext: bytes = b''
        self.current_round_nonce: bytes = b''
        
    def send(self, data: bytes) -> bool:
        """Send data to client."""
        try:
            self.conn.sendall(data)
            return True
        except Exception as e:
            print(f"[SERVER] Send error to Client {self.client_id}: {e}")
            return False
    
    def recv(self, timeout: float = None) -> Optional[bytes]:
        """Receive data from client."""
        try:
            if timeout:
                self.conn.settimeout(timeout)
            
            # Read header first
            header = b''
            while len(header) < HEADER_SIZE:
                chunk = self.conn.recv(HEADER_SIZE - len(header))
                if not chunk:
                    return None
                header += chunk
            
            # Read rest
            rest = self.conn.recv(4096)
            if not rest:
                return None
            
            return header + rest
        except socket.timeout:
            return None
        except Exception as e:
            print(f"[SERVER] Recv error from Client {self.client_id}: {e}")
            return None
    
    def close(self):
        """Close connection."""
        try:
            self.conn.close()
        except:
            pass


# ==============================================================================
# Server
# ==============================================================================

class SecureServer:
    def __init__(self, config: ServerConfig, client_keys: Dict[int, bytes]):
        """
        Initialize server.
        
        client_keys: Dict mapping client_id -> master_key
        """
        self.config = config
        self.client_keys = client_keys
        self.sessions: Dict[int, ClientSession] = {}
        self.socket: Optional[socket.socket] = None
        self.running = False
        self.lock = threading.Lock()
        
    def log(self, msg: str):
        """Print log message."""
        print(f"[SERVER] {msg}")
    
    def start(self):
        """Start the server."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.config.host, self.config.port))
        self.socket.listen(self.config.num_clients)
        self.running = True
        
        self.log(f"Server started on {self.config.host}:{self.config.port}")
        self.log(f"Expecting {self.config.num_clients} clients")
        self.log(f"Round timeout: {self.config.round_timeout}s")
        
        # Wait for all clients to connect
        self.log(f"\nWaiting for {self.config.num_clients} clients to connect...")
        
        while len(self.sessions) < self.config.num_clients and self.running:
            try:
                self.socket.settimeout(1.0)
                conn, addr = self.socket.accept()
                self.log(f"New connection from {addr}")
                
                # Handle handshake in separate thread
                thread = threading.Thread(target=self._handle_new_connection, args=(conn, addr))
                thread.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.log(f"Accept error: {e}")
        
        if len(self.sessions) == self.config.num_clients:
            self.log(f"\nAll {self.config.num_clients} clients connected!")
            self._run_rounds()
        
        self.stop()
    
    def _handle_new_connection(self, conn: socket.socket, addr: Tuple[str, int]):
        """Handle a new connection - perform handshake."""
        try:
            conn.settimeout(10.0)
            
            # Receive CLIENT_HELLO
            data = b''
            while len(data) < HEADER_SIZE:
                chunk = conn.recv(HEADER_SIZE - len(data))
                if not chunk:
                    self.log(f"Connection closed during handshake from {addr}")
                    conn.close()
                    return
                data += chunk
            
            rest = conn.recv(4096)
            data += rest
            
            # Parse header to get client ID
            opcode, client_id, round_num, direction, iv = parse_header(data)
            
            if opcode != Opcode.CLIENT_HELLO:
                self.log(f"Expected CLIENT_HELLO, got {opcode.name}")
                conn.close()
                return
            
            # Check if client is registered
            if client_id not in self.client_keys:
                self.log(f"Unknown client ID: {client_id}")
                conn.close()
                return
            
            # Check if already connected
            with self.lock:
                if client_id in self.sessions:
                    self.log(f"Client {client_id} already connected!")
                    conn.close()
                    return
            
            # Create session
            master_key = self.client_keys[client_id]
            session = ClientSession(client_id, master_key, conn, addr, self.config.verbose)
            
            # Parse and verify CLIENT_HELLO
            self.log(f"\n--- Received from Client {client_id} ---")
            self.log(f"Message: {message_summary(data)}")
            
            try:
                opcode, cid, payload, ciphertext, nonce = parse_message(
                    data,
                    session.state.c2s_enc,
                    session.state.c2s_mac,
                    expected_round=0,
                    expected_direction=Direction.CLIENT_TO_SERVER,
                    verbose=self.config.verbose
                )
            except ProtocolError as e:
                self.log(f"CLIENT_HELLO verification failed: {e}")
                conn.close()
                return
            
            client_nonce, timestamp = parse_client_hello_payload(payload)
            self.log(f"CLIENT_HELLO: nonce={client_nonce.hex()[:16]}..., timestamp={timestamp}")
            
            # Build SERVER_CHALLENGE
            server_nonce = generate_nonce()
            challenge = generate_nonce(32)
            challenge_payload = build_server_challenge_payload(server_nonce, challenge)
            
            self.log(f"\n--- Sending to Client {client_id} ---")
            response, s2c_ciphertext, s2c_nonce = build_message(
                Opcode.SERVER_CHALLENGE,
                client_id,
                0,
                Direction.SERVER_TO_CLIENT,
                challenge_payload,
                session.state.s2c_enc,
                session.state.s2c_mac,
                verbose=self.config.verbose
            )
            
            if not session.send(response):
                conn.close()
                return
            
            self.log(f"Sent SERVER_CHALLENGE to Client {client_id}")
            
            # Evolve keys
            session.state.evolve_keys(
                c2s_ciphertext=ciphertext,
                c2s_nonce=client_nonce,
                s2c_data=challenge,
                s2c_status=struct.pack('!B', 0),
                verbose=self.config.verbose
            )
            session.state.phase = Phase.ACTIVE
            
            # Add to sessions
            with self.lock:
                self.sessions[client_id] = session
            
            self.log(f"Client {client_id} handshake complete, now in ACTIVE phase, Round {session.state.round_number}")
            
        except Exception as e:
            self.log(f"Handshake error: {e}")
            try:
                conn.close()
            except:
                pass
    
    def _run_rounds(self):
        """Run the main round loop."""
        self.log("\n" + "="*60)
        self.log("ENTERING ROUND LOOP")
        self.log("="*60)
        
        while self.running and len(self.sessions) > 0:
            current_round = list(self.sessions.values())[0].state.round_number
            self.log(f"\n{'='*60}")
            self.log(f"ROUND {current_round}")
            self.log(f"{'='*60}")
            self.log(f"Active clients: {list(self.sessions.keys())}")
            self.log(f"Waiting for CLIENT_DATA (timeout: {self.config.round_timeout}s)...")
            
            # Reset round data
            for session in self.sessions.values():
                session.current_round_data = None
            
            # Wait for data from all clients
            received_from = self._wait_for_client_data(current_round)
            
            if not received_from:
                self.log("No clients sent data. Ending rounds.")
                break
            
            # Terminate clients who didn't send
            to_terminate = [cid for cid in list(self.sessions.keys()) if cid not in received_from]
            for cid in to_terminate:
                self.log(f"Client {cid} did not send data - TERMINATING")
                self._terminate_client(cid, "Timeout - did not send data")
            
            if not self.sessions:
                self.log("No clients remaining.")
                break
            
            # Compute aggregate
            values = [s.current_round_data for s in self.sessions.values() if s.current_round_data is not None]
            if values:
                total = sum(values)
                count = len(values)
                aggregate = f"{total:.2f},{count}"
            else:
                aggregate = "0.00,0"
            
            self.log(f"\nAggregate computed: {aggregate}")
            
            # Send aggregate to all participating clients
            self._send_aggregate_to_all(aggregate, current_round)
            
            self.log(f"\nRound {current_round} complete. Clients now at Round {current_round + 1}")
            
            # Check if any clients remain
            if not self.sessions:
                self.log("No clients remaining after round.")
                break
    
    def _wait_for_client_data(self, expected_round: int) -> set:
        """Wait for CLIENT_DATA from all clients. Returns set of client IDs who sent."""
        received_from = set()
        start_time = time.time()
        
        # Use threads to receive from all clients simultaneously
        threads = []
        for client_id, session in list(self.sessions.items()):
            t = threading.Thread(target=self._receive_client_data, 
                               args=(session, expected_round, received_from))
            t.start()
            threads.append(t)
        
        # Wait for threads with timeout
        for t in threads:
            remaining = self.config.round_timeout - (time.time() - start_time)
            if remaining > 0:
                t.join(timeout=remaining)
        
        return received_from
    
    def _receive_client_data(self, session: ClientSession, expected_round: int, received_from: set):
        """Receive CLIENT_DATA from one client."""
        client_id = session.client_id
        
        data = session.recv(timeout=self.config.round_timeout)
        if not data:
            self.log(f"Client {client_id}: No data received (timeout or disconnect)")
            return
        
        self.log(f"\n--- Received from Client {client_id} ---")
        self.log(f"Message: {message_summary(data)}")
        
        try:
            opcode, cid, payload, ciphertext, nonce = parse_message(
                data,
                session.state.c2s_enc,
                session.state.c2s_mac,
                expected_round=expected_round,
                expected_direction=Direction.CLIENT_TO_SERVER,
                verbose=self.config.verbose
            )
            
            if opcode == Opcode.TERMINATE:
                self.log(f"Client {client_id} sent TERMINATE")
                with self.lock:
                    self._terminate_client(client_id, "Client requested")
                return
            
            if opcode != Opcode.CLIENT_DATA:
                self.log(f"Client {client_id}: Expected CLIENT_DATA, got {opcode.name}")
                self._terminate_client(client_id, f"Invalid opcode: {opcode.name}")
                return
            
            # Parse data
            client_nonce, data_str = parse_client_data_payload(payload)
            try:
                value = float(data_str)
            except ValueError:
                self.log(f"Client {client_id}: Invalid data format: {data_str}")
                value = 0.0
            
            self.log(f"Client {client_id} sent value: {value}")
            
            # Store for round completion
            session.current_round_data = value
            session.current_round_ciphertext = ciphertext
            session.current_round_nonce = client_nonce
            
            with self.lock:
                received_from.add(client_id)
                
        except ProtocolError as e:
            self.log(f"Client {client_id}: Protocol error - {e}")
            self._terminate_client(client_id, str(e))
    
    def _send_aggregate_to_all(self, aggregate: str, round_num: int):
        """Send aggregate response to all remaining clients."""
        status = 0  # Success
        
        for client_id, session in list(self.sessions.items()):
            self.log(f"\n--- Sending to Client {client_id} ---")
            
            payload = build_server_response_payload(status, aggregate)
            
            try:
                message, ciphertext, nonce = build_message(
                    Opcode.SERVER_AGGR_RESPONSE,
                    client_id,
                    round_num,
                    Direction.SERVER_TO_CLIENT,
                    payload,
                    session.state.s2c_enc,
                    session.state.s2c_mac,
                    verbose=self.config.verbose
                )
                
                if not session.send(message):
                    self._terminate_client(client_id, "Send failed")
                    continue
                
                self.log(f"Sent aggregate to Client {client_id}")
                
                # Evolve keys
                session.state.evolve_keys(
                    c2s_ciphertext=session.current_round_ciphertext,
                    c2s_nonce=session.current_round_nonce,
                    s2c_data=aggregate.encode(),
                    s2c_status=struct.pack('!B', status),
                    verbose=self.config.verbose
                )
                
            except Exception as e:
                self.log(f"Error sending to Client {client_id}: {e}")
                self._terminate_client(client_id, str(e))
    
    def _terminate_client(self, client_id: int, reason: str):
        """Terminate a client session."""
        with self.lock:
            if client_id not in self.sessions:
                return
            
            session = self.sessions[client_id]
            
            # Try to send TERMINATE message
            try:
                payload = build_terminate_payload(reason)
                message, _, _ = build_message(
                    Opcode.TERMINATE,
                    client_id,
                    session.state.round_number,
                    Direction.SERVER_TO_CLIENT,
                    payload,
                    session.state.s2c_enc,
                    session.state.s2c_mac,
                    verbose=False
                )
                session.send(message)
            except:
                pass
            
            session.close()
            del self.sessions[client_id]
            self.log(f"Client {client_id} TERMINATED: {reason}")
    
    def stop(self):
        """Stop the server."""
        self.running = False
        
        # Close all sessions
        with self.lock:
            for session in self.sessions.values():
                session.close()
            self.sessions.clear()
        
        # Close server socket
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        self.log("Server stopped")


# ==============================================================================
# Main
# ==============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Secure Server')
    parser.add_argument('--host', default='127.0.0.1', help='Server host')
    parser.add_argument('--port', type=int, default=6000, help='Server port')
    parser.add_argument('--clients', type=int, default=2, help='Number of expected clients')
    parser.add_argument('--timeout', type=float, default=300.0, help='Round timeout in seconds')
    parser.add_argument('--quiet', action='store_true', help='Disable verbose output')
    args = parser.parse_args()
    
    config = ServerConfig(
        host=args.host,
        port=args.port,
        num_clients=args.clients,
        round_timeout=args.timeout,
        verbose=not args.quiet
    )
    
    # Define client keys (in real system, loaded securely)
    client_keys = {
        1: b'client_1_master_key_32_bytes_!!',
        2: b'client_2_master_key_32_bytes_!!',
        3: b'client_3_master_key_32_bytes_!!',
    }
    
    print("="*60)
    print("SECURE SERVER")
    print("="*60)
    print(f"Registered clients: {list(client_keys.keys())}")
    print()
    
    server = SecureServer(config, client_keys)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nInterrupted")
        server.stop()


if __name__ == '__main__':
    main()
