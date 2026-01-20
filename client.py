"""
client.py
Interactive Secure Client

Commands:
- send <value>  : Send data for current round
- quit          : Disconnect and exit
"""

import socket
import struct
import time
from typing import Optional, Tuple
from dataclasses import dataclass

from crypto_utils import generate_nonce, HMAC_SIZE
from protocol_fsm import (
    SessionState, Phase, Opcode, Direction,
    HEADER_SIZE, build_message, parse_message, parse_header, message_summary,
    build_client_hello_payload, build_client_data_payload, build_terminate_payload,
    parse_server_challenge_payload, parse_server_response_payload, parse_terminate_payload,
    ProtocolError
)


# ==============================================================================
# Configuration
# ==============================================================================

@dataclass  
class ClientConfig:
    server_host: str = '127.0.0.1'
    server_port: int = 7000      # Connect to attacker, not directly to server
    client_id: int = 1
    master_key: bytes = b'client_1_master_key_32_bytes_!!'
    verbose: bool = True


# ==============================================================================
# Client
# ==============================================================================

class SecureClient:
    def __init__(self, config: ClientConfig):
        self.config = config
        self.socket: Optional[socket.socket] = None
        self.state = SessionState(
            client_id=config.client_id,
            master_key=config.master_key
        )
        self.connected = False
        
        # For key evolution
        self.last_ciphertext: bytes = b''
        self.last_nonce: bytes = b''
    
    def log(self, msg: str):
        """Print log message."""
        print(f"[CLIENT-{self.config.client_id}] {msg}")
    
    def connect(self) -> bool:
        """Connect to server (through attacker)."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.config.server_host, self.config.server_port))
            self.connected = True
            self.log(f"Connected to {self.config.server_host}:{self.config.server_port}")
            return True
        except Exception as e:
            self.log(f"Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from server."""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.connected = False
        self.log("Disconnected")
    
    def send(self, data: bytes) -> bool:
        """Send data."""
        try:
            self.socket.sendall(data)
            return True
        except Exception as e:
            self.log(f"Send error: {e}")
            return False
    
    def recv(self, timeout: float = 300.0) -> Optional[bytes]:
        """Receive data."""
        try:
            self.socket.settimeout(timeout)
            
            # Read header first
            header = b''
            while len(header) < HEADER_SIZE:
                chunk = self.socket.recv(HEADER_SIZE - len(header))
                if not chunk:
                    return None
                header += chunk
            
            # Read rest
            rest = self.socket.recv(4096)
            if not rest:
                return None
            
            return header + rest
        except socket.timeout:
            self.log("Receive timeout")
            return None
        except Exception as e:
            self.log(f"Receive error: {e}")
            return None
    
    def handshake(self) -> bool:
        """Perform handshake with server."""
        self.log("\n" + "="*50)
        self.log("STARTING HANDSHAKE")
        self.log("="*50)
        
        # Build CLIENT_HELLO
        client_nonce = generate_nonce()
        timestamp = int(time.time())
        payload = build_client_hello_payload(client_nonce, timestamp)
        
        self.log(f"\n--- Sending CLIENT_HELLO ---")
        message, ciphertext, nonce = build_message(
            Opcode.CLIENT_HELLO,
            self.config.client_id,
            0,
            Direction.CLIENT_TO_SERVER,
            payload,
            self.state.c2s_enc,
            self.state.c2s_mac,
            verbose=self.config.verbose
        )
        
        # Store for key evolution
        self.last_ciphertext = ciphertext
        self.last_nonce = client_nonce
        
        if not self.send(message):
            return False
        
        self.log(f"Sent CLIENT_HELLO ({len(message)} bytes)")
        
        # Receive SERVER_CHALLENGE
        self.log(f"\n--- Waiting for SERVER_CHALLENGE ---")
        response = self.recv()
        if not response:
            self.log("No response received")
            return False
        
        self.log(f"Received: {message_summary(response)}")
        
        try:
            opcode, client_id, resp_payload, s2c_ciphertext, s2c_nonce = parse_message(
                response,
                self.state.s2c_enc,
                self.state.s2c_mac,
                expected_round=0,
                expected_direction=Direction.SERVER_TO_CLIENT,
                verbose=self.config.verbose
            )
        except ProtocolError as e:
            self.log(f"SERVER_CHALLENGE verification failed: {e}")
            return False
        
        if opcode != Opcode.SERVER_CHALLENGE:
            self.log(f"Expected SERVER_CHALLENGE, got {opcode.name}")
            return False
        
        server_nonce, challenge = parse_server_challenge_payload(resp_payload)
        self.log(f"SERVER_CHALLENGE received: nonce={server_nonce.hex()[:16]}...")
        
        # Evolve keys
        self.state.evolve_keys(
            c2s_ciphertext=self.last_ciphertext,
            c2s_nonce=self.last_nonce,
            s2c_data=challenge,
            s2c_status=struct.pack('!B', 0),
            verbose=self.config.verbose
        )
        self.state.phase = Phase.ACTIVE
        
        self.log(f"\nHandshake complete! Now in ACTIVE phase, Round {self.state.round_number}")
        return True
    
    def send_data(self, value: str) -> Optional[Tuple[float, int]]:
        """
        Send data and receive aggregate response.
        
        Returns: (total, count) or None on failure
        """
        if self.state.phase != Phase.ACTIVE:
            self.log("Not in ACTIVE phase!")
            return None
        
        current_round = self.state.round_number
        
        self.log(f"\n{'='*50}")
        self.log(f"ROUND {current_round} - SENDING DATA")
        self.log(f"{'='*50}")
        
        # Build CLIENT_DATA
        client_nonce = generate_nonce()
        payload = build_client_data_payload(client_nonce, value)
        
        self.log(f"\n--- Sending CLIENT_DATA ---")
        self.log(f"Value: {value}")
        
        message, ciphertext, nonce = build_message(
            Opcode.CLIENT_DATA,
            self.config.client_id,
            current_round,
            Direction.CLIENT_TO_SERVER,
            payload,
            self.state.c2s_enc,
            self.state.c2s_mac,
            verbose=self.config.verbose
        )
        
        # Store for key evolution
        self.last_ciphertext = ciphertext
        self.last_nonce = client_nonce
        
        if not self.send(message):
            return None
        
        self.log(f"Sent CLIENT_DATA ({len(message)} bytes)")
        
        # Receive SERVER_AGGR_RESPONSE
        self.log(f"\n--- Waiting for SERVER_AGGR_RESPONSE ---")
        response = self.recv()
        if not response:
            self.log("No response received")
            return None
        
        self.log(f"Received: {message_summary(response)}")
        
        try:
            opcode, client_id, resp_payload, s2c_ciphertext, s2c_nonce = parse_message(
                response,
                self.state.s2c_enc,
                self.state.s2c_mac,
                expected_round=current_round,
                expected_direction=Direction.SERVER_TO_CLIENT,
                verbose=self.config.verbose
            )
        except ProtocolError as e:
            self.log(f"Response verification failed: {e}")
            self.state.phase = Phase.TERMINATED
            return None
        
        if opcode == Opcode.TERMINATE:
            reason = parse_terminate_payload(resp_payload)
            self.log(f"Server TERMINATED session: {reason}")
            self.state.phase = Phase.TERMINATED
            return None
        
        if opcode != Opcode.SERVER_AGGR_RESPONSE:
            self.log(f"Expected SERVER_AGGR_RESPONSE, got {opcode.name}")
            return None
        
        # Parse aggregate
        status, aggregate_str = parse_server_response_payload(resp_payload)
        self.log(f"Aggregate received: {aggregate_str} (status={status})")
        
        try:
            parts = aggregate_str.split(',')
            total = float(parts[0])
            count = int(parts[1])
        except (ValueError, IndexError):
            total, count = 0.0, 0
        
        # Evolve keys
        self.state.evolve_keys(
            c2s_ciphertext=self.last_ciphertext,
            c2s_nonce=self.last_nonce,
            s2c_data=aggregate_str.encode(),
            s2c_status=struct.pack('!B', status),
            verbose=self.config.verbose
        )
        
        self.log(f"\nRound {current_round} complete! Now at Round {self.state.round_number}")
        
        return total, count
    
    def send_terminate(self, reason: str = "User quit"):
        """Send TERMINATE message."""
        if not self.connected:
            return
        
        try:
            payload = build_terminate_payload(reason)
            message, _, _ = build_message(
                Opcode.TERMINATE,
                self.config.client_id,
                self.state.round_number,
                Direction.CLIENT_TO_SERVER,
                payload,
                self.state.c2s_enc,
                self.state.c2s_mac,
                verbose=False
            )
            self.send(message)
            self.log(f"Sent TERMINATE: {reason}")
        except:
            pass
        
        self.state.phase = Phase.TERMINATED
    
    def run_interactive(self):
        """Run interactive session."""
        print("\n" + "="*60)
        print(f"SECURE CLIENT {self.config.client_id} - INTERACTIVE MODE")
        print("="*60)
        print("Commands:")
        print("  send <value>  - Send numeric value for this round")
        print("  quit          - Disconnect and exit")
        print()
        
        # Connect and handshake
        if not self.connect():
            return
        
        if not self.handshake():
            self.disconnect()
            return
        
        # Interactive loop
        while self.connected and self.state.phase == Phase.ACTIVE:
            try:
                prompt = f"\n[Client {self.config.client_id} | Round {self.state.round_number}] > "
                cmd = input(prompt).strip()
                
                if not cmd:
                    continue
                
                parts = cmd.split(maxsplit=1)
                command = parts[0].lower()
                
                if command == 'send':
                    if len(parts) < 2:
                        print("Usage: send <value>")
                        continue
                    
                    value = parts[1]
                    result = self.send_data(value)
                    if result:
                        total, count = result
                        print(f"\n>>> Aggregate: total={total:.2f}, count={count}")
                    else:
                        print("\n>>> Failed to send data")
                        break
                
                elif command == 'quit':
                    self.send_terminate("User quit")
                    break
                
                else:
                    print(f"Unknown command: {command}")
                    
            except KeyboardInterrupt:
                print("\nInterrupted")
                self.send_terminate("User interrupted")
                break
            except EOFError:
                break
        
        self.disconnect()


# ==============================================================================
# Main
# ==============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Secure Client')
    parser.add_argument('--host', default='127.0.0.1', help='Server/Attacker host')
    parser.add_argument('--port', type=int, default=7000, help='Server/Attacker port')
    parser.add_argument('--id', type=int, required=True, help='Client ID (1-3)')
    parser.add_argument('--quiet', action='store_true', help='Disable verbose output')
    args = parser.parse_args()
    
    # Client keys (must match server)
    client_keys = {
        1: b'client_1_master_key_32_bytes_!!',
        2: b'client_2_master_key_32_bytes_!!',
        3: b'client_3_master_key_32_bytes_!!',
    }
    
    if args.id not in client_keys:
        print(f"Invalid client ID. Valid IDs: {list(client_keys.keys())}")
        return
    
    config = ClientConfig(
        server_host=args.host,
        server_port=args.port,
        client_id=args.id,
        master_key=client_keys[args.id],
        verbose=not args.quiet
    )
    
    client = SecureClient(config)
    client.run_interactive()


if __name__ == '__main__':
    main()
