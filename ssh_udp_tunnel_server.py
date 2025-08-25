#!/usr/bin/env python3
"""
SSH + UDP Tunnel Server
Supports SSH authentication and UDP forwarding for ports 1-65535
"""

import socket
import threading
import time
import logging
import struct
import os
import hashlib
import hmac
from typing import Dict, Tuple, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SSHUDPServer:
    def __init__(self, ssh_port: int = 22, udp_port: int = 4433, 
                 encryption_key: str = "quicvpn2024secretkey32byteslong!"):
        self.ssh_port = ssh_port
        self.udp_port = udp_port
        self.encryption_key = encryption_key.encode('utf-8')
        
        # SSH authentication
        self.users = {
            "vpnuser": "vpnpass123",  # Change these credentials
            "admin": "adminpass456"   # Add more users as needed
        }
        
        # Active connections
        self.connections: Dict[int, Dict] = {}
        self.ssh_sessions: Dict[str, Dict] = {}
        
        # Server sockets
        self.ssh_socket = None
        self.udp_socket = None
        self.raw_socket = None
        
        # Server state
        self.is_running = False
        
        # Statistics
        self.stats = {
            'packets_forwarded': 0,
            'bytes_forwarded': 0,
            'active_connections': 0
        }
    
    def start(self):
        """Start the SSH + UDP tunnel server"""
        try:
            logger.info("Starting SSH + UDP Tunnel Server...")
            
            # Setup raw socket for internet forwarding
            self._setup_raw_socket()
            
            # Start SSH server
            self._start_ssh_server()
            
            # Start UDP tunnel server
            self._start_udp_server()
            
            self.is_running = True
            logger.info(f"SSH + UDP Tunnel Server started on SSH:{self.ssh_port}, UDP:{self.udp_port}")
            
            # Main server loop
            while self.is_running:
                time.sleep(1)
                self._cleanup_connections()
                
        except KeyboardInterrupt:
            logger.info("Shutting down server...")
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the server"""
        self.is_running = False
        
        if self.ssh_socket:
            self.ssh_socket.close()
        if self.udp_socket:
            self.udp_socket.close()
        if self.raw_socket:
            self.raw_socket.close()
        
        logger.info("SSH + UDP Tunnel Server stopped")
    
    def _setup_raw_socket(self):
        """Setup raw socket for internet forwarding"""
        try:
            # Create raw socket for IP packet forwarding
            self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            logger.info("Raw socket created for internet forwarding")
        except PermissionError:
            logger.warning("Raw socket requires sudo/root privileges")
            self.raw_socket = None
        except Exception as e:
            logger.error(f"Failed to create raw socket: {e}")
            self.raw_socket = None
    
    def _start_ssh_server(self):
        """Start SSH server for authentication"""
        try:
            self.ssh_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.ssh_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.ssh_socket.bind(('0.0.0.0', self.ssh_port))
            self.ssh_socket.listen(5)
            
            # Start SSH listener thread
            ssh_thread = threading.Thread(target=self._ssh_listener, daemon=True)
            ssh_thread.start()
            
            logger.info(f"SSH server listening on port {self.ssh_port}")
            
        except Exception as e:
            logger.error(f"Failed to start SSH server: {e}")
    
    def _start_udp_server(self):
        """Start UDP tunnel server"""
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.bind(('0.0.0.0', self.udp_port))
            
            # Start UDP listener thread
            udp_thread = threading.Thread(target=self._udp_listener, daemon=True)
            udp_thread.start()
            
            logger.info(f"UDP tunnel server listening on port {self.udp_port}")
            
        except Exception as e:
            logger.error(f"Failed to start UDP server: {e}")
    
    def _ssh_listener(self):
        """SSH connection listener"""
        while self.is_running:
            try:
                client_socket, addr = self.ssh_socket.accept()
                logger.info(f"SSH connection from {addr}")
                
                # Handle SSH connection in separate thread
                ssh_handler = threading.Thread(
                    target=self._handle_ssh_connection, 
                    args=(client_socket, addr), 
                    daemon=True
                )
                ssh_handler.start()
                
            except Exception as e:
                if self.is_running:
                    logger.error(f"SSH accept error: {e}")
    
    def _udp_listener(self):
        """UDP packet listener"""
        while self.is_running:
            try:
                data, addr = self.udp_socket.recvfrom(4096)
                if data:
                    # Handle UDP packet in separate thread
                    udp_handler = threading.Thread(
                        target=self._handle_udp_packet, 
                        args=(data, addr), 
                        daemon=True
                    )
                    udp_handler.start()
                    
            except Exception as e:
                if self.is_running:
                    logger.error(f"UDP receive error: {e}")
    
    def _handle_ssh_connection(self, client_socket: socket.socket, addr: Tuple[str, int]):
        """Handle SSH connection and authentication"""
        try:
            # Simple SSH-like handshake
            # In production, use proper SSH library like paramiko
            
            # Send SSH banner
            banner = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
            client_socket.send(banner)
            
            # Receive client version
            client_version = client_socket.recv(1024)
            logger.debug(f"Client version: {client_version}")
            
            # Simple authentication (username/password)
            auth_success = self._authenticate_ssh(client_socket)
            
            if auth_success:
                logger.info(f"SSH authentication successful for {addr}")
                self._handle_authenticated_ssh(client_socket, addr)
            else:
                logger.warning(f"SSH authentication failed for {addr}")
                client_socket.close()
                
        except Exception as e:
            logger.error(f"SSH connection error: {e}")
            client_socket.close()
    
    def _authenticate_ssh(self, client_socket: socket.socket) -> bool:
        """Simple SSH authentication"""
        try:
            # Send authentication request
            auth_request = b"Password: "
            client_socket.send(auth_request)
            
            # Receive username
            username = client_socket.recv(1024).decode('utf-8').strip()
            
            # Send password prompt
            password_prompt = b"Password: "
            client_socket.send(password_prompt)
            
            # Receive password
            password = client_socket.recv(1024).decode('utf-8').strip()
            
            # Check credentials
            if username in self.users and self.users[username] == password:
                # Store authenticated session
                session_id = hashlib.md5(f"{username}_{time.time()}".encode()).hexdigest()
                self.ssh_sessions[session_id] = {
                    'username': username,
                    'addr': client_socket.getpeername(),
                    'authenticated_at': time.time(),
                    'last_activity': time.time()
                }
                
                # Send success message
                success_msg = b"Authentication successful!\r\n"
                client_socket.send(success_msg)
                return True
            else:
                # Send failure message
                failure_msg = b"Authentication failed!\r\n"
                client_socket.send(failure_msg)
                return False
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    def _handle_authenticated_ssh(self, client_socket: socket.socket, addr: Tuple[str, int]):
        """Handle authenticated SSH connection"""
        try:
            # Send welcome message
            welcome = b"Welcome to SSH + UDP Tunnel Server!\r\n"
            welcome += b"UDP tunnel is now active on port " + str(self.udp_port).encode() + b"\r\n"
            welcome += b"Press Ctrl+C to disconnect\r\n\r\n"
            client_socket.send(welcome)
            
            # Keep connection alive
            while self.is_running:
                try:
                    # Send heartbeat
                    heartbeat = b"."
                    client_socket.send(heartbeat)
                    time.sleep(30)  # Heartbeat every 30 seconds
                    
                except Exception:
                    break
                    
        except Exception as e:
            logger.error(f"Authenticated SSH error: {e}")
        finally:
            client_socket.close()
    
    def _handle_udp_packet(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming UDP tunnel packet"""
        try:
            # Decrypt packet
            decrypted_packet = self._decrypt_packet(data)
            if not decrypted_packet:
                logger.warning(f"Failed to decrypt packet from {addr}")
                return
            
            if len(decrypted_packet) < 24:
                logger.warning(f"Decrypted packet too short: {len(decrypted_packet)} bytes")
                return
            
            # Parse packet header
            connection_id = struct.unpack('!Q', decrypted_packet[0:8])[0]
            packet_number = struct.unpack('!Q', decrypted_packet[8:16])[0]
            port_range = struct.unpack('!H', decrypted_packet[16:18])[0]  # Port range identifier
            payload = decrypted_packet[18:]
            
            # Check if this is a new connection
            if connection_id not in self.connections:
                self.connections[connection_id] = {
                    'addr': addr,
                    'created': time.time(),
                    'packet_count': 0,
                    'port_range': port_range,
                    'last_activity': time.time()
                }
                logger.info(f"New UDP tunnel connection {connection_id} from {addr} (port range: {port_range})")
                self.stats['active_connections'] += 1
            
            self.connections[connection_id]['packet_count'] += 1
            self.connections[connection_id]['last_activity'] = time.time()
            
            # Process based on payload type
            if payload.startswith(b'SSH_UDP_INIT'):
                logger.info(f"SSH UDP connection {connection_id} initialized")
                response = self._create_initial_response(connection_id, packet_number)
                self._send_response(response, addr)
            
            elif payload.startswith(b'SSH_UDP_DISC'):
                logger.info(f"SSH UDP connection {connection_id} disconnecting")
                if connection_id in self.connections:
                    del self.connections[connection_id]
                    self.stats['active_connections'] -= 1
                response = self._create_disconnect_response(connection_id, packet_number)
                self._send_response(response, addr)
            
            elif payload.startswith(b'PING'):
                logger.debug(f"Ping packet from {connection_id}")
                response = self._create_ping_response(connection_id, packet_number)
                self._send_response(response, addr)
            
            else:
                # Regular data packet - forward to internet
                logger.debug(f"Data packet from {connection_id}: {len(payload)} bytes")
                self._process_data_packet(connection_id, packet_number, payload, addr)
                
        except Exception as e:
            logger.error(f"Error handling UDP packet from {addr}: {e}")
    
    def _process_data_packet(self, connection_id: int, packet_number: int, data: bytes, addr: Tuple[str, int]):
        """Process data packet and forward to internet"""
        try:
            # This is the actual IP packet that needs to be forwarded to the internet
            if len(data) < 20:  # Minimum IP header size
                logger.warning(f"Data packet too short: {len(data)} bytes")
                return
            
            # Extract destination IP from IP header (bytes 16-19)
            dest_ip = f"{data[16]}.{data[17]}.{data[18]}.{data[19]}"
            
            # Check if destination port is in allowed range
            if len(data) > 22:
                dest_port = struct.unpack('!H', data[20:22])[0]
                if dest_port < 1 or dest_port > 65535:
                    logger.warning(f"Port {dest_port} out of range 1-65535")
                    return
            
            logger.info(f"Forwarding {len(data)} bytes to {dest_ip}")
            self.stats['packets_forwarded'] += 1
            self.stats['bytes_forwarded'] += len(data)
            
            # Forward packet to internet using raw socket
            if self.raw_socket:
                try:
                    # Send the IP packet to the destination
                    self.raw_socket.sendto(data, (dest_ip, 0))
                    logger.debug(f"Packet sent to {dest_ip}")
                    
                    # Create response to simulate internet traffic
                    mock_response = self._create_mock_response(data, dest_ip)
                    if mock_response:
                        response = self._create_data_response(connection_id, packet_number, mock_response)
                        self._send_response(response, addr)
                        logger.info(f"Sent response for {dest_ip} back to client")
                    
                except Exception as e:
                    logger.error(f"Failed to forward packet to {dest_ip}: {e}")
                    # Send error response
                    error_response = self._create_data_response(connection_id, packet_number, b"FORWARD_ERROR")
                    self._send_response(error_response, addr)
            else:
                # No raw socket - just echo back for testing
                logger.warning("No raw socket available - echoing back for testing")
                response = self._create_data_response(connection_id, packet_number, data)
                self._send_response(response, addr)
            
            logger.debug(f"Data packet {packet_number} from {connection_id} processed for {dest_ip}")
            
        except Exception as e:
            logger.error(f"Error processing data packet: {e}")
    
    def _create_mock_response(self, original_packet: bytes, dest_ip: str) -> bytes:
        """Create a mock response packet to simulate internet traffic"""
        try:
            if len(original_packet) < 20:
                return b""
            
            # Create a simple mock response
            # This simulates what an internet server would send back
            
            # For DNS queries (port 53), create a mock DNS response
            if len(original_packet) > 28:
                # Check if this looks like a DNS query (UDP port 53)
                if len(original_packet) > 40 and original_packet[20:22] == b'\x00\x35':  # Port 53
                    # Create a mock DNS response
                    mock_dns = b'\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'  # DNS header
                    mock_dns += b'\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00'  # example.com
                    mock_dns += b'\x00\x01\x00\x01'  # Type A, Class IN
                    mock_dns += b'\xc0\x0c'  # Name pointer
                    mock_dns += b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'  # TTL + data length
                    mock_dns += b'\x08\x08\x08\x08'  # IP: 8.8.8.8
                    return mock_dns
            
            # For other packets, create a simple acknowledgment
            mock_response = f"SSH_UDP_RESPONSE_FROM_{dest_ip}".encode()
            return mock_response
            
        except Exception as e:
            logger.error(f"Error creating mock response: {e}")
            return b""
    
    def _create_initial_response(self, connection_id: int, packet_number: int) -> bytes:
        """Create initial response packet"""
        buffer = struct.pack('!QQH', connection_id, packet_number + 1, 0)  # 0 = port range
        response_data = b'SSH_UDP_ACK'
        buffer += response_data
        buffer += b'\x00' * (32 - len(response_data))  # Pad to 32 bytes
        
        # Encrypt response
        encrypted_response = self._encrypt_packet(buffer)
        return encrypted_response
    
    def _create_disconnect_response(self, connection_id: int, packet_number: int) -> bytes:
        """Create disconnect response packet"""
        buffer = struct.pack('!QQH', connection_id, packet_number + 1, 0)
        response_data = b'SSH_UDP_DISC_ACK'
        buffer += response_data
        buffer += b'\x00' * (16 - len(response_data))  # Pad to 16 bytes
        
        # Encrypt response
        encrypted_response = self._encrypt_packet(buffer)
        return encrypted_response

    def _create_ping_response(self, connection_id: int, packet_number: int) -> bytes:
        """Create ping response packet"""
        buffer = struct.pack('!QQH', connection_id, packet_number + 1, 0)
        response_data = b'PONG'
        buffer += response_data
        buffer += b'\x00' * (8 - len(response_data))  # Pad to 8 bytes
        
        # Encrypt response
        encrypted_response = self._encrypt_packet(buffer)
        return encrypted_response
    
    def _create_data_response(self, connection_id: int, packet_number: int, data: bytes) -> bytes:
        """Create data response packet"""
        buffer = struct.pack('!QQH', connection_id, packet_number + 1, 0)
        buffer += data
        
        # Encrypt response
        encrypted_response = self._encrypt_packet(buffer)
        return encrypted_response
    
    def _send_response(self, response: bytes, addr: Tuple[str, int]):
        """Send encrypted response to client"""
        try:
            self.udp_socket.sendto(response, addr)
        except Exception as e:
            logger.error(f"Failed to send response to {addr}: {e}")
    
    def _encrypt_packet(self, packet: bytes) -> bytes:
        """Encrypt packet using AES"""
        try:
            # Generate IV
            iv = os.urandom(16)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Add padding
            padding_length = 16 - (len(packet) % 16)
            padded_packet = packet + bytes([padding_length] * padding_length)
            
            # Encrypt
            encrypted = encryptor.update(padded_packet) + encryptor.finalize()
            
            # Return IV + encrypted data
            return iv + encrypted
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return packet
    
    def _decrypt_packet(self, encrypted_data: bytes) -> Optional[bytes]:
        """Decrypt packet using AES"""
        try:
            if len(encrypted_data) < 32:
                return encrypted_data
            
            # Extract IV and encrypted data
            iv = encrypted_data[:16]
            encrypted = encrypted_data[16:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt
            decrypted = decryptor.update(encrypted) + decryptor.finalize()
            
            # Remove padding
            padding_length = decrypted[-1]
            if padding_length < 16:
                decrypted = decrypted[:-padding_length]
            
            return decrypted
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None
    
    def _cleanup_connections(self):
        """Clean up inactive connections"""
        current_time = time.time()
        inactive_connections = []
        
        for conn_id, conn_data in self.connections.items():
            if current_time - conn_data['last_activity'] > 300:  # 5 minutes timeout
                inactive_connections.append(conn_id)
        
        for conn_id in inactive_connections:
            logger.info(f"Cleaning up inactive connection {conn_id}")
            del self.connections[conn_id]
            self.stats['active_connections'] -= 1
        
        # Clean up old SSH sessions
        old_sessions = []
        for session_id, session_data in self.ssh_sessions.items():
            if current_time - session_data['last_activity'] > 3600:  # 1 hour timeout
                old_sessions.append(session_id)
        
        for session_id in old_sessions:
            del self.ssh_sessions[session_id]
    
    def get_stats(self) -> Dict:
        """Get server statistics"""
        return {
            **self.stats,
            'total_connections': len(self.connections),
            'ssh_sessions': len(self.ssh_sessions),
            'uptime': time.time() - getattr(self, '_start_time', time.time())
        }

def main():
    """Main function"""
    print("SSH + UDP Tunnel Server")
    print("=" * 40)
    
    # Server configuration
    ssh_port = int(os.environ.get('SSH_PORT', '22'))
    udp_port = int(os.environ.get('UDP_PORT', '4433'))
    encryption_key = os.environ.get('ENCRYPTION_KEY', 'quicvpn2024secretkey32byteslong!')
    
    print(f"SSH Port: {ssh_port}")
    print(f"UDP Port: {udp_port}")
    print(f"Encryption: AES-256-CBC")
    print(f"Port Range: 1-65535")
    print("=" * 40)
    
    # Create and start server
    server = SSHUDPServer(ssh_port, udp_port, encryption_key)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.stop()

if __name__ == "__main__":
    main()
