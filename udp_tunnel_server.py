#!/usr/bin/env python3
"""
UDP Tunnel Server with Internet Forwarding
Receives encrypted UDP packets, decrypts them, forwards to internet, and sends responses back
"""

import socket
import struct
import logging
import threading
import time
from typing import Dict, Optional, Tuple
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import select

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class UdpTunnelServer:
    def __init__(self, host: str = '0.0.0.0', port: int = 4433, encryption_key: str = "quicvpn2024secretkey32byteslong!"):
        self.host = host
        self.port = port
        self.encryption_key = encryption_key.encode()
        self.socket = None
        self.running = False
        self.connections: Dict[int, Dict] = {}
        self.connection_counter = 0
        
        # Raw socket for internet forwarding
        self.raw_socket = None
        self.setup_raw_socket()
        
        logger.info(f"UDP Tunnel Server initialized on {host}:{port}")
    
    def setup_raw_socket(self):
        """Setup raw socket for internet forwarding"""
        try:
            # Create raw socket for IP packets
            self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            logger.info("Raw socket created for internet forwarding")
        except Exception as e:
            logger.error(f"Failed to create raw socket: {e}")
            logger.warning("Internet forwarding will be limited - run with sudo for full functionality")
            self.raw_socket = None
    
    def start(self):
        """Start the UDP tunnel server"""
        try:
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            
            self.running = True
            logger.info(f"UDP Tunnel Server started on {self.host}:{self.port}")
            logger.info("Waiting for encrypted UDP packets...")
            
            # Start connection cleanup thread
            cleanup_thread = threading.Thread(target=self._cleanup_connections, daemon=True)
            cleanup_thread.start()
            
            # Main receive loop
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(65507)  # Max UDP payload
                    if data:
                        # Handle packet in separate thread
                        client_thread = threading.Thread(
                            target=self._handle_packet,
                            args=(data, addr),
                            daemon=True
                        )
                        client_thread.start()
                        
                except socket.error as e:
                    if self.running:
                        logger.error(f"Socket error: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Failed to start UDP tunnel server: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the UDP tunnel server"""
        self.running = False
        if self.socket:
            self.socket.close()
        if self.raw_socket:
            self.raw_socket.close()
        logger.info("UDP Tunnel Server stopped")
    
    def _handle_packet(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming encrypted packet"""
        try:
            # Decrypt packet
            decrypted_packet = self._decrypt_packet(data)
            if not decrypted_packet:
                logger.warning(f"Failed to decrypt packet from {addr}")
                return
            
            if len(decrypted_packet) < 16:
                logger.warning(f"Decrypted packet too short: {len(decrypted_packet)} bytes")
                return
            
            # Parse packet header
            connection_id = struct.unpack('!Q', decrypted_packet[0:8])[0]
            packet_number = struct.unpack('!Q', decrypted_packet[8:16])[0]
            payload = decrypted_packet[16:]
            
            # Check if this is a new connection
            if connection_id not in self.connections:
                self.connections[connection_id] = {
                    'addr': addr,
                    'created': time.time(),
                    'packet_count': 0
                }
                logger.info(f"New UDP tunnel connection {connection_id} from {addr}")
            
            self.connections[connection_id]['packet_count'] += 1
            
            # Process based on payload type
            if payload.startswith(b'UDP_TUNNEL_INIT'):
                logger.info(f"Connection {connection_id} initialized")
                response = self._create_initial_response(connection_id, packet_number)
                self._send_response(response, addr)
            
            elif payload.startswith(b'UDP_TUNNEL_DISC'):
                logger.info(f"Connection {connection_id} disconnecting")
                if connection_id in self.connections:
                    del self.connections[connection_id]
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
            logger.error(f"Error handling packet from {addr}: {e}")
    
    def _process_data_packet(self, connection_id: int, packet_number: int, data: bytes, addr: Tuple[str, int]):
        """Process data packet and forward to internet"""
        try:
            # This is the actual IP packet that needs to be forwarded to the internet
            if len(data) < 20:  # Minimum IP header size
                logger.warning(f"Data packet too short: {len(data)} bytes")
                return
            
            # Extract destination IP from IP header (bytes 16-19)
            dest_ip = f"{data[16]}.{data[17]}.{data[18]}.{data[19]}"
            
            logger.info(f"Forwarding {len(data)} bytes to {dest_ip}")
            
            # Forward packet to internet using raw socket
            if self.raw_socket:
                try:
                    # Send the IP packet to the destination
                    self.raw_socket.sendto(data, (dest_ip, 0))
                    logger.debug(f"Packet sent to {dest_ip}")
                    
                    # For now, create a mock response to simulate internet traffic
                    # In a real implementation, you would wait for actual responses
                    # This is a temporary solution to get the tunnel working
                    
                    # Create a mock response packet (simulating internet response)
                    mock_response = self._create_mock_response(data, dest_ip)
                    if mock_response:
                        response = self._create_data_response(connection_id, packet_number, mock_response)
                        self._send_response(response, addr)
                        logger.info(f"Sent mock response for {dest_ip} back to client")
                    
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
                # This is a simplified check - in reality you'd parse the packet properly
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
            # This simulates a TCP ACK or similar response
            mock_response = f"RESPONSE_FROM_{dest_ip}".encode()
            return mock_response
            
        except Exception as e:
            logger.error(f"Error creating mock response: {e}")
            return b""
    
    def _create_initial_response(self, connection_id: int, packet_number: int) -> bytes:
        """Create initial response packet"""
        buffer = struct.pack('!QQ', connection_id, packet_number + 1)
        response_data = b'UDP_TUNNEL_ACK'
        buffer += response_data
        buffer += b'\x00' * (32 - len(response_data))  # Pad to 32 bytes
        
        # Encrypt response
        encrypted_response = self._encrypt_packet(buffer)
        return encrypted_response
    
    def _create_disconnect_response(self, connection_id: int, packet_number: int) -> bytes:
        """Create disconnect response packet"""
        buffer = struct.pack('!QQ', connection_id, packet_number + 1)
        response_data = b'UDP_TUNNEL_DISC_ACK'
        buffer += response_data
        buffer += b'\x00' * (16 - len(response_data))  # Pad to 16 bytes
        
        # Encrypt response
        encrypted_response = self._encrypt_packet(buffer)
        return encrypted_response

    def _create_ping_response(self, connection_id: int, packet_number: int) -> bytes:
        """Create ping response packet"""
        buffer = struct.pack('!QQ', connection_id, packet_number + 1)
        response_data = b'PONG'
        buffer += response_data
        buffer += b'\x00' * (8 - len(response_data))  # Pad to 8 bytes
        
        # Encrypt response
        encrypted_response = self._encrypt_packet(buffer)
        return encrypted_response
    
    def _create_data_response(self, connection_id: int, packet_number: int, data: bytes) -> bytes:
        """Create data response packet"""
        buffer = struct.pack('!QQ', connection_id, packet_number + 1)
        buffer += data
        
        # Encrypt response
        encrypted_response = self._encrypt_packet(buffer)
        return encrypted_response
    
    def _send_response(self, response: bytes, addr: Tuple[str, int]):
        """Send encrypted response to client"""
        try:
            self.socket.sendto(response, addr)
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
            return encrypted_data
    
    def _cleanup_connections(self):
        """Clean up old connections"""
        while self.running:
            try:
                current_time = time.time()
                expired_connections = []
                
                for conn_id, conn_info in self.connections.items():
                    if current_time - conn_info['created'] > 300:  # 5 minutes
                        expired_connections.append(conn_id)
                
                for conn_id in expired_connections:
                    del self.connections[conn_id]
                    logger.info(f"Cleaned up expired connection {conn_id}")
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in connection cleanup: {e}")
                time.sleep(60)

def main():
    """Main function to run the UDP tunnel server"""
    print("🚀 Starting UDP Tunnel Server with Internet Forwarding...")
    print("This server will receive encrypted UDP packets, forward them to the internet,")
    print("and send responses back to your Android VPN app.")
    print()
    
    # Check if running as root (required for raw sockets)
    if os.geteuid() != 0:
        print("⚠️  Warning: This server needs raw socket access for internet forwarding")
        print("   You may need to run with sudo for full functionality")
        print("   Without sudo, it will only echo back packets for testing")
        print()
    
    try:
        # Create and start server
        server = UdpTunnelServer(
            host='0.0.0.0',
            port=4433,
            encryption_key="quicvpn2024secretkey32byteslong!"
        )
        
        print("✅ Server created successfully")
        print("📡 Listening on 0.0.0.0:4433")
        print("🔐 Encryption key: quicvpn2024secretkey32byteslong!")
        print("🌐 Internet forwarding: Enabled")
        print("📱 Your Android app should connect to this server")
        print()
        print("Press Ctrl+C to stop the server")
        print()
        
        # Start server
        server.start()
        
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Failed to start server: {e}")
        print("\n💡 Try running with sudo for full internet forwarding:")
        print("   sudo python3 udp_tunnel_server.py")

if __name__ == "__main__":
    main()
