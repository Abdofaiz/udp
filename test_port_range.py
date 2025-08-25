#!/usr/bin/env python3
"""
Port Range Test Script for SSH + UDP Tunnel
Tests connectivity across the full port range 1-65535
"""

import socket
import struct
import time
import threading
from typing import Dict, List, Tuple
import argparse

class PortRangeTester:
    def __init__(self, server_address: str, server_port: int = 4433, 
                 encryption_key: str = "quicvpn2024secretkey32byteslong!"):
        self.server_address = server_address
        self.server_port = server_port
        self.encryption_key = encryption_key.encode('utf-8')
        
        # Test results
        self.results: Dict[int, bool] = {}
        self.connection_id = 12345
        self.packet_number = 0
        
        # Statistics
        self.stats = {
            'total_ports': 0,
            'successful_ports': 0,
            'failed_ports': 0,
            'test_duration': 0
        }
    
    def test_port_range(self, start_port: int = 1, end_port: int = 65535, 
                       max_concurrent: int = 100, timeout: float = 2.0):
        """Test connectivity across the specified port range"""
        print(f"🚀 Starting port range test: {start_port}-{end_port}")
        print(f"📡 Server: {self.server_address}:{self.server_port}")
        print(f"⚡ Max concurrent tests: {max_concurrent}")
        print(f"⏱️  Timeout per port: {timeout}s")
        print("=" * 60)
        
        start_time = time.time()
        
        # Create test ports list
        test_ports = list(range(start_port, end_port + 1))
        self.stats['total_ports'] = len(test_ports)
        
        # Test ports in batches
        for i in range(0, len(test_ports), max_concurrent):
            batch = test_ports[i:i + max_concurrent]
            self._test_port_batch(batch, timeout)
            
            # Progress update
            progress = min((i + max_concurrent) / len(test_ports) * 100, 100)
            print(f"📊 Progress: {progress:.1f}% ({i + len(batch)}/{len(test_ports)})")
        
        # Calculate statistics
        self.stats['test_duration'] = time.time() - start_time
        self.stats['successful_ports'] = sum(1 for success in self.results.values() if success)
        self.stats['failed_ports'] = sum(1 for success in self.results.values() if not success)
        
        # Print results
        self._print_results()
    
    def _test_port_batch(self, ports: List[int], timeout: float):
        """Test a batch of ports concurrently"""
        threads = []
        
        for port in ports:
            thread = threading.Thread(target=self._test_single_port, args=(port, timeout))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
    
    def _test_single_port(self, port: int, timeout: float):
        """Test connectivity to a single port"""
        try:
            # Create test packet for this port
            test_packet = self._create_test_packet(port)
            encrypted_packet = self._encrypt_packet(test_packet)
            
            # Send packet to server
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            sock.sendto(encrypted_packet, (self.server_address, self.server_port))
            
            # Try to receive response
            try:
                response, addr = sock.recvfrom(1024)
                self.results[port] = True
                print(f"✅ Port {port:5d}: SUCCESS")
            except socket.timeout:
                self.results[port] = False
                print(f"❌ Port {port:5d}: TIMEOUT")
            except Exception as e:
                self.results[port] = False
                print(f"❌ Port {port:5d}: ERROR - {e}")
            
            sock.close()
            
        except Exception as e:
            self.results[port] = False
            print(f"❌ Port {port:5d}: FAILED - {e}")
    
    def _create_test_packet(self, port: int) -> bytes:
        """Create a test packet for the specified port"""
        # Create a simple test packet that includes the port number
        buffer = struct.pack('!QQH', self.connection_id, self.packet_number, port)
        self.packet_number += 1
        
        # Add test data
        test_data = f"TEST_PORT_{port}".encode()
        buffer += test_data
        
        # Pad to minimum size
        if len(buffer) < 32:
            buffer += b'\x00' * (32 - len(buffer))
        
        return buffer
    
    def _encrypt_packet(self, packet: bytes) -> bytes:
        """Simple encryption simulation (in real implementation, use proper AES)"""
        # For testing purposes, just return the packet
        # In production, implement proper AES encryption
        return packet
    
    def _print_results(self):
        """Print test results and statistics"""
        print("\n" + "=" * 60)
        print("🎯 PORT RANGE TEST RESULTS")
        print("=" * 60)
        
        print(f"📊 Total Ports Tested: {self.stats['total_ports']}")
        print(f"✅ Successful Connections: {self.stats['successful_ports']}")
        print(f"❌ Failed Connections: {self.stats['failed_ports']}")
        print(f"📈 Success Rate: {(self.stats['successful_ports'] / self.stats['total_ports'] * 100):.2f}%")
        print(f"⏱️  Total Test Duration: {self.stats['test_duration']:.2f} seconds")
        print(f"🚀 Average Speed: {self.stats['total_ports'] / self.stats['test_duration']:.1f} ports/second")
        
        # Port range analysis
        if self.results:
            successful_ports = [port for port, success in self.results.items() if success]
            failed_ports = [port for port, success in self.results.items() if not success]
            
            if successful_ports:
                print(f"\n✅ Successful Ports Range: {min(successful_ports)} - {max(successful_ports)}")
                print(f"📋 Sample Successful Ports: {sorted(successful_ports)[:10]}")
            
            if failed_ports:
                print(f"\n❌ Failed Ports Range: {min(failed_ports)} - {max(failed_ports)}")
                print(f"📋 Sample Failed Ports: {sorted(failed_ports)[:10]}")
        
        # Recommendations
        print("\n💡 RECOMMENDATIONS:")
        if self.stats['successful_ports'] / self.stats['total_ports'] > 0.9:
            print("🎉 Excellent! Port range 1-65535 is working well.")
        elif self.stats['successful_ports'] / self.stats['total_ports'] > 0.7:
            print("👍 Good! Most ports are working. Check firewall rules.")
        elif self.stats['successful_ports'] / self.stats['total_ports'] > 0.5:
            print("⚠️  Fair. Some ports are blocked. Check server configuration.")
        else:
            print("❌ Poor performance. Check server logs and configuration.")
        
        print("\n🔧 TROUBLESHOOTING:")
        print("1. Check server logs: journalctl -u ssh-udp-tunnel -f")
        print("2. Verify firewall rules: ufw status")
        print("3. Check server configuration and encryption key")
        print("4. Ensure raw socket permissions (requires root)")
    
    def save_results(self, filename: str = "port_test_results.txt"):
        """Save test results to a file"""
        try:
            with open(filename, 'w') as f:
                f.write("SSH + UDP Tunnel Port Range Test Results\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"Server: {self.server_address}:{self.server_port}\n")
                f.write(f"Test Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Ports: {self.stats['total_ports']}\n")
                f.write(f"Successful: {self.stats['successful_ports']}\n")
                f.write(f"Failed: {self.stats['failed_ports']}\n")
                f.write(f"Success Rate: {(self.stats['successful_ports'] / self.stats['total_ports'] * 100):.2f}%\n\n")
                
                f.write("Port Results:\n")
                f.write("-" * 20 + "\n")
                for port in sorted(self.results.keys()):
                    status = "SUCCESS" if self.results[port] else "FAILED"
                    f.write(f"Port {port:5d}: {status}\n")
            
            print(f"\n💾 Results saved to: {filename}")
            
        except Exception as e:
            print(f"❌ Failed to save results: {e}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Test SSH + UDP Tunnel Port Range")
    parser.add_argument("--server", "-s", required=True, help="Server IP address")
    parser.add_argument("--port", "-p", type=int, default=4433, help="UDP tunnel port (default: 4433)")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=65535, help="End port (default: 65535)")
    parser.add_argument("--concurrent", "-c", type=int, default=100, help="Max concurrent tests (default: 100)")
    parser.add_argument("--timeout", "-t", type=float, default=2.0, help="Timeout per port in seconds (default: 2.0)")
    parser.add_argument("--save", help="Save results to file")
    
    args = parser.parse_args()
    
    print("🔍 SSH + UDP Tunnel Port Range Tester")
    print("=" * 50)
    
    # Validate arguments
    if args.start < 1 or args.end > 65535:
        print("❌ Error: Port range must be between 1 and 65535")
        return
    
    if args.start > args.end:
        print("❌ Error: Start port must be less than or equal to end port")
        return
    
    # Create tester and run tests
    tester = PortRangeTester(args.server, args.port)
    
    try:
        tester.test_port_range(args.start, args.end, args.concurrent, args.timeout)
        
        # Save results if requested
        if args.save:
            tester.save_results(args.save)
        
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")

if __name__ == "__main__":
    main()
