#!/usr/bin/env python3
"""
Enhanced PCAP Analyzer
Analyzes PCAP files and extracts network traffic information
"""

import os
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import logging

# Add the project root to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

try:
    from scapy.all import rdpcap, IP, TCP, UDP, IPv6
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not available. PCAP analysis will be limited.")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnhancedPCAPAnalyzer:
    """Enhanced PCAP analyzer with network quintuple extraction"""
    
    def __init__(self, pcap_file: str, variant_id: str | None = None, debug: bool = False):
        self.pcap_file = pcap_file
        self.variant_id = variant_id
        self.debug = debug
        self.connections = {}
        self.session_counter = 1
        
        # Set debug logging level
        if debug:
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Create output directory
        variant_id = variant_id or "unknown"
        output_dir = f"data/processed/{variant_id}/pcap"
        os.makedirs(output_dir, exist_ok=True)
        
        self.output_file = self._get_output_filename(pcap_file)
    
    def _get_output_filename(self, pcap_file: str) -> str:
        """Generate output filename based on input PCAP file"""
        base_name = os.path.splitext(os.path.basename(pcap_file))[0]
        variant_suffix = f"_{self.variant_id}" if self.variant_id else ""
        variant_id = self.variant_id or "unknown"
        return f"data/processed/{variant_id}/pcap/{base_name}{variant_suffix}_analysis.jsonl"
    
    def _extract_network_quintuple(self, packet) -> Dict[str, Any]:
        """Extract network quintuple information from packet"""
        quintuple = {
            "src_ip": "",
            "dst_ip": "",
            "src_port": 0,
            "dst_port": 0,
            "protocol": "",
            "connection_id": "",
            "connection_state": "UNKNOWN",
            "session_duration": 0.0
        }
        
        try:
            # Debug packet structure
            if self.debug:
                logger.debug(f"Packet layers: {packet.layers()}")
                if hasattr(packet, 'sll'):
                    logger.debug(f"SLL packet: {packet.sll}")
                    if hasattr(packet.sll, 'payload'):
                        logger.debug(f"SLL payload: {packet.sll.payload}")
                        logger.debug(f"SLL payload layers: {packet.sll.payload.layers() if hasattr(packet.sll.payload, 'layers') else 'No layers'}")
            
            # Handle Linux cooked v2 format (SLL2)
            if hasattr(packet, 'sll'):
                # For Linux cooked v2, we need to look at the payload
                if hasattr(packet.sll, 'payload'):
                    # Try to extract IP information from the payload
                    payload = packet.sll.payload
                    if hasattr(payload, 'src'):
                        quintuple["src_ip"] = payload.src
                    if hasattr(payload, 'dst'):
                        quintuple["dst_ip"] = payload.dst
                    if hasattr(payload, 'proto'):
                        quintuple["protocol"] = payload.proto
                    
                    # For IPv6
                    if hasattr(payload, 'src') and ':' in str(payload.src):
                        quintuple["src_ip"] = str(payload.src)
                    if hasattr(payload, 'dst') and ':' in str(payload.dst):
                        quintuple["dst_ip"] = str(payload.dst)
                    if hasattr(payload, 'nxt'):
                        quintuple["protocol"] = payload.nxt
            
            # Handle different packet types (fallback)
            if not quintuple["src_ip"] and hasattr(packet, 'ip'):
                quintuple["src_ip"] = packet.ip.src if hasattr(packet.ip, 'src') else ""
                quintuple["dst_ip"] = packet.ip.dst if hasattr(packet.ip, 'dst') else ""
                quintuple["protocol"] = packet.ip.proto if hasattr(packet.ip, 'proto') else ""
            elif not quintuple["src_ip"] and hasattr(packet, 'ipv6'):
                quintuple["src_ip"] = packet.ipv6.src if hasattr(packet.ipv6, 'src') else ""
                quintuple["dst_ip"] = packet.ipv6.dst if hasattr(packet.ipv6, 'dst') else ""
                quintuple["protocol"] = packet.ipv6.nxt if hasattr(packet.ipv6, 'nxt') else ""
            
            # Also check for IPv6 in the packet layers
            if not quintuple["src_ip"]:
                for layer in packet.layers():
                    if 'IPv6' in str(layer):
                        ipv6_layer = packet.getlayer(layer)
                        if hasattr(ipv6_layer, 'src'):
                            quintuple["src_ip"] = str(ipv6_layer.src)
                        if hasattr(ipv6_layer, 'dst'):
                            quintuple["dst_ip"] = str(ipv6_layer.dst)
                        if hasattr(ipv6_layer, 'nxt'):
                            quintuple["protocol"] = ipv6_layer.nxt
                        break
            
            # Extract port information
            if hasattr(packet, 'tcp'):
                quintuple["src_port"] = int(packet.tcp.srcport) if hasattr(packet.tcp, 'srcport') else 0
                quintuple["dst_port"] = int(packet.tcp.dstport) if hasattr(packet.tcp, 'dstport') else 0
                quintuple["protocol"] = "TCP"
                quintuple["connection_state"] = self._determine_tcp_state(packet)
            elif hasattr(packet, 'udp'):
                quintuple["src_port"] = int(packet.udp.srcport) if hasattr(packet.udp, 'srcport') else 0
                quintuple["dst_port"] = int(packet.udp.dstport) if hasattr(packet.udp, 'dstport') else 0
                quintuple["protocol"] = "UDP"
                quintuple["connection_state"] = "ESTABLISHED"
        
            # Generate connection ID
            if quintuple["src_ip"] and quintuple["dst_ip"]:
                quintuple["connection_id"] = f"{quintuple['protocol']}_{quintuple['src_ip']}_{quintuple['src_port']}_{quintuple['dst_ip']}_{quintuple['dst_port']}"
                
                # Update connection tracking
                if hasattr(packet, 'sniff_timestamp'):
                    self._update_connection_tracking(quintuple, packet.sniff_timestamp, packet)
                
                # Get session duration
                quintuple["session_duration"] = self._get_session_duration(quintuple["connection_id"])
        
        except Exception as e:
            if self.debug:
                logger.debug(f"Error extracting network quintuple: {e}")
        
        return quintuple
    
    def _determine_tcp_state(self, packet) -> str:
        """Determine TCP connection state"""
        try:
            if hasattr(packet.tcp, 'flags'):
                flags = packet.tcp.flags
                if 'SYN' in flags and 'ACK' not in flags:
                    return "SYN_SENT"
                elif 'SYN' in flags and 'ACK' in flags:
                    return "SYN_RECEIVED"
                elif 'FIN' in flags:
                    return "FIN_WAIT"
                elif 'RST' in flags:
                    return "RESET"
                else:
                    return "ESTABLISHED"
        except Exception as e:
            if self.debug:
                logger.debug(f"Error determining TCP state: {e}")
            return "UNKNOWN"
    
    def _update_connection_tracking(self, quintuple: Dict[str, Any], timestamp: float, packet):
        """Update connection tracking information"""
        try:
            connection_id = quintuple["connection_id"]
            if connection_id:
                if connection_id not in self.connections:
                    self.connections[connection_id] = {
                        "start_time": timestamp,
                        "last_seen": timestamp,
                        "packet_count": 0,
                        "session_id": self.session_counter
                    }
                    self.session_counter += 1
                else:
                    self.connections[connection_id]["last_seen"] = timestamp
                    self.connections[connection_id]["packet_count"] += 1
        except Exception as e:
            if self.debug:
                logger.debug(f"Error updating connection tracking: {e}")
    
    def _get_session_duration(self, connection_id: str) -> float:
        """Get session duration for a connection"""
        try:
            if connection_id in self.connections:
                conn_info = self.connections[connection_id]
                return conn_info["last_seen"] - conn_info["start_time"]
        except Exception as e:
            if self.debug:
                logger.debug(f"Error getting session duration: {e}")
        return 0.0
    
    def _extract_raw_data(self, packet) -> Dict[str, str]:
        """Extract raw packet data with enhanced error handling"""
        raw_data = {
            "raw_hex": "",
            "raw_ascii": ""
        }
        
        try:
            if hasattr(packet, 'data'):
                raw_data["raw_hex"] = packet.data.data if hasattr(packet.data, 'data') else ""
                # Convert hex to ASCII if possible
                try:
                    if raw_data["raw_hex"]:
                        raw_data["raw_ascii"] = bytes.fromhex(raw_data["raw_hex"].replace(':', '')).decode('utf-8', errors='ignore')
                except:
                    raw_data["raw_ascii"] = ""
        except Exception as e:
            if self.debug:
                logger.debug(f"Error extracting raw data: {e}")
        
        return raw_data
    
    def _extract_protocol_info(self, packet) -> Dict[str, Any]:
        """Extract protocol-specific information with enhanced error handling"""
        protocol_info = {}
        
        try:
            # TCP layer
            if hasattr(packet, 'tcp'):
                protocol_info['tcp'] = {
                    'src_port': packet.tcp.srcport if hasattr(packet.tcp, 'srcport') else None,
                    'dst_port': packet.tcp.dstport if hasattr(packet.tcp, 'dstport') else None,
                    'flags': packet.tcp.flags if hasattr(packet.tcp, 'flags') else None,
                    'seq': packet.tcp.seq if hasattr(packet.tcp, 'seq') else None,
                    'ack': packet.tcp.ack if hasattr(packet.tcp, 'ack') else None,
                    'window': packet.tcp.window_size if hasattr(packet.tcp, 'window_size') else None
                }
            
            # UDP layer
            if hasattr(packet, 'udp'):
                protocol_info['udp'] = {
                    'src_port': packet.udp.srcport if hasattr(packet.udp, 'srcport') else None,
                    'dst_port': packet.udp.dstport if hasattr(packet.udp, 'dstport') else None,
                    'length': packet.udp.length if hasattr(packet.udp, 'length') else None
                }
            
            # HTTP layer (basic detection)
            if hasattr(packet, 'data'):
                try:
                    payload = str(packet.data)
                    if 'HTTP' in payload or 'GET ' in payload or 'POST ' in payload:
                        protocol_info['http'] = {
                            'method': 'GET' if 'GET ' in payload else 'POST' if 'POST ' in payload else 'UNKNOWN',
                            'has_http': True
                        }
                except:
                    pass
                    
        except Exception as e:
            if self.debug:
                logger.debug(f"Error extracting protocol info: {e}")
        
        return protocol_info
    
    def _extract_payload_info(self, packet) -> Dict[str, Any]:
        """Extract payload information with enhanced analysis"""
        payload_info = {
            "payload_size": 0,
            "payload_type": "unknown",
            "content_preview": "",
            "is_encrypted": False,
            "has_sql_keywords": False,
            "sql_keywords_found": []
        }
        
        try:
            # Get payload size
            if hasattr(packet, 'data'):
                payload_info["payload_size"] = len(packet.data) if hasattr(packet.data, '__len__') else 0
            
            # Analyze payload content
            if hasattr(packet, 'data'):
                try:
                    payload_str = str(packet.data)
                    payload_info["content_preview"] = payload_str[:200] if len(payload_str) > 200 else payload_str
                    
                    # Check for SQL keywords
                    sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'UNION', 'OR 1=1', 'OR 1=1--', 'ADMIN', 'PASSWORD']
                    found_keywords = [kw for kw in sql_keywords if kw.lower() in payload_str.lower()]
                    if found_keywords:
                        payload_info["has_sql_keywords"] = True
                        payload_info["sql_keywords_found"] = found_keywords
                        payload_info["payload_type"] = "sql_injection"
                    
                    # Check for HTTP content
                    elif 'HTTP' in payload_str or 'GET ' in payload_str or 'POST ' in payload_str:
                        payload_info["payload_type"] = "http"
                    
                    # Check for DNS content
                    elif 'DNS' in payload_str or 'query' in payload_str.lower():
                        payload_info["payload_type"] = "dns"
                    
                    # Check if content looks encrypted (high entropy)
                    elif len(payload_str) > 50 and len(set(payload_str)) / len(payload_str) > 0.8:
                        payload_info["is_encrypted"] = True
                        payload_info["payload_type"] = "encrypted"
                        
                except Exception as e:
                    if self.debug:
                        logger.debug(f"Error analyzing payload: {e}")
                        
        except Exception as e:
            if self.debug:
                logger.debug(f"Error extracting payload info: {e}")
        
        return payload_info
    
    def analyze_packet(self, packet, packet_index: int) -> Dict[str, Any]:
        """Analyze a single packet and extract all relevant information"""
        try:
            # Convert timestamp to UTC ISO 8601 format
            timestamp = None
            if hasattr(packet, 'time'):
                # Convert Unix timestamp to UTC ISO 8601
                from datetime import datetime
                timestamp = datetime.utcfromtimestamp(float(packet.time)).isoformat() + "Z"
            
            # Basic packet information
            packet_info = {
                "packet_index": packet_index,
                "timestamp": timestamp,
                "length": len(packet) if hasattr(packet, '__len__') else 0,
                "variant_id": self.variant_id,
                "source_type": "pcap",
                "event_type": "network_traffic",
                "severity": "info",
                "is_attack": False,
                "attack_stage": None
            }
            
            # Extract network quintuple
            quintuple = self._extract_network_quintuple(packet)
            packet_info.update(quintuple)
            
            # Extract protocol information
            protocol_info = self._extract_protocol_info(packet)
            packet_info["protocol_details"] = protocol_info
            
            # Extract payload information
            payload_info = self._extract_payload_info(packet)
            packet_info["payload"] = payload_info
            
            # Extract raw data
            raw_data = self._extract_raw_data(packet)
            packet_info["raw_data"] = raw_data
            
            # Determine if this is attack traffic
            if self._is_attack_traffic(packet_info):
                packet_info["is_attack"] = True
                packet_info["attack_stage"] = self._determine_attack_stage(packet_info)
            
            # Add host information
            packet_info["host"] = os.uname().nodename
            
            return packet_info
            
        except Exception as e:
            if self.debug:
                logger.debug(f"Error analyzing packet {packet_index}: {e}")
            return None
    
    def _is_attack_traffic(self, packet_info: Dict[str, Any]) -> bool:
        """Determine if packet represents attack traffic"""
        try:
            # Check for SQL injection patterns in payload
            payload = packet_info.get("payload", {}).get("http_payload", "")
            if payload:
                sql_patterns = ["'", "OR", "UNION", "SELECT", "DROP", "INSERT", "UPDATE", "DELETE"]
                if any(pattern.lower() in payload.lower() for pattern in sql_patterns):
                    return True
            
            # Check for port scanning
            if packet_info.get("protocol") == "TCP":
                flags = packet_info.get("protocol_details", {}).get("tcp", {}).get("flags", "")
                if "SYN" in flags and "ACK" not in flags:
                    # Potential port scan
                    return True
            
            # Check for suspicious ports
            dst_port = packet_info.get("dst_port", 0)
            suspicious_ports = [22, 23, 3389, 445, 135, 139]  # SSH, Telnet, RDP, SMB, etc.
            if dst_port in suspicious_ports:
                return True
                
        except Exception as e:
            if self.debug:
                logger.debug(f"Error determining attack traffic: {e}")
        
        return False
    
    def _determine_attack_stage(self, packet_info: Dict[str, Any]) -> str:
        """Determine attack stage based on packet characteristics"""
        try:
            # Port scanning
            if packet_info.get("protocol") == "TCP":
                flags = packet_info.get("protocol_details", {}).get("tcp", {}).get("flags", "")
                if "SYN" in flags and "ACK" not in flags:
                    return "reconnaissance"
            
            # SQL injection
            payload = packet_info.get("payload", {}).get("http_payload", "")
            if payload and any(pattern.lower() in payload.lower() for pattern in ["'", "OR", "UNION", "SELECT"]):
                return "exploit"
            
            # Data exfiltration
            if packet_info.get("payload", {}).get("data_size", 0) > 1000:
                return "exfiltration"
                
        except Exception as e:
            if self.debug:
                logger.debug(f"Error determining attack stage: {e}")
        
        return "unknown"
    
    def analyze_pcap_file(self, max_packets: int = None) -> int:
        """Analyze PCAP file and write results to JSONL"""
        processed_count = 0
        error_count = 0
        
        try:
            # Read PCAP file using scapy
            packets = rdpcap(self.pcap_file)
            
            if self.debug:
                logger.info(f"Total packets in file: {len(packets)}")
            
            # Limit packets if specified
            if max_packets:
                packets = packets[:max_packets]
            
            # Process each packet
            for i, packet in enumerate(packets):
                try:
                    if self.debug and i % 100 == 0:
                        logger.debug(f"Processing packet {i+1}/{len(packets)}")
                    
                    # Analyze packet
                    packet_data = self.analyze_packet(packet, i)
                    
                    # Debug first few packets
                    if self.debug and i < 5:
                        logger.debug(f"Packet {i} analysis result: {packet_data}")
                        if packet_data:
                            logger.debug(f"  src_ip: {packet_data.get('src_ip')}")
                            logger.debug(f"  dst_ip: {packet_data.get('dst_ip')}")
                            logger.debug(f"  protocol: {packet_data.get('protocol')}")
                        else:
                            logger.debug(f"  Packet {i} returned None")
                    
                    # Only write packets that have meaningful data
                    if packet_data and (packet_data.get("src_ip") or packet_data.get("dst_ip")):
                        # Write to output file
                        with open(self.output_file, 'a', encoding='utf-8') as f:
                            f.write(json.dumps(packet_data, ensure_ascii=False) + '\n')
                        processed_count += 1
                    elif self.debug and i < 10:  # Show first 10 skipped packets
                        logger.debug(f"Skipping packet {i}: no meaningful data - src_ip: {packet_data.get('src_ip') if packet_data else 'None'}, dst_ip: {packet_data.get('dst_ip') if packet_data else 'None'}")
                        
                except Exception as e:
                    error_count += 1
                    if self.debug and error_count <= 5:  # Show first 5 errors
                        logger.debug(f"Error processing packet {i}: {e}")
                    continue
            
            if self.debug:
                logger.info(f"Processed {processed_count} packets, {error_count} errors")
            
        except Exception as e:
            logger.error(f"Error reading PCAP file: {e}")
            return 0
        
        return processed_count

def main():
    """Main function for command line usage"""
    parser = argparse.ArgumentParser(description="Enhanced PCAP Analyzer")
    parser.add_argument("pcap_file", help="PCAP file to analyze")
    parser.add_argument("--variant-id", help="Variant ID for the experiment")
    parser.add_argument("--max-packets", type=int, help="Maximum number of packets to process")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.pcap_file):
        print(f"Error: PCAP file {args.pcap_file} not found")
        sys.exit(1)
    
    try:
        analyzer = EnhancedPCAPAnalyzer(args.pcap_file, args.variant_id, args.debug)
        processed_count = analyzer.analyze_pcap_file(args.max_packets)
        print(f"Successfully processed {processed_count} packets")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 