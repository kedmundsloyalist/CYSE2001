#!/usr/bin/env python3
"""
Scapy Frame Configuration Scripts
Multiple examples showing different frame types with custom protocols
"""

from scapy.all import *
import time

# Define custom EtherTypes for easy Wireshark filtering
CUSTOM_ETHERTYPE_BASIC = 0x88B5  # Custom protocol type 1
CUSTOM_ETHERTYPE_ADVANCED = 0x88B6  # Custom protocol type 2
CUSTOM_ETHERTYPE_VLAN_TEST = 0x88B7  # Custom protocol type 3
ADAPTER = "Wireless LAN adapter Wi-Fi"

#"Intel(R) Wi-Fi 6E AX211 160MHz"

def script1_basic_custom_frame():
    """
    Script 1: Basic Ethernet frame with custom EtherType
    Creates a simple frame with custom protocol and text payload
    """
    print("=== Script 1: Basic Custom Frame ===")
    
    # Create basic Ethernet frame with custom EtherType
    frame = Ether(
        dst="ff:ff:ff:ff:ff:ff",  # Broadcast MAC
        src="aa:bb:cc:dd:ee:ff",  # Custom source MAC
        type=CUSTOM_ETHERTYPE_BASIC  # Our custom EtherType
    ) / Raw(load="BASIC_TEST_MESSAGE: Hello from Scapy Basic Frame!")
    
    # Display frame information
    print(f"Frame size: {len(frame)} bytes")
    print(f"EtherType: 0x{frame.type:04x}")
    frame.show()
    
    # Send frame (will appear as broadcast on local network)
    print("Sending basic custom frame..." + ADAPTER)
    sendp(frame, iface=ADAPTER, verbose=True)  # Change interface as needed
    
    # Save to file for offline analysis
    wrpcap("basic_custom_frame.pcap", frame)
    print("Saved to: basic_custom_frame.pcap")
    print()

def script2_layered_custom_protocol():
    """
    Script 2: Multi-layer custom protocol with structured data
    Creates a frame with custom headers and multiple data fields
    """
    print("=== Script 2: Layered Custom Protocol ===")
    
    # Define custom protocol structure using Packet class
    class CustomProtocol(Packet):
        name = "CustomTestProtocol"
        fields_desc = [
            ByteField("version", 1),
            ByteField("msg_type", 0x42),
            ShortField("sequence", 1337),
            StrLenField("message", "ADVANCED_TEST: Custom protocol with structured headers!", 
                       length_from=lambda pkt: 50)
        ]
    
    # Create frame with our custom protocol
    frame = Ether(
        dst="11:22:33:44:55:66",
        src="aa:bb:cc:dd:ee:ff", 
        type=CUSTOM_ETHERTYPE_ADVANCED
    ) / CustomProtocol(
        version=1,
        msg_type=0x42,
        sequence=1337,
        message="ADVANCED_TEST: This is a structured custom protocol message!"
    )
    
    print(f"Frame size: {len(frame)} bytes")
    print(f"Custom protocol version: {frame[CustomProtocol].version}")
    print(f"Message type: 0x{frame[CustomProtocol].msg_type:02x}")
    print(f"Sequence number: {frame[CustomProtocol].sequence}")
    frame.show()
    
    # Send and save
    print("Sending advanced custom frame...")
    sendp(frame, iface=ADAPTER, verbose=True)
    wrpcap("advanced_custom_frame.pcap", frame)
    print("Saved to: advanced_custom_frame.pcap")
    print()

def script3_vlan_tagged_custom():
    """
    Script 3: VLAN-tagged frame with custom protocol
    Shows how VLAN tags work with custom protocols
    """
    print("=== Script 3: VLAN Tagged Custom Frame ===")
    
    # Create VLAN-tagged frame
    frame = Ether(
        dst="ff:ff:ff:ff:ff:ff",
        src="aa:bb:cc:dd:ee:ff"
    ) / Dot1Q(
        vlan=100,           # VLAN ID
        prio=3,             # Priority
        type=CUSTOM_ETHERTYPE_VLAN_TEST
    ) / Raw(load="VLAN_TEST: This frame is tagged with VLAN 100 and uses custom EtherType!")
    
    print(f"Frame size: {len(frame)} bytes")
    print(f"VLAN ID: {frame[Dot1Q].vlan}")
    print(f"Priority: {frame[Dot1Q].prio}")
    print(f"Inner EtherType: 0x{frame[Dot1Q].type:04x}")
    frame.show()
    
    print("Sending VLAN tagged custom frame...")
    sendp(frame, iface=ADAPTER, verbose=True)
    wrpcap("vlan_custom_frame.pcap", frame)
    print("Saved to: vlan_custom_frame.pcap")
    print()

def script4_multiple_test_frames():
    """
    Script 4: Generate multiple frames for comprehensive testing
    Creates a series of frames with different characteristics
    """
    print("=== Script 4: Multiple Test Frames ===")
    
    frames = []
    
    # Frame 1: Small payload
    frame1 = Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:01", type=CUSTOM_ETHERTYPE_BASIC) / \
             Raw(load="SMALL")
    frames.append(frame1)
    
    # Frame 2: Medium payload
    frame2 = Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:02", type=CUSTOM_ETHERTYPE_BASIC) / \
             Raw(load="MEDIUM_PAYLOAD: " + "A" * 100)
    frames.append(frame2)
    
    # Frame 3: Large payload (approaching MTU)
    large_payload = "LARGE_PAYLOAD: " + "B" * 1400
    frame3 = Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:03", type=CUSTOM_ETHERTYPE_BASIC) / \
             Raw(load=large_payload)
    frames.append(frame3)
    
    # Frame 4: Custom protocol with timestamps
    class TimestampProtocol(Packet):
        fields_desc = [
            IntField("timestamp", int(time.time())),
            StrLenField("data", "TIMESTAMP_TEST: Frame created at " + str(int(time.time())), 
                       length_from=lambda pkt: 50)
        ]
    
    frame4 = Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:04", type=CUSTOM_ETHERTYPE_ADVANCED) / \
             TimestampProtocol()
    frames.append(frame4)
    
    # Display and send all frames
    for i, frame in enumerate(frames, 1):
        print(f"Frame {i}: {len(frame)} bytes, EtherType: 0x{frame.type:04x}")
    
    print(f"\nSending {len(frames)} test frames...")
    sendp(frames, iface=ADAPTER, verbose=True)
    
    # Save all frames to one capture file
    wrpcap("multiple_test_frames.pcap", frames)
    print("Saved all frames to: multiple_test_frames.pcap")
    print()

def script5_comparison_frames():
    """
    Script 5: Side-by-side comparison of standard vs custom protocols
    Creates frames showing the difference between standard and custom protocols
    """
    print("=== Script 5: Standard vs Custom Protocol Comparison ===")
    
    frames = []
    
    # Standard ARP frame for comparison
    arp_frame = Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:ff") / \
                ARP(op=1, psrc="192.168.1.100", pdst="192.168.1.1", 
                    hwsrc="aa:bb:cc:dd:ee:ff", hwdst="00:00:00:00:00:00")
    frames.append(arp_frame)
    
    # Custom frame mimicking ARP structure
    class CustomARP(Packet):
        name = "CustomARPLike"
        fields_desc = [
            ShortField("hw_type", 1),
            ShortField("proto_type", 0x0800),
            ByteField("hw_len", 6),
            ByteField("proto_len", 4),
            ShortField("operation", 1),
            MACField("src_mac", "aa:bb:cc:dd:ee:ff"),
            IPField("src_ip", "192.168.1.100"),
            MACField("dst_mac", "00:00:00:00:00:00"),
            IPField("dst_ip", "192.168.1.1"),
            StrFixedLenField("custom_data", "CUSTOM_ARP_TEST", 15)
        ]
    
    custom_arp = Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:ff", 
                      type=CUSTOM_ETHERTYPE_ADVANCED) / CustomARP()
    frames.append(custom_arp)
    
    # Standard IP frame
    ip_frame = Ether(dst="11:22:33:44:55:66", src="aa:bb:cc:dd:ee:ff") / \
               IP(src="192.168.1.100", dst="8.8.8.8") / \
               Raw(load="Standard IP packet with text payload")
    frames.append(ip_frame)
    
    # Custom IP-like frame
    custom_ip = Ether(dst="11:22:33:44:55:66", src="aa:bb:cc:dd:ee:ff", 
                     type=CUSTOM_ETHERTYPE_BASIC) / \
                Raw(load="CUSTOM_IP_LIKE: This looks like IP but uses custom EtherType")
    frames.append(custom_ip)
    
    print("Comparison frames created:")
    print("1. Standard ARP")
    print("2. Custom ARP-like protocol")
    print("3. Standard IP")
    print("4. Custom IP-like protocol")
    
    sendp(frames, iface=ADAPTER, verbose=True)
    wrpcap("comparison_frames.pcap", frames)
    print("Saved comparison frames to: comparison_frames.pcap")
    print()

def display_wireshark_filters():
    """
    Display useful Wireshark filters for finding our custom frames
    """
    print("=== Wireshark Display Filters for Custom Frames ===")
    print(f"Basic custom frames:     eth.type == 0x{CUSTOM_ETHERTYPE_BASIC:04x}")
    print(f"Advanced custom frames:  eth.type == 0x{CUSTOM_ETHERTYPE_ADVANCED:04x}")
    print(f"VLAN custom frames:      eth.type == 0x{CUSTOM_ETHERTYPE_VLAN_TEST:04x}")
    print("All custom frames:       eth.type == 0x88b5 or eth.type == 0x88b6 or eth.type == 0x88b7")
    print("Custom MAC addresses:    eth.src == aa:bb:cc:dd:ee:ff")
    print("Broadcast custom:        eth.dst == ff:ff:ff:ff:ff:ff and (eth.type == 0x88b5 or eth.type == 0x88b6)")
    print("VLAN 100 frames:         vlan.id == 100")
    print()
    print("=== Raw Data Filters ===")
    print('Frames containing "TEST": data contains "TEST"')
    print('Basic test messages:      data contains "BASIC_TEST"')
    print('Advanced test messages:   data contains "ADVANCED_TEST"')
    print('VLAN test messages:       data contains "VLAN_TEST"')
    print()

def main():
    """
    Main function - runs all test scripts
    """
    print("Scapy Custom Frame Generator")
    print("=" * 40)
    print("This script creates various custom Ethernet frames for Wireshark analysis")
    print("Make sure to run as root/administrator for packet sending")
    print()
    
    # Display filter information first
    display_wireshark_filters()
    
    try:
        # Run all scripts
        script1_basic_custom_frame()
        script2_layered_custom_protocol()
        script3_vlan_tagged_custom()
        script4_multiple_test_frames()
        script5_comparison_frames()
        
        print("=== Summary ===")
        print("Generated capture files:")
        print("- basic_custom_frame.pcap")
        print("- advanced_custom_frame.pcap") 
        print("- vlan_custom_frame.pcap")
        print("- multiple_test_frames.pcap")
        print("- comparison_frames.pcap")
        print()
        print("Use the Wireshark filters shown above to find these frames!")
        
    except Exception as e:
        print(f"Error: {e}")
        print("Make sure you're running as root and have the correct network interface")
        print("You may need to change 'eth0' to your actual interface name")

if __name__ == "__main__":
    main()
