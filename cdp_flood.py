from scapy.all import *
from scapy.contrib.cdp import CDPv2_HDR, CDPMsgDeviceID, CDPMsgPortID, CDPMsgSoftwareVersion

load_contrib("cdp")

#Create a frame with the CDP mulitcast address.
eth = Ether(dst="01:00:0c:cc:cc:cc",src=RandMAC(),type=0x2000)

#Create a CDP Packet for our eth payload
cdp = CDPv2_HDR(
	vers=2, #CDP version
	ttl=180 #Time to Live
)/CDPMsgDeviceID(val="MyCiscoDevice")/CDPMsgPortID(iface="GigabitEthernet0/1")

cdp_packet = eth/cdp

#cdp_packet.show()
#send with loop set to 1, this will send packets until execution is interupted.
sendp(cdp_packet,loop=1)
