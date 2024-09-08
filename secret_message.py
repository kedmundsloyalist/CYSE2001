#Prompt for a destination and source IP and a message. If all filled out create an IP packet with the message as a body and src and dst options set. Layer that into
#a frame and then send it.
#
#The recipent will be able to view the message in a program like Wireshark.
from scapy.all import *

dst_ip = input("Enter Destination IP Address:")
src_ip = input("Enter the IP you Want to Send From:")
msg = input("What is your Message?")

if dst_ip != "" and msg != "" and src_ip != "":
	frame = Ether()/IP(dst=dst_ip, src=src_ip)/msg
	sendp(frame)
	print("Message sent to " + dst_ip)
else:
	print("Please provide a dest,src and message!")
	exit()
