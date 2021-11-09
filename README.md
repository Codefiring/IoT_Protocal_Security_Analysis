# IoT_Protocal_Security_Analysis
It is a project to reproduce top conference work: "Discovering and understanding the security hazards in the interactions between IoT devices, mobile apps, and clouds on smart home platforms" (USENIX Security). Based on the paper, we capture the network traffic, use reverse engineering to analysis the mobile app and use physical debug tools on the device to get the necessary information to decrypt the package and complete the security analysis of the whole communication protocol. Finally, we successfully use the analysis result to implement phantom devices to mimic a real device. 

## pcap_decrypt.py
This python file decrypt the network traffic packages which are captured by wireshark.

## replay.py
This python file replays the instruction when the device is registering in the network and causes it failed to configure the network.
