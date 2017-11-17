# packet Analyzer And  Sniffer

**_This module is to be used for Educational purposes only. Exploiting (Hacking) a computer without the concent of the owner is a criminal
offence purnishable by LAW_**

A simple python module that implements a packet sniffer. It sniffs TCP and UDP. It also sniffs IPV4 and IPV6.
It uses the struct modle to unpack each segment of the layers. AF_PAcket of the socket object is used to imply 
that it uses raw socket. Note from windows 7 64bit upward, raw socket programming is not allowed thus this module 
was writen n works on the Linux OS. 'socket.inet_ntoa' was used to convert binary data to source and destination IP address.
Additional pdf documents to help support how the module was built are included in the repo.
This module was written in a  [Geany Python Editor](https://www.geany.org/).

The packet analyser just checks if its a _IPV4 or IPV6_ IP address, while the packet sniffer breaks down eack packet and 
gives you more info about the packet being sniffed like what a typical **_wireshark_** would do.

### To use this module:
- Clone the repo to your local system.
- Download [Geany](https://www.geany.org/Download/Releases) if you dont already have one installed.
- Ensure data is being sent across a networkr you want to listen on
- Execute the script.
- This Script is to be used for Educational purposes only. Sniffing or analyzing data packets without the concent of the owner is a criminal offence purnishable by LAW.....be smart :wink:
