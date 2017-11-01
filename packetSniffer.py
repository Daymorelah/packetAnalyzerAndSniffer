'''
Author: Hussain Ademola Ibrahim
e-mail: demola.hussainin@gmail.com
Phone No. : +2348039539268
Created: 24th May, 2017. 2:13 A.M
This is a python module that implements a packet sniffer. It sniffs TCP and UDP. It also sniffs IPV4 and
IPV6.It uses the struct modle to unpack each segment of the layers. AF_PAcket of the socket
object is used to imply that it uses raw socket. Note from windows 7 64bit upward, raw
socket programming is not allowed thus this module was writen n works on the Linux OS.
'socket.inet_ntoa' was used to convert binary data to src n dst IP address.
/************************************************************************/
python works with binary data dt is an array of characters (string)
or interger. Thus we cant use 'char' struct type cos we wunt b able to move
the bits around. Notie dt d smallest struct type we have is 1 byte n dis 
is a string. since HDl n VSR r 4 bits each. we cant use char. Thus we use
H which is d smallest int we have. since IP fields cn never be signed 
we use H.see strut module for more clarity in the python docs V.2.7.
'''
import socket
import os
import struct
import binascii #converts binary data to ASCII data n fort (hex) for MAC addresses

def etherHeader(packet):
  IpHeader = struct.unpack("!6s6sH",packet[0:14]) #ipv4==0x0800
  dstMac = binascii.hexlify(IpHeader[0]) #source MAC address. converts binary data into ascii dt looks like hex. MAC address is always in hex format.
  srcMac = binascii.hexlify(IpHeader[1]) #Destination MAC address
  protoType = IpHeader[2] #next protocol (ip/ipv4,arp,icmp,ipv6)
  nextProto = hex(protoType) #hex() returns a string. it a built in finction

  print "*******************ETHER HEADER***********************"
  print "\tDestination MAC: "+dstMac[0:2]+":"+dstMac[0:2]+":"+dstMac[2:4]+":"+dstMac[4:6]+":"+dstMac[6:8]+":"+dstMac[8:10]+":"+dstMac[10:]
  print "\tsource MAC: "+srcMac[0:2]+":"+srcMac[0:2]+":"+srcMac[2:4]+":"+srcMac[4:6]+":"+srcMac[6:8]+":"+srcMac[8:10]+":"+srcMac[10:]

  print "\tNext Protocol: "+nextProto
  #print type(nextProto). Turns out nextProto is a string bcos of the hex() which returns a srting

  if (nextProto == '0x800'): #IP/IPV4 frame ethertype. check if_ether.h for other ether protocol hex values.
     proto = 'IPV4'
  if (nextProto == '0x806'): #ARP  frame. check wikipedia (ether type)
     proto = 'ARP'
  if (nextProto == '0x86DD'): #IP/IPV6 frame. check if_ethr.h header file
     proto = 'IPV6'

  packet = packet[14:]
  return packet,proto

#Strips d next layer which is the netwrk protocol layer. Here its IPV4. Its strips each section in the IPV4 header. See IP header for more clarity.
def ipv4Header(data):
   packet = struct.unpack("!6H4s4s",data[0:20]) #6Unsigned shrt,4bytsOfStirng,4bytsOfString. 2*6byts+4byts+4byts==20byts
   version = packet[0] >> 12 #shift dis byte to d right by 12 bits so that only version field remains and all bits to its left is zero. 
   headerLenght = (packet[0] >> 8) & 0x000F #Removes typ of srvc via logic shift to the right and removes version field via '&'.
   typeOfService = packet[0] & 0x00FF #Removes vrs n headrlen via '&'
   totalLenght = packet[1]
   identification = packet[2]
   flags = (packet[3] >> 13)
   fragOffSet = packet[3] & 0x1FFF
   ttl = packet[4] >> 8
   protocol = packet[4] & 0x00FF
   hdrChkSum = packet[5]
   srcAddress = socket.inet_ntoa(packet[6]) #_ntoa==netwotk to ascii.
   dstAddress = socket.inet_ntoa(packet[7]) #_ntoa==netwotk to ascii.

   print "*******************IP HEADER***********************"
   print "\tVersion: "+str(version)
   print "\tHeader Lenght: "+str(headerLenght)
   print "\tType Of Service: "+str(typeOfService)
   print "\tTotal Lenght: "+str(totalLenght) 
   print "\tIdentification: "+str(identification) 
   print"\tFlags: "+str(flags) 
   print "\tFragment Offset: "+str(fragOffSet) 
   print "\tTll: "+str(ttl)
   print "\tNext Protocol: "+str(protocol) 
   print "\tHeader checksum: "+str(hdrChkSum) 
   print "\tSource Address: "+srcAddress 
   print "\tDestination Address: "+dstAddress 

   if (protocol == 6): #check protocol number documentation
     nextProto = 'TCP'
   elif (protocol == 17):
     nextProto = 'UDP'
   else:
     nextProto = 'ICMP'

   data = data[20:]
   return data, nextProto
   
def tcpHeader(newPacket):
   packet = struct.unpack("!2H2I4H",newPacket[0:20]) #2 unsigned short,2unsigned Int,2 unsigned shot. 2byt+2byt+4byt+4byt+2byt+2byt+2byt+2byt==20byts
   srcPort = packet[0]
   dstPort = packet[1]
   sqncNum = packet[2]
   acknNum = packet[3]
   dataOffset = packet[4] >> 12
   reserved = (packet[4] >> 6) & 0x003F 
   tcpFlags = packet[4] & 0x003F #1111 1111 1111 1111 & 0000 0000 0011 1111
   urgFlag = tcpFlags & 0x0020  #1111 1111 1111 1111 & 0000 0000 0010 0000
   ackFlag = tcpFlags & 0x0010  #1111 1111 1111 1111 & 0000 0000 0001 0000
   pushFlag = tcpFlags & 0x0008 #1111 1111 1111 1111 & 0000 0000 0000 1000
   resetFlag = tcpFlags & 0x0004 #1111 1111 1111 1111 & 0000 0000 0000 0100
   synFlag = tcpFlags & 0x0002  #1111 1111 1111 1111 & 0000 0000 0000 0010
   finFlag = tcpFlags & 0x0001  #1111 1111 1111 1111 & 0000 0000 0000 0001
   window = packet[5]
   checkSum = packet[6]
   urgPntr = packet[7]
   

   print "*******************TCP HEADER***********************"
   print "\tSource Port: "+str(srcPort)
   print "\tDestination Port: "+str(dstPort)
   print "\tSequence Number: "+str(sqncNum)
   print "\tAck. Number: "+str(acknNum)
   print "\tData Offset: "+str(dataOffset)
   print "\tReserved: "+str(reserved)
   print "\tTCP Flags: "+str(tcpFlags)

   if(urgFlag == 32):
     print "\tUrgent Flag: Set"
   if(ackFlag == 16):
     print "\tAck Flag: Set"
   if(pushFlag == 8):
     print "\tPush Flag: Set"
   if(resetFlag == 4):
     print "\tReset Flag: Set"
   if(synFlag == 2):
     print "\tSyn Flag: Set"
   if(finFlag == True):
     print "\tFin Flag: Set"
   
   print "\tWindow: "+str(window)
   print "\tChecksum: "+str(checkSum)
   print "\tUrgent Pointer: "+str(urgPntr)

   packet = packet[20:]
   return packet

def udpHeader(newPacket):
  packet = struct.unpack("!4H",newPacket[0:8])
  srcPort = packet[0]
  dstPort = packet[1]
  lenght = packet[2]
  checkSum = packet[3]

  print "*******************UDP HEADER***********************"
  print "\tSource Port: "+str(srcPort)
  print "\tDestination Port: "+str(dstPort)
  print "\tLenght: "+str(lenght)
  print "\tChecksum: "+str(checkSum)
  
  packet = packet[8:]
  return packet
 
def main():

  newPacket,nextProto = '',''
  #os.system('clear')
  packet = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x003))
  receivedRawPacket = packet.recv(2048)
  resultingPacket,proto = etherHeader(receivedRawPacket)

  if (proto=='IPV4'):
   newPacket,nextProto = ipv4Header(resultingPacket)
  #elif (proto=='ARP'):
   #newPacket,nextProto = stripARP(resultingPacket)
  #else:
   #newPacket,nextProto = stripIpv6(resultingPacket)

  if (nextProto == 'TCP'):
    remainingPacket = tcpHeader(newPacket)
  elif (nextProto == 'UDP'):
    remainingPacket = udpHeader(newPacket)
  else:
    return

while(True):
 main()
