import socket, sys, random, time, binascii
import struct
import logging
from utils.udp import handle_udp
from utils.tcp import handle_tcp
from utils.utils import *


eth_protocol_dict = {
        8: 'IPv4',
        1544: 'ARP',
        56710: 'IPv6'
        }
ip_protocol_dict = {
        6: 'TCP',
        1: 'ICMP',
        17: 'UDP'
        }

logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %I:%M:%S %p')

class Sniffer():

    def __init__(self, ifc, packets=0, ip_protocol=0, eth_protocol=8, verb=1):
        try:
            #define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
            self.sock = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
            self.sock.bind((ifc,0))
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, ICMP_RECV_BUF*BUF_FACTOR)
        except Exception as e:
            logging.error('Socket could not be created. Error: ', e)
            raise e

        self.packets = packets
        self.ip_protocol = ip_protocol
        self.eth_protocol = eth_protocol
        self.verb = verb

    def start(self):
        # receive a packet
        while True:
            packet, _ = self.sock.recvfrom(65565)
            self._handlePacket(packet)

    def _handlePacket(self, packet):
        #parse ethernet header

        eth_header = packet[:ETH_LENGTH]
        eth = struct.unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
        src_mac = packet[0:6]
        des_mac = packet[6:12]

        try:
            output = ('Source Mac: %s Destination Mac: %s Protocol: %s' % (
                self.ethAddrDecode(src_mac), self.ethAddrDecode(des_mac), eth_protocol_dict[eth_protocol]
                ))
        except KeyError:
            logging.error('No such Eth Protocol')
            return
        #Parse IP packets, IP Protocol number = 8
        if eth_protocol == 8 :
            self._handleIPv4Packet(packet, output)
        elif eth_protocol == 1544:
            self._handleARPPacket(packet, output)
        else:
            return

    def _handleIPv4Packet(self, packet, output):

        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[ETH_LENGTH:20+ETH_LENGTH]

        iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
        IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, src_IP,dest_IP = iph

        version = IHL_VERSION >> 4
        ihl = IHL_VERSION & 0xF
        iph_length = ihl * 4

        try:
            output += ' Version: %s Type of Service: %s Packet ID: %s TTL: %s Protocol: %s Source IP: %s Destination IP: %s' % (
                str(version), str(TYPE_OF_SERVICE), str(pktID), str(TIME_TO_LIVE),
                str(ip_protocol_dict[PROTOCOL]), socket.inet_ntoa(src_IP), socket.inet_ntoa(dest_IP))
        except KeyError:
            logging.error('No such IP Protocol')
            return

        if PROTOCOL == 1:
            self._handleICMPPacket(packet, output)
        elif PROTOCOL == 6:
            self._handleTCPPacket(packet, iph_length, output)
        elif PROTOCOL == 17:
            self._handleUDPPacket(packet, iph_length, output)
        else:
            return

    def _handleARPPacket(self, packet, output):
        arp_header_len = 28
        HTYPE, PTYPE, HLEN, PLEN, Operation, SHA, SPA, THA, TPA = struct.unpack('2s2s1s1s2s6s4s6s4s',packet[ETH_LENGTH:ETH_LENGTH+arp_header_len])
        print ("ARP Header :")
        print (" |_ SHA: {0} -> THA: {1}".format(self.ethAddrDecode(SHA), self.ethAddrDecode(THA)))
        print (" |_ SPA: {0} -> TPA: {1}".format(socket.inet_ntoa(SPA), socket.inet_ntoa(TPA)))
        print (" |_ HTYPE          : {0}".format(binascii.hexlify(HTYPE)))
        print (" |_ PTYPE          : {0}".format(binascii.hexlify(PTYPE)))
        print (" |_ HLEN           : {0}".format(binascii.hexlify(HLEN)))
        print (" |_ PLEN           : {0}".format(binascii.hexlify(PLEN)))
        print (" |_ OPER           : {0}".format(binascii.hexlify(Operation)))


    def _handleICMPPacket(self, packet, output):

        ethiph_length = 34
        icmph_length = 8
        icmp_header = packet[ethiph_length:ethiph_length+icmph_length]
        data = packet[ethiph_length+icmph_length:]

        icmph = struct.unpack('BbHHh' , icmp_header)
        icmp_type, code, checksum, packetid, seq = icmph

        logging.info(output + '\nICMP Type: %s Packet ID: %s Seq: %s' % (str(icmp_type), str(packetid), str(seq)) + divide_line)

    def _handleTCPPacket(self, packet, iph_length, output):
        result = handle_tcp(packet[ETH_LENGTH+iph_length:], output)
        logging.info(output + '\n' + result + divide_line)

    def _handleUDPPacket(self, packet, iph_length, output):
        result = handle_udp(packet[ETH_LENGTH+iph_length:], output)
        logging.info(output + '\n' + result + divide_line)


        #Convert a string of 6 characters of ethernet address into a dash separated hex string
    def ethAddrDecode(self, macAddr) :
        macAddr = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (macAddr[0] , macAddr[1] , macAddr[2], macAddr[3], macAddr[4] , macAddr[5])
        return macAddr


    def __del__(self):
        self.sock.close()



