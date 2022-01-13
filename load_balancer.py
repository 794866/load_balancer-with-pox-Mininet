import time

from pox.core import core
import pox.lib.packet as libpacket
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
from pox.openflow.of_json import *
import random
import threading

log = core.getLogger()

IDLE_TIMEOUT = 10   # SECONDS

""" SWITCH ADDRESSES """
NET_PROXY_IP = IPAddr('10.0.0.13')
NET_PROXY_MAC = EthAddr('00:00:00:00:00:13')

""" Gets host by mac """
def map_list_mac(list, mac):
    return next((x for x in list.values() if str(x.mac) == str(mac)), None)

""" Gets host by IP """
def map_list_ip(list, ip):
    return next((x for x in list.values() if str(x.ip) == str(ip)), None)

class proxy_controller(object):
    class Host(object):
        def __init__(self, mac, ip, port):
            self.mac = mac
            self.ip = ip
            self.port = port
        def __str__(self):
            return "MAC: " + str(self.mac) + " | IP: " + str(self.ip) + " | Port:" + str(self.port)
    """Statistic packets """
    class stats_request(threading.Thread):
        def __init__(self, connection):
            threading.Thread.__init__(self)
            self.connection = connection

        def run(self):
            while True:
                msg = of.ofp_stats_request()
                msg.type = of.OFPST_PORT
                msg.body = of.ofp_port_stats_request()
                self.connection.send(msg)
                time.sleep(5)

    """ INITIALIZATION PROXY """
    def __init__(self, connection):
        self.connection = connection
        self.selectedMehod = 0

        # Timer should be global in order to be stopped when ConnectionDown event is raised
        self.stats_request(self.connection).start()

        """ FROM CLIENTS AND SERVERS ADDRESSES """
        self.MAP_CLIENT = {}
        self.MAP_CLIENT[0] = self.Host('00:00:00:00:00:01', '10.0.0.1', 1)
        self.MAP_CLIENT[1] = self.Host('00:00:00:00:00:02', '10.0.0.2', 2)
        self.MAP_CLIENT[2] = self.Host('00:00:00:00:00:03', '10.0.0.3', 3)
        self.MAP_CLIENT[3] = self.Host('00:00:00:00:00:04', '10.0.0.4', 4)
        self.MAP_CLIENT[4] = self.Host('00:00:00:00:00:05', '10.0.0.5', 5)
        self.MAP_CLIENT[5] = self.Host('00:00:00:00:00:06', '10.0.0.6', 6)

        self.MAP_SERVER = {}
        self.MAP_SERVER[0] = self.Host('00:00:00:00:00:07', '10.0.0.7', 7)
        self.MAP_SERVER[1] = self.Host('00:00:00:00:00:08', '10.0.0.8', 8)
        self.MAP_SERVER[2] = self.Host('00:00:00:00:00:09', '10.0.0.9', 9)
        self.MAP_SERVER[3] = self.Host('00:00:00:00:00:10', '10.0.0.10', 10)
        self.MAP_SERVER[4] = self.Host('00:00:00:00:00:11', '10.0.0.11', 11)
        self.MAP_SERVER[5] = self.Host('00:00:00:00:00:12', '10.0.0.12', 12)
        self.getServer = 0


        # Listen to the connection
        connection.addListeners(self)

    def _handle_PortStatsReceived(self, event):
        log.info("Statistics: %s" % (str(flow_stats_to_list(event.stats))))

    def _handle_PacketIn(self, event):
        """ Handles packet in messages from the switch """
        packet = event.parse() # This is the parsed packet data.
        if packet.type == packet.ARP_TYPE:    # ARP request
            log.debug("Handling ARP Request")
            self.handle_ARP_request(packet, event)

        elif packet.type == packet.IP_TYPE:   # Service request
            log.debug("Handling Request Service")
            self.handle_IP_request(packet, event)

    def handle_ARP_request(self, packet, event):
        #Get ARP request from packet
        arp_request = packet.next
        # Build Ethernet ARP packet
        ethernet_packet = ethernet()
        ethernet_packet.type = ethernet.ARP_TYPE
        ethernet_packet.dst = packet.src

        ethernet_packet.src = NET_PROXY_MAC # Change ARP source to NETWORK_PROXY_MAC
        #We'r Mapping the source packet
        packet_from_client = False if map_list_mac(self.MAP_CLIENT, packet.src) is None else True

        #Create an ARP reply with NET_PROXY_MAC
        arp_reply = arp()
        arp_reply.opcode = arp.REPLY
        arp_reply.hwsrc = NET_PROXY_MAC
        arp_reply.hwdst = arp_request.hwsrc
        if packet_from_client == True:
            arp_reply.protosrc = NET_PROXY_IP # Set PROXY IP if is CLient source and server IP otherwise
        else:
            arp_reply.protosrc = arp_request.protodst
        arp_reply.protodst = arp_request.protosrc

        # ARP Reply is the packet payload
        ethernet_packet.set_payload(arp_reply)

        # Send the ARP Reply packet
        msg = of.ofp_packet_out()
        msg.data = ethernet_packet.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        msg.in_port = event.port
        log.debug("Sending ARP Reply packet")
        self.connection.send(msg)

    """ RoundRobbin Method to select new random server """
    def getNewServer(self):
        if self.selectedMehod == 0: #Selected round robbin or otherwise random method
            self.getServer = (self.getServer + 1) % len(self.MAP_SERVER)
            return self.MAP_SERVER[self.getServer]
        else:
            return random.choice(self.MAP_SERVER)

    def handle_IP_request(self, frame, event):
        """ Reply to the Pings """
        packet = frame.next

        """ Verify ICMP Reply packet """
        def icmp_reply(frame):
            if map_list_mac(self.MAP_SERVER, frame.src) is None:
                return False
            return True

        # Send any ICMP reply
        if icmp_reply(frame) == True:
            msg = of.ofp_packet_out()
            msg_dst = map_list_ip(self.MAP_CLIENT, packet.dstip)
            frame.src = NET_PROXY_MAC
            frame.dst = msg_dst.mac
            frame.next.srcip = NET_PROXY_IP
            msg.actions.append(of.ofp_action_output(port=msg_dst.port))
            msg.in_port = event.port
            log.debug("Sending any ICMP Packet Reply")
            self.connection.send(msg)
            return None

        server = self.getNewServer()

        #Match Rule from Server to Client
        msg = of.ofp_flow_mod()
        msg.idle_timeout = IDLE_TIMEOUT
        msg.hard_timeout = IDLE_TIMEOUT
        msg.match.in_port = server.port
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.dl_src = server.mac
        msg.match.dl_dst = NET_PROXY_MAC
        msg.match.nw_src = server.ip
        msg.match.nw_dst = packet.srcip

        log.debug("Selected Server from the Client %s -> %s" % (packet.srcip, server.ip))

        # Update IP & MAC Network Proxy if theres a match
        msg.actions.append(of.ofp_action_dl_addr.set_src(NET_PROXY_MAC))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(frame.src))
        msg.actions.append(of.ofp_action_nw_addr.set_src(NET_PROXY_IP))
        msg.actions.append(of.ofp_action_output(port=event.port))
        log.debug("Sending ICMP reply Server to Client ")
        self.connection.send(msg)

        #Match Rule from Client to Server
        msg = of.ofp_flow_mod()
        msg.idle_timeout = IDLE_TIMEOUT
        msg.hard_timeout = IDLE_TIMEOUT
        msg.data = event.ofp
        msg.match.in_port = event.port
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.dl_src = frame.src
        msg.match.dl_dst = NET_PROXY_MAC
        msg.match.nw_src = packet.srcip
        msg.match.nw_dst = NET_PROXY_IP

        # Update Selected Server IP & MAC
        msg.actions.append(of.ofp_action_dl_addr.set_dst(server.mac))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(server.ip))
        msg.actions.append(of.ofp_action_output(port=server.port))
        log.debug("Sending request Client to Server ")
        self.connection.send(msg)

""" Controller """
class load_balancer(object):
    def __init__(self):
        core.openflow.addListeners(self)

    """ New connection from switch """
    def _handle_ConnectionUp(self, event):
        log.debug("Switch connected" % ())
        # Create load balancer
        proxy_controller(event.connection)

def launch():
    core.registerNew(load_balancer)

