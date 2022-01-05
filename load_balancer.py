from pox.core import core    # the POX core object
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *    # event system
from pox.lib.util import dpidToStr
from pox.lib.packet.ethernet import ethernet    # handle ethernet
from pox.lib.packet.arp import arp    # handle arp
from pox.lib.addresses import IPAddr    # ip address
from pox.lib.addresses import EthAddr    # ethernet address
import time

log = core.getLogger()
IDLE_TIMEOUT = 10    #Seconds

"""
SWITCH ADDRESSES
"""
LOAD_BALANCER_IP = IPAddr('10.0.0.13')
LOAD_BALANCER_MAC = EthAddr('00:00:00:00:00:13')

def get_host_by_mac (hosts_list, mac):
	return next( (x for x in hosts_list.values() if str(x.mac) == str(mac)), None)

"""
Gets a host by its ip
"""
def get_host_by_ip (hosts_list, ip):
	return next( (x for x in hosts_list.values() if str(x.ip) == str(ip)), None)

class balancer (object):
    class Server:
        log.debug("Init Class Server")
        def __init__ (self, ip, mac, port):
            self.ip = IPAddr(ip)    # set the ip address
            self.mac = EthAddr(mac)    # set the mac address
            self.port = port

            def __str__(self):
                return','.join([str(self.ip), str(self.mac), str(self.port)])

    def __init__ (self, connection):
        self.connection = connection
        #self.listenTo(connection)
        connection.addListeners(self)

        # Initialize the server list
        self.clients = [
            self.Server('10.0.0.1', '00:00:00:00:00:01', 1),
            self.Server('10.0.0.2', '00:00:00:00:00:02', 2),
            self.Server('10.0.0.3', '00:00:00:00:00:03', 3),
            self.Server('10.0.0.4', '00:00:00:00:00:04', 4),
            self.Server('10.0.0.5', '00:00:00:00:00:05', 5),
            self.Server('10.0.0.6', '00:00:00:00:00:06', 6),
        ]

        # Initialize the server list
        self.servers = [
            self.Server('10.0.0.7', '00:00:00:00:00:07', 7),
            self.Server('10.0.0.8', '00:00:00:00:00:08', 8),
            self.Server('10.0.0.9', '00:00:00:00:00:09', 9),
            self.Server('10.0.0.10', '00:00:00:00:00:10', 10),
            self.Server('10.0.0.11', '00:00:00:00:00:11', 11),
            self.Server('10.0.0.12', '00:00:00:00:00:12', 12),
        ]
        self.last_server = 0

    def _handle_PortStatsReceived(self, event):
        log.info("Stats received: %s" % (str(flow_stats_to_list(event.stats))))

    def _handle_PacketIn(self, event):
        frame = event.parse()

        # ARP request
        if frame.type == frame.ARP_TYPE:
            log.debug("Handling ARP Request from %s" % (frame.next.protosrc))
            self.handler_arp(frame, event)
        # Service request
        elif frame.type == frame.IP_TYPE:
            log.debug("Handling Service request from %s" % (frame.next.srcip))
            self.handler_service(frame, event)

    def get_next_server(self):
        # Round-robin load the servers
        self.last_server = (self.last_server + 1) % len(self.servers)
        return self.servers[self.last_server]

    """
    An ARP reply with switch fake MAC has to be sent
    """

    def handler_arp (self, frame, event):
        eth_reply_msg = ethernet()
        eth_reply_msg.type = ethernet.ARP_TYPE
        eth_reply_msg.dst = frame.src
        # Switch fake MAC
        eth_reply_msg.src = LOAD_BALANCER_MAC

        arp_request_msg = frame.next

        arp_reply_msg = arp()
        arp_reply_msg.opcode = arp.REPLY
        # Switch fake MAC
        arp_reply_msg.hwsrc = LOAD_BALANCER_MAC
        arp_reply_msg.hwdst = arp_request_msg.hwsrc
        # Transparent proxy IP
        arp_reply_msg.protosrc = LOAD_BALANCER_IP

        # Encapsulate
        eth_reply_msg.set_payload(arp_reply_msg)

        # Send OF msg to output ARP packet
        msg = of.ofp_packet_out()
        msg.data = eth_reply_msg.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        msg.in_port = event.port
        log.debug("Sending OFP ARP Packet Out" % ())

        log.info("msg ->")
        log.info(msg)

        self.connection.send(msg)


    def handler_service(self, frame, event):
        server = self.get_next_server()
        packet = frame.next

        # Server -> Client path
        msg = of.ofp_flow_mod()
        msg.idle_timeout = IDLE_TIMEOUT
        msg.hard_timeout = IDLE_TIMEOUT
        # Packets coming from the chosen server
        msg.match.in_port = server.port
        # Rule only for IP packets (service)
        msg.match.dl_type = ethernet.IP_TYPE
        # Ethernet src address matching the MAC of the chosen server
        msg.match.dl_src = server.mac
        # Ethernet dst address matching the Switch fake MAC
        msg.match.dl_dst = LOAD_BALANCER_MAC
        # Network src address matching the IP of the chosen server
        msg.match.nw_src = server.ip
        # Network dst address matching the IP of the client
        msg.match.nw_dst = packet.srcip

        log.debug("Chosen server for %s is %s" % (packet.srcip, server.ip))

        #UPDATE IP AND MAC FROM LOADBALANCER.IP AND .MAC
        msg.actions.append(of.ofp_action_nw_addr.set_src(LOAD_BALANCER_IP))
        msg.actions.append(of.ofp_action_dl_addr.set_src(LOAD_BALANCER_MAC))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(frame.src))

        # - Forward to the client
        msg.actions.append(of.ofp_action_output(port=event.port))
        # Send OF msg to update flow rules
        log.debug("Sending OFP FlowMod Server -> Client path" % ())
        self.connection.send(msg)

        # Client -> Server path
        msg = of.ofp_flow_mod()
        msg.idle_timeout = IDLE_TIMEOUT
        msg.hard_timeout = IDLE_TIMEOUT
        msg.data = event.ofp
        # Packets coming from the client
        msg.match.in_port = event.port
        # Rule only for IP packets (service)
        msg.match.dl_type = ethernet.IP_TYPE
        # Ethernet src address matching the MAC of the client
        msg.match.dl_src = frame.src
        # Ethernet dst address matching the MAC of the proxy
        msg.match.dl_dst = LOAD_BALANCER_MAC
        # Network src address matching the IP of the client
        msg.match.nw_src = packet.srcip
        # Network dst address matching the IP of the proxy
        msg.match.nw_dst = LOAD_BALANCER_IP

        # - Update the src IP and MAC to the chosen server
        msg.actions.append(of.ofp_action_dl_addr.set_dst(server.mac))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(server.ip))
        # - Forward to the chosen server
        msg.actions.append(of.ofp_action_output(port=server.port))
        # Send OF msg to update flow rules
        log.debug("Sending OFP FlowMod Client -> Server path" % ())
        self.connection.send(msg)

"""
Controller
"""
class load_balancer (object):
    def __init__(self):
        # Add listeners
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        log.debug("Switch connected" % ())
        # Create load balancer
        balancer(event.connection)

def launch ():
	core.registerNew(load_balancer)