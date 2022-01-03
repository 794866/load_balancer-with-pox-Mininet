
m pox.core import core
import pox.lib.packet as libpacket
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
from pox.openflow.of_json import *
import random
import threading

log = core.getLogger()


class Host (object):
	def __init__ (self, ip, mac, port):
		self.ip = ip
		self.mac = mac
		self.port = port
		self.req_n = 0

CL_HOSTS={}
SV_HOSTS={}

"""
Initialization Client Hosts
"""
CL_HOSTS[0]= Host(IPAddr('10.0.0.1'), EthAddr('00:00:00:00:00:01'), 1)
CL_HOSTS[1]= Host(IPAddr('10.0.0.2'), EthAddr('00:00:00:00:00:02'), 2)
CL_HOSTS[2]= Host(IPAddr('10.0.0.3'), EthAddr('00:00:00:00:00:03'), 3)
CL_HOSTS[3]= Host(IPAddr('10.0.0.4'), EthAddr('00:00:00:00:00:04'), 4)
CL_HOSTS[4]= Host(IPAddr('10.0.0.5'), EthAddr('00:00:00:00:00:05'), 5)
CL_HOSTS[5]= Host(IPAddr('10.0.0.6'), EthAddr('00:00:00:00:00:06'), 6)

"""
Initialization Servers Proxy Hosts
"""
SV_HOSTS[0]= Host(IPAddr('10.0.0.7'), EthAddr('00:00:00:00:00:07'), 7)
SV_HOSTS[1]= Host(IPAddr('10.0.0.8'), EthAddr('00:00:00:00:00:08'), 8)
SV_HOSTS[2]= Host(IPAddr('10.0.0.9'), EthAddr('00:00:00:00:00:09'), 9)
SV_HOSTS[3]= Host(IPAddr('10.0.0.10'), EthAddr('00:00:00:00:00:10'), 10)
SV_HOSTS[4]= Host(IPAddr('10.0.0.11'), EthAddr('00:00:00:00:00:11'), 11)
SV_HOSTS[5]= Host(IPAddr('10.0.0.12'), EthAddr('00:00:00:00:00:12'), 12)

"""
Controller
"""
class load_balancer (object):
	def __init__ (self):
		self.listenTo(core.openflow)

	def _handle_ConnectionUp (self, event):
		log.debug("Connection %s" % event.connection)
    		LoadBalancer(event.connection)

class proxy_load_balancer (object):
	"""
		ALL PROXY CLASS
	"""

def launch ():
	core.registerNew(load_balancer) #load balancer
