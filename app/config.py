HOST = "localhost"
ROUTER_INT1_PORT = 8001
ROUTER_INT2_PORT = 8002
ROUTER_INT3_PORT = 8003
ROUTER_INT4_PORT = 8004
VPN_SERVER_PORT = 8005
ROUTER_INT5_PORT = 8006
PROTECTED_SERVER_PORT = 8007

DNS_SERVER_PREFIX = "0x3"

ROUTER_INT1_CONFIG = {
  "device_name": "Router",
  "network_int_ip_address": "0x11",
  "router_interface_address": "R1",
  "network_int_port": ROUTER_INT1_PORT,
  "max_connections": 5
}

NODE1_CONFIG = {
  "device_name": "Node",
  "node_mac": "N1",
  "router_interface_address": "R1", 
  "network_int_port": ROUTER_INT1_PORT,
  "dns_server_prefix": DNS_SERVER_PREFIX
}

ROUTER_INT2_CONFIG = {
  "device_name": "Router",
  "network_int_ip_address": "0x21",
  "router_interface_address": "R2",
  "network_int_port": ROUTER_INT2_PORT,
  "max_connections": 5,
  "network_int_relay_addresses": [(HOST, ROUTER_INT1_PORT)]
}

NODE2_CONFIG = {
  "device_name": "Node",
  "node_mac": "N2",
  "router_interface_address": "R2", 
  "network_int_port": ROUTER_INT2_PORT,
  "dns_server_prefix": DNS_SERVER_PREFIX
}

NODE3_CONFIG = {
  "device_name": "Node",
  "node_mac": "N3",
  "router_interface_address": "R2", 
  "network_int_port": ROUTER_INT2_PORT,
  "dns_server_prefix": DNS_SERVER_PREFIX,
}


# DNS_SERVER_CONFIG = {
#   "device_name": "DNS Server",
#   "node_mac": "N4",
#   "router_interface_address": "R3", 
#   "network_int_port": ROUTER_INT3_PORT,
#   "dns_records": [
#     {
#       "domain_name": "N1.com",
#       "ip_address": "0x1A"
#     }, {
#       "domain_name": "www.N2.com",
#       "ip_address": "0x2A"
#     }, {
#       "domain_name": "N3.com",
#       "ip_address": "0x2B"
#     }
#   ]
# }