import os
import socket
import time
import threading
from models.arp.ARPTable import ARPTable
from models.routing.RoutingTable import RoutingTable
from IPPacket import IPPacket
from EthernetFrame import EthernetFrame
from models.util import print_brk, print_command_not_found, print_network_int_help, clean_ethernet_payload, clean_ip_payload
from models.constants import PROTOCOL
from config import HOST
import traceback

class NetworkInterface:
  device_name = None
  network_int_address = None
  network_int_ip_address = None
  network_int_ip_prefix = None
  router_interface_address = None
  network_int_socket = None

  network_int_relay_addresses: list[tuple] = []
  failed_network_relays: list[tuple] = []

  max_connections = 0
  arp_table = ARPTable()
  network_int_arp_table = ARPTable()
  routing_table = RoutingTable()

  # to keep track of which IP to assign MAC to
  arp_last_broadcasted_ip = None
  arp_table_ip_last_updated = None
  arp_response = False

  def __init__(
    self,
    device_name: str,
    network_int_ip_address: str,
    router_interface_address: str,
    network_int_port: int,
    max_connections: int,
    network_int_relay_addresses: list[tuple] = [],
    network_int_host: str = HOST
  ):
    self.device_name = device_name
    self.network_int_address = (network_int_host, network_int_port)
    self.network_int_ip_address = network_int_ip_address
    self.network_int_ip_prefix = network_int_ip_address[:3]
    self.router_interface_address = router_interface_address
    self.max_connections = max_connections
    self.network_int_relay_addresses = network_int_relay_addresses

    self.network_int_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.network_int_socket.bind(self.network_int_address)

  def get_available_ip_address(self):
    assigned_ip_addresses = self.arp_table.get_used_ip_addresses()
    for i in range(self.max_connections):
      check_ip = f"0x{(int(self.network_int_ip_address, 0) + 9 + i):X}"
      if not (check_ip in assigned_ip_addresses):
        return check_ip
    return False

  def provide_node_connection_data(self, corresponding_socket: socket.socket) -> tuple[str, str]:
    assigned_ip_address = self.get_available_ip_address()
    data = f"{assigned_ip_address}|{self.router_interface_address}"
    corresponding_socket.send(bytes("provide_node_connection_data" ,"utf-8"))
    time.sleep(1)
    corresponding_socket.send(bytes(f"{data}" ,"utf-8"))
    time.sleep(1)
    corresponding_socket.send(bytes("provide_node_connection_data_completed" ,"utf-8"))
    time.sleep(1)
    return assigned_ip_address, self.router_interface_address

  def request_mac_address(self, corresponding_socket: socket.socket) -> str:
    corresponding_socket.send(bytes("request_mac_address" ,"utf-8"))
    while True:
      message = corresponding_socket.recv(1024).decode("utf-8")
      if (message == "request_mac_address_completed"):
        break
      response_mac_address = message
    
    return response_mac_address

  def destroy_arp_connections(self, ip_address: str, mac_address: str) -> None:
    is_destroyed = self.arp_table.destroy_arp_connection(ip_address, mac_address)
    if not is_destroyed:
      self.network_int_arp_table.destroy_arp_connection(ip_address, mac_address)
    return

  def node_connection_response(self, corresponding_socket: socket.socket) -> tuple[str, str]:
    print(f"Node connection request received.")
    print(f"Assigning free IP address")
    assigned_ip_address, _ = self.provide_node_connection_data(corresponding_socket)

    print(f"Requesting MAC address")
    response_mac_address = self.request_mac_address(corresponding_socket)

    print(f"Updating ARP tables")
    self.arp_table.update_arp_table(assigned_ip_address, response_mac_address, corresponding_socket)

    print(f"Connection established")
    print_brk()
    return assigned_ip_address, response_mac_address

  def broadcast_ethernet_frame_data(self, ethernet_frame: EthernetFrame, is_broadcast_channel: bool = False):
    print("Broadcasting ethernet frame to connected MACs")
    arp_records = self.arp_table.get_all_arp_records()
    for arp_record in arp_records:
      if is_broadcast_channel:
        ethernet_frame.destination = arp_record["mac"]
      arp_record["corresponding_socket"].send(bytes(ethernet_frame.dumps(), "utf-8"))
    print("Ethernet frame broadcasted.")

  def route_ip_packet_data(self, ip_packet: IPPacket):
    print("Checking IP packet destination")
    ip_prefix = ip_packet.dest_ip_prefix()
    
    if ip_prefix == self.network_int_ip_prefix:
      print("Broadcasting encapsulated IP packets to connected nodes")
      dest_mac = None
      is_broadcast_channel = ip_packet.is_broadcast_address()
      if not is_broadcast_channel:
        dest_mac = self.arp_table.get_corresponding_mac(ip_packet.destination)
      ethernet_frame_with_headers: EthernetFrame = ip_packet.to_eth_frame(dest_mac, self.router_interface_address)
      self.broadcast_ethernet_frame_data(ethernet_frame_with_headers, is_broadcast_channel)

    else:
      print("Destination not in LAN.")
      print("Routing packet to LAN with destination prefix")
      next_hop_prefix = self.routing_table.get_next_hop_prefix(ip_prefix)
      if next_hop_prefix:
        corresponding_socket = self.network_int_arp_table.get_corresponding_socket_from_prefix(next_hop_prefix)
        corresponding_socket.send(bytes(ip_packet.dumps(), "utf-8"))
        print("IP packet routed")
      else:
        print("Failed to locate next hop")
        print("Failed to route IP packet")

  def handle_ethernet_frame(self, ethernet_frame: EthernetFrame, corresponding_socket: socket.socket) -> None:
    if ethernet_frame.destination == self.router_interface_address and ethernet_frame.data.data == "arp_response":
      self.arp_response = True
      print(f"ARP response received, updating ARP table for {self.arp_last_broadcasted_ip}...")

      self.arp_table.update_arp_table(
        self.arp_last_broadcasted_ip,
        ethernet_frame.source,
        corresponding_socket
      )
      self.arp_table_ip_last_updated = self.arp_last_broadcasted_ip
      self.arp_last_broadcasted_ip = None
      print("ARP table successfully updated.")

    else:
      payload = ethernet_frame.dumps()
      print("Ethernet frame received: ", payload)
      self.broadcast_ethernet_frame_data(ethernet_frame)

  def handle_ip_packet(self, ip_packet: IPPacket, corresponding_socket: socket.socket) -> None:
    payload = ip_packet.dumps()
    print("IP packet received: ", payload)

    if ip_packet.destination == self.network_int_ip_address:
      print(f"Intended recipient...")

      if ip_packet.protocol == PROTOCOL["ROUTE_ADD"]:
        print("New route received.")
        print(f"Adding new route to routing table")
        update_prefix, cost, exclusion_ips = ip_packet.get_route_add_data()
        self.routing_table.extend_entry(ip_packet.source[:3], update_prefix, int(cost))
        print("Broadcasting path to neighbouring interfaces")
        self.broadcast_route_add(update_prefix, int(cost), exclusion_ips)
        print("Routing table updated. [Success]")
      
      elif ip_packet.protocol == PROTOCOL["ROUTE_REMOVE"]:
        print(f"Removing new route to routing table")
        update_prefix, exclusion_ips = ip_packet.get_route_remove_data()
        self.routing_table.remove_entire_entry(update_prefix)
        print("Broadcasting removal to neighbouring interfaces")
        self.broadcast_route_remove(update_prefix, exclusion_ips)
        print("Routing table updated. [Success]")

    else:
      self.route_ip_packet_data(ip_packet)


  def listen(self, corresponding_socket: socket.socket, ip_address: str, mac_address: str, config_address: tuple = None):
    while True:
      try:
        data = corresponding_socket.recv(1024)
        if not data:
          print(f"Connection terminated from IP address of {ip_address} and MAC of {mac_address}.")
          print(f"Closing corresponding connections")
          if config_address and config_address in self.network_int_relay_addresses:
            self.failed_network_relays.append(config_address)
          corresponding_socket.close()
          print(f"Unassigning IP address from ARP and routing tables")
          self.destroy_arp_connections(ip_address, mac_address)
          if (ip_address[:3] != self.network_int_ip_prefix):
            self.routing_table.remove_entire_entry(ip_address[:3])
            self.broadcast_route_remove(ip_address[:3], [])
          print(f"Connection to {mac_address} terminated")
          print_brk()
          return

        payload = data.decode("utf-8")
        payload_segments = payload.split("|")
        is_valid_payload = len(payload_segments) > 1

        if is_valid_payload:
          if payload[:2] != "0x":
            ethernet_frame = EthernetFrame.loads(payload)
            self.handle_ethernet_frame(ethernet_frame, corresponding_socket)
            
          elif payload[:2] == "0x":
            ip_packet = IPPacket.loads(payload)
            self.handle_ip_packet(ip_packet, corresponding_socket)
        
        print_brk()

      except ConnectionResetError as cre:
        print(f"Connection terminated from IP address of {ip_address} and MAC of {mac_address}.")
        print(f"Closing corresponding connections")
        corresponding_socket.close()
        if config_address and config_address in self.network_int_relay_addresses:
          self.failed_network_relays.append(config_address)
        print(f"Unassigning IP address from ARP and routing tables")
        self.destroy_arp_connections(ip_address, mac_address)
        if (ip_address[:3] != self.network_int_ip_prefix):
          self.routing_table.remove_entire_entry(ip_address[:3])
          self.broadcast_route_remove(ip_address[:3], [])
        print(f"Connection to {mac_address} terminated")
        print_brk()
        return

      except:
        traceback.print_exc()
        print_brk()
        corresponding_socket.close()
        os._exit(0)

  def provide_network_int_connection_data(self, corresponding_socket: socket.socket):
    data = f"{self.network_int_ip_address}|{self.router_interface_address}|{self.routing_table.dumps()}"
    corresponding_socket.send(bytes(f"provide_network_int_connection_data" ,"utf-8"))
    time.sleep(1)
    corresponding_socket.send(bytes(f"{data}" ,"utf-8"))
    time.sleep(1)
    corresponding_socket.send(bytes(f"provide_network_int_connection_data_completed" ,"utf-8"))
    time.sleep(1)
    return

  def receive_network_int_connection_data(self, corresponding_socket: socket.socket) -> list[str]:
    ip_received = None
    mac_received = None

    while True:
      data = corresponding_socket.recv(1024).decode('utf-8')
      if data == f"provide_network_int_connection_data_completed":
        break
      
      data = data.split("|")
      if (len(data) > 1): 
        ip_received, mac_received, routing_table_dump = data

    print(f"Connection interaface's IP address of {ip_received} and MAC of {mac_received} received.")
    return ip_received, mac_received, routing_table_dump
  
  def network_int_connection_request(self, corresponding_socket: socket.socket, is_reconnection: bool = False) -> tuple[str, str]:
    corresponding_socket.send(bytes("network_int_connection_request", "utf-8"))
    corresponding_ip_address = None
    corresponding_mac_address = None
    data_provided = False
    print("Connecting to network interface...")

    while (corresponding_ip_address is None) or (corresponding_mac_address is None) or not data_provided:
      data = corresponding_socket.recv(1024)
      if not data:
        print_brk()
        print("Connection from network interface terminated prematurely.") # Network interface connection ends before ARP established
        print(f"Closing corresponding connections")
        corresponding_socket.close()
        print(f"Unassigning IP address from ARP tables")
        if corresponding_ip_address:
          self.destroy_arp_connections(corresponding_ip_address)
          self.routing_table.remove_entire_entry(corresponding_ip_address[:3])
          #self.broadcast_route_remove(ip_address[:3], [])
        print(f"Connection terminated. [Completed]")
        print_brk()
        return corresponding_ip_address, corresponding_mac_address # End thread

      message = data.decode('utf-8')
      if (message == "provide_network_int_connection_data"):
        print(f"Receiving connection interface's IP address, MAC and routing dumps")
        corresponding_ip_address, corresponding_mac_address, routing_table_dump = self.receive_network_int_connection_data(corresponding_socket)

      elif (message == "request_network_int_connecting_data"):
        print(f"Providing connecting data")
        data_provided = self.provide_network_int_connecting_data(corresponding_socket, is_reconnection)
    
    print(f"Updating ARP and routing tables")
    self.network_int_arp_table.update_arp_table(corresponding_ip_address, corresponding_mac_address, corresponding_socket)
    self.routing_table.loads(self.network_int_ip_prefix, corresponding_ip_address[:3], routing_table_dump)
    print(f"Connected to network interface")
    print_brk()
    return corresponding_ip_address, corresponding_mac_address
  
  def request_network_int_connecting_data(self, corresponding_socket: socket.socket) -> list[str]:
    corresponding_socket.send(bytes(f"request_network_int_connecting_data" ,"utf-8"))
    while True:
      message = corresponding_socket.recv(1024).decode('utf-8')
      if message == f"provide_network_int_connecting_data_completed":
        break
      data = message.split("|")
    print(f"Connecting interface's IP address of {data[0]} and MAC of {data[1]} received.")
    return data
  
  def provide_network_int_connecting_data(self, corresponding_socket: socket.socket, is_reconnection: bool = False):
    '''
      If network interface is reconnecting, we need to provide existing routing tables.
    '''
    data = f"{self.network_int_ip_address}|{self.router_interface_address}"
    if is_reconnection:
      data += f"|{self.routing_table.dumps()}"
    corresponding_socket.send(bytes(f"{data}" ,"utf-8"))
    time.sleep(1)
    corresponding_socket.send(bytes(f"provide_network_int_connecting_data_completed" ,"utf-8"))
    time.sleep(1)
    print(f"Connecting data provided.")
    return True

  def broadcast_route_add(self, prefix_to_add: str, cost: int = 0, exclusion_ips: list[str] = []):
    ip_addresses = self.network_int_arp_table.get_all_ip_addresses()
    broadcast_ips = list(filter(lambda ip_address: (not ip_address in exclusion_ips) and prefix_to_add != ip_address[:3], ip_addresses))
    exclusion_ips.extend(broadcast_ips)

    if not (self.network_int_ip_address in exclusion_ips):
      exclusion_ips.append(self.network_int_ip_address)
    exclusion_ips_payload = f"{'/'.join(exclusion_ips)}"

    for ip_address in broadcast_ips:
      payload = f"{prefix_to_add}:{cost + 1}:{exclusion_ips_payload}"
      ip_packet = IPPacket(ip_address, self.network_int_ip_address, PROTOCOL["ROUTE_ADD"], payload)
      self.network_int_arp_table.get_corresponding_socket(ip_address).send(bytes(ip_packet.dumps(),"utf-8"))

  def broadcast_route_remove(self, prefix_to_remove: str, exclusion_ips: list[str] = []):
    ip_addresses = self.network_int_arp_table.get_all_ip_addresses()
    broadcast_ips = list(filter(lambda ip_address: (not ip_address in exclusion_ips) and prefix_to_remove != ip_address[:3], ip_addresses))
    exclusion_ips.extend(broadcast_ips)

    if not (self.network_int_ip_address in exclusion_ips):
      exclusion_ips.append(self.network_int_ip_address)
    exclusion_ips_payload = f"{'/'.join(exclusion_ips)}"

    for ip_address in broadcast_ips:
      payload = f"{prefix_to_remove}:{exclusion_ips_payload}"
      ip_packet = IPPacket(ip_address, self.network_int_ip_address, PROTOCOL["ROUTE_REMOVE"], payload)
      self.network_int_arp_table.get_corresponding_socket(ip_address).send(bytes(ip_packet.dumps(),"utf-8"))

  def network_int_connection_response(self, corresponding_socket: socket.socket) -> tuple[str, str]:
    print(f"Network interface connection request received.")
    print(f"Providing own IP address and MAC... [1/4]")
    self.provide_network_int_connection_data(corresponding_socket)

    print(f"Requesting connecting interface's IP address and MAC... [2/4]")
    data = self.request_network_int_connecting_data(corresponding_socket)
    if len(data) > 2: # This is a reconnection request
      connecting_ip_address, connecting_mac, routing_table_dump = data
      self.routing_table.loads(self.network_int_ip_prefix, connecting_ip_address[:3], routing_table_dump)
    else:
      connecting_ip_address, connecting_mac = data
      self.routing_table.create_entry(connecting_ip_address[:3])

    print(f"Broadcasting new routes to connected interfaces... [3/4]")
    self.broadcast_route_add(connecting_ip_address[:3], cost=0, exclusion_ips=[])

    print(f"Updating ARP and routing tables... [4/4]")
    self.network_int_arp_table.update_arp_table(connecting_ip_address, connecting_mac, corresponding_socket)

    print(f"Connection established. [Completed]")
    print_brk()
    return connecting_ip_address, connecting_mac

  def handle_connection(self, corresponding_socket: socket.socket):
    ip_address = None

    try:
      while True:
        data = corresponding_socket.recv(1024)
        if not data:
          print("Connection from node terminated prematurely.") # Node connection ends before ARP established
          print(f"Closing corresponding connections... [1/2]")
          corresponding_socket.close()
          print(f"Unassigning IP address from ARP tables... [2/2]")
          if ip_address:
            self.destroy_arp_connections(ip_address)
            self.routing_table.remove_entire_entry(ip_address[:3])
            self.broadcast_route_remove(ip_address[:3], [])
          print(f"Connection terminated. [Completed]")
          print_brk()
          return

        message = data.decode("utf-8")
        if message == "node_connection_request":
          ip_address, mac_address = self.node_connection_response(corresponding_socket)
          break
        elif message == "network_int_connection_request":
          ip_address, mac_address = self.network_int_connection_response(corresponding_socket)
          break

    except ConnectionResetError:
      print("Connection reset error in handle_connection")
      return
    
    self.listen(corresponding_socket, ip_address, mac_address)

  def handle_network_int_connection(self, corresponding_socket: socket.socket, config_address: tuple, is_reconnection: bool = False) -> None:
    ip_address, mac_address = self.network_int_connection_request(corresponding_socket, is_reconnection)
    if ip_address and mac_address:
      threading.Thread(target=self.listen, args=(corresponding_socket, ip_address, mac_address, config_address, )).start()

  def reconnect(self):
    if len(self.failed_network_relays) == 0:
      print("No failed connections to reconnect to.")
      return
    for address in self.failed_network_relays:
      corresponding_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      try:
        corresponding_socket.connect(address)
        self.handle_network_int_connection(corresponding_socket, address, is_reconnection=True)
        self.failed_network_relays.remove(address)
      except ConnectionRefusedError:
        print(f"Unable to connect to the network interface with address: {address}.")
    if len(self.failed_network_relays) != 0:
      print('Enter "reconnect" to attempt to reconnect to failed network interface connections after turning them on.')
    else:
      print("Successfully reconnected to all failed connections.")

  def handle_input(self):
    while True:
      network_int_input = input()
      if network_int_input == "quit" or network_int_input == "q":
        print("Terminating network interface and all existing connections...")
        connected_sockets = self.arp_table.get_all_sockets() + self.network_int_arp_table.get_all_sockets()
        for corresponding_socket in connected_sockets:
          corresponding_socket.close()
        print(f"Network interface {self.network_int_ip_address} terminating.")
        os._exit(0)

      elif network_int_input == "whoami":
        print_brk()
        print(f"{self.device_name} interface's address is {self.network_int_address}")
        print(f"{self.device_name} interface's IP address is {self.network_int_ip_address}")
        print(f"{self.device_name} interface's MAC address is {self.router_interface_address}")
        print(f"{self.device_name} interface's relay addresses are {self.network_int_relay_addresses}")
        print_brk()


      elif network_int_input == "broadcast":
        print_brk()
        self.broadcast_arp_query()

      elif network_int_input == "help" or network_int_input == "h":
        print_network_int_help()

      elif network_int_input == "arp":
        print("Displaying all ARP tables...")
        print("> ARP tables for with connected nodes (IP:MAC).")
        self.arp_table.pprint()
        print("> ARP tables for with connected network interfaces (IP:MAC).")
        self.network_int_arp_table.pprint()
        print_brk()
      
      elif network_int_input == "arp -n":
        print("Displaying ARP tables with connected nodes (IP:MAC)...")
        self.arp_table.pprint()
        print_brk()

      elif network_int_input == "arp -r":
        print("Displaying ARP tables with connected network interfaces (IP:MAC)...")
        self.network_int_arp_table.pprint()
        print_brk()

      elif network_int_input == "ip route":
        print("Displaying IP routing tables with connected network interfaces (IP Prefix:Connected Prefixes)...")
        self.routing_table.pprint()
        print_brk()

      elif network_int_input == "reconnect":
        print(f"Attempting to reconnect to the following network interfaces {self.failed_network_relays}...")
        self.reconnect()
        print_brk()
      
      else:
        print_command_not_found(device = "network_interface")
  
  def broadcast_arp_query(self):
    self.arp_response = False

    target_ip = input("What is the IP address of the MAC you wish to get.\n> ")
    self.arp_last_broadcasted_ip = target_ip
    print("Broadcasting ARP query to all nodes in the same LAN...")
    connected_sockets = self.arp_table.get_all_sockets()
    
    while not self.arp_response: 
      try:
        for connected_socket in connected_sockets:
          connected_socket.send(bytes(f"Who has IP: {target_ip}, I am {self.router_interface_address}", "utf-8"))
        time.sleep(2)

      except OSError:
        print("OS Error in broadcast_arp_query")
        return
      except UnboundLocalError:
        print("UnboundLocalError in broadcast_arp_query")
        return

  def receive_connections(self):
    self.network_int_socket.listen(self.max_connections)
    while True:
      corresponding_socket, corresponding_address = self.network_int_socket.accept()
      threading.Thread(target=self.handle_connection, args=(corresponding_socket, )).start()

  def run(self):
    print_brk()
    print(f"{self.device_name} interface starting with mac {self.router_interface_address} and ip address of {self.network_int_ip_address}...")
    print_brk()
    if (len(self.network_int_relay_addresses) != 0):
      print("Connecting to configured network interfaces...")
      print_brk()
      for address in self.network_int_relay_addresses:
        corresponding_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
          corresponding_socket.connect(address)
          self.handle_network_int_connection(corresponding_socket, address)
        except ConnectionRefusedError:
          print(f"Unable to connect to the network interface with address: {address}.")
          self.failed_network_relays.append(address)
      if (len(self.failed_network_relays) != 0):
        print('Enter "reconnect" to attempt to reconnect to failed network interface connections after turning them on.')
        print_brk()
  
    try:
      threading.Thread(target=self.receive_connections).start()
      print_network_int_help(False)
      self.handle_input()

    except:
      traceback.print_exc()
      print_brk()
      print(f"{self.device_name} interface {self.network_int_ip_address} terminating.")
      print_brk()
      os._exit(0)