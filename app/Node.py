import os
import socket
import time
import threading
import traceback
import json
from typing import List
from EthernetFrame import EthernetFrame
from IPPacket import IPPacket
from ARPTable import ARPTable
from Firewall import Firewall
from Sniffer import Sniffer
from Ping import Ping
from Log import Log
from Kill import Kill
from constants import PROTOCOL
from util import print_brk, print_node_help, print_command_not_found, print_error, input_ip_sequence, is_valid_domain_name
from config import HOST
from MitMAttack import MitMAttack


class Node:
  device_name = None
  node_ip_address = None # Assigned by router  - See NetworkInterface.nodeConnection()
  node_mac = None

  network_interface_address = None
  router_interface_address = None
  network_interface_socket = None

  arp_table = ARPTable()
  dns_table = None
  dns_server_prefix = None
  firewall = Firewall()
  ping_protocol = Ping()
  kill_protocol = Kill()
  sniffer = Sniffer()
  mitm_attack = None # for mitm

  def __init__(
    self,
    device_name: str,
    node_mac: str,
    router_interface_address: str,
    network_int_port: int,
    network_int_host: str = HOST,
    dns_server_prefix: str = None,
  ):
    self.device_name = device_name
    self.node_mac = node_mac
    self.network_interface_address = (network_int_host, network_int_port)
    self.router_interface_address = router_interface_address
    self.network_interface_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.dns_server_prefix = dns_server_prefix
    self.mitm_attack = MitMAttack(self) # for mitm

  def ICMP_Packet(self, dest_ip: str) -> IPPacket:
      # Create an ICMP echo request packet
      icmp_data = {
          "type": PROTOCOL["ICMP_TYPE_ECHO_REQUEST"],
          "code": 0,  # Assuming code is 0 for echo request
          # Other ICMP data fields as needed
          "identifier": 1234,  # Identifier to match requests with replies
          "sequence_number": 1,  # Sequence number for distinguishing requests
          "checksum": 0,  # Placeholder for checksum calculation
          "timestamp": 1234567890,  # Timestamp indicating when packet was sent
          "data": "Hello, world!"
      }

      # Construct the ICMP packet with the destination IP address and ICMP data
      icmp_packet = IPPacket(self.node_ip_address, dest_ip, PROTOCOL["ICMP"], icmp_data)

      return icmp_packet

  def nodeConnection(self):
    print("Waiting for node connection data")
    assigned_ip_address = None
    router_interface_address = None

    while True:
      data = self.network_interface_socket.recv(1024).decode('utf-8')
      if data == "provide_node_connection_data_completed":
        break
      
      data = data.split("|")
      if (len(data) > 1): 
        assigned_ip_address, router_interface_address = data
    
    print(f"IP address: {assigned_ip_address} is assigned.")
    print(f"Updating the ARP tables")
    self.arp_table.update_arp_table(assigned_ip_address, router_interface_address, self.network_interface_socket)
    self.node_ip_address = assigned_ip_address
    return self.node_ip_address, router_interface_address

  def MacAddress(self):
    print("Sending MAC address")
    self.network_interface_socket.send(bytes(f"{self.node_mac}" ,"utf-8"))
    time.sleep(1)
    self.network_interface_socket.send(bytes(f"request_mac_address_completed" ,"utf-8"))
    print(f"{self.device_name} MAC {self.node_mac} sent.")
    return True

  def node_connection_request(self):
    self.network_interface_socket.send(bytes("node_connection_request", "utf-8"))
    ip_assigned = False
    mac_provided = False

    while not ip_assigned or not mac_provided:
      message = self.network_interface_socket.recv(1024).decode('utf-8')
      if (message == "provide_node_connection_data"):
        ip_assigned, _ = self.nodeConnection()

      elif (message == "request_mac_address"):
        mac_provided = self.MacAddress()

    print(f"Connection established with router's network interface with MAC of {self.router_interface_address}.")
    print(f"{self.device_name} connection request is completed.")
    print_brk()
    return

  def EthernetFrame(self, ethernet_frame: EthernetFrame, corresponding_socket: socket.socket) -> None:
    if self.mitm_attack.is_attack_active: # for mitm
        # Check if the source or destination of the frame is one of the victims.
        if ethernet_frame.source in ["N1", "N3"] and ethernet_frame.destination in ["N1", "N3"]:
            print(f"MitM: Intercepting and forwarding a frame from {ethernet_frame.source} to {ethernet_frame.destination}")
            # Here the frame can be modified if necessary before forwarding
            self.mitm_attack.execute_attack(ethernet_frame, corresponding_socket)
    # ---------------------------------------------------------------

    if ethernet_frame.is_recipient(self.node_mac):
      print("Intended recipient is retrieving data")

      if ethernet_frame.data.protocol and ethernet_frame.data.protocol[0] == PROTOCOL["PING"]:
        self.ping_protocol.handle_ping(ethernet_frame, corresponding_socket)

      elif ethernet_frame.data.protocol and ethernet_frame.data.protocol[0] == PROTOCOL["LOG"]:
        Log.log(ethernet_frame)

      elif ethernet_frame.data.protocol and ethernet_frame.data.protocol[0] == PROTOCOL["KILL"]:
        self.kill_protocol.kill(self.arp_table)

      elif ethernet_frame.data.protocol and ethernet_frame.data.protocol[0] == PROTOCOL["DNS_QUERY"]:
        self.handle_dns_response(ethernet_frame)

      elif ethernet_frame.data.protocol and ethernet_frame.data.protocol[0] == PROTOCOL["ETH"]:
        print(f"Ethernet frame data: {ethernet_frame.data.data}")

    elif self.sniffer.is_sniffing:
      print("Sniffing enabled")
      sniffed_data = ethernet_frame.data.data
      if self.sniffer.is_dns_spoofing:
        try:
          sniffed_data = json.loads(ethernet_frame.data.data) # type dict

          # Capture and check if it is domain name to attack
          domain_name = sniffed_data["domain_name"]

          # # Resolve ip in malicious table and assign to malicious ip
          # malicious_payload = self.malicious_dns_table.resolve(domain_name)
          # if (
          #     malicious_payload is None or 
          #     ethernet_frame.data.dest_ip == self.node_ip_address or
          #     ethernet_frame.data.src_ip == self.node_ip_address
          #   ):
          #   pass
          # else:
          #   malicious_ip_address = malicious_payload["ip_address"]
          #   print(f"DNS response prepared with DNS record of {malicious_payload}.")
          #   ip_packet = IPPacket(ethernet_frame.data.dest_ip, malicious_ip_address, PROTOCOL["DNS_QUERY"], json.dumps(malicious_payload))
          #   self.send_ip_packet(ip_packet, corresponding_socket, has_bottom_break=False)

        except json.decoder.JSONDecodeError:
          pass

      print(f"Ethernet frame data: {sniffed_data}")

    else:
      print("\n")

  

  def send_ICMP_Query(self, address: str) -> str:
    print("Sending DNS query...")
    ip_packet = IPPacket(self.dns_server_prefix + "F", self.node_ip_address, PROTOCOL["DNS_QUERY"], address)
    self.send_ip_packet(ip_packet, self.network_interface_socket)
    print(f"DNS query sent to DNS server at prefix {self.dns_server_prefix}.")

    icmp_packet = IPPacket(self.node_ip_address,  PROTOCOL["ICMP"])

    return icmp_packet

  def get_input_address(self) -> str:
    dest_address = input("Enter destination address\n> ")
    while True:
      if dest_address[:2] == "0x":
        return dest_address
      
      if not is_valid_domain_name(dest_address):
        dest_address = input("Invalid Destination address. Please enter destination address again:\n> ")
        continue 
      
      if not self.dns_table.resolve(dest_address):
        self.send_ICMP_Query(dest_address)
      elif self.dns_table.resolve(dest_address)["ip_address"] is None:
        self.dns_table.remove_record(dest_address)
        self.send_ICMP_Query(dest_address)
      
      dns_query_time_out = 5
      current_time = 2
      while not (self.dns_table.resolve(dest_address)) and not (current_time == dns_query_time_out):
        print(f"Awaiting DNS response{'.' * (current_time % 3 + 1)}")
        current_time += 1
        time.sleep(1)

      dns_record = self.dns_table.resolve(dest_address)
      if dns_record and dns_record["ip_address"]:
        dest_ip_address = dns_record["ip_address"]
        print(f"Destination address of {dest_address} successfully resolved to IP address of {dest_ip_address}.")
        return dest_ip_address

      print("DNS failed to resolve, please try again later.")
      return

  def send_ip_packet(self, ip_packet: IPPacket, corresponding_socket: socket.socket, has_top_break: bool = True, has_bottom_break: bool = True) -> None:
    if has_top_break:print_brk()

    if ip_packet.protocol == PROTOCOL["PING"]:
      self.ping_protocol.ping(ip_packet, corresponding_socket)

    else:
      self.network_interface_socket.send(bytes(ip_packet.dumps(), "utf-8")) # Temporarily handle outgoing packets for other protocols
      print("IP packet sent. [Completed]")
      if has_bottom_break: print_brk()

  def listen(self):
    while True:
      try:
        data = self.network_interface_socket.recv(1024)
        if not data:
          print(f"Connection from router's network interface terminated. {self.device_name} terminated.")
          self.network_interface_socket.close()
          os._exit(0)

        payload = data.decode("utf-8")
        payload_segments = payload.split("|")
        is_valid_payload = len(payload_segments) > 1

        if payload[:10] == "Who has IP":
          print(payload)

        if is_valid_payload: 
          print(f"Ethernet frame received: {payload}")
          ethernet_frame = EthernetFrame.loads(payload)
          src_ip = ethernet_frame.data.src_ip

          if not self.firewall.is_disabled() and not self.firewall.is_allowed(src_ip):
            print(f"Packet from {src_ip} filtered and dropped by firewall.")
          
          else:
            self.EthernetFrame(ethernet_frame, self.network_interface_socket)
          
        print_brk()

      except:
        traceback.print_exc()
        print(f"{self.device_name} terminated.")
        return
      
  # for mitm
  def handle_mitm_attack(self):
    self.mitm_attack.arp_poisoning()
    print(f"ARP poisoning initiated by Node 2")
    self.mitm_attack.start_attack()
    
  def input(self):
    while True:
      node_input = input()
      if node_input == "quit" or node_input == "q":
        print("Terminating node and connection with router interface...")
        self.network_interface_socket.close()
        os._exit(0)

      elif node_input == "help" or node_input == "h":
        print_node_help()

      elif node_input == "icmp":
            print("Create an ICMP packet by entering the destination IP address...")
            dest_ip = input("Enter destination IP address:\n> ")
            if dest_ip:
                icmp_packet = self.ICMP_Packet(dest_ip)
                self.send_ip_packet(icmp_packet, self.network_interface_socket)
            else:
                print_error()

      

      elif node_input == "eth":
        payload = EthernetFrame.input_sequence(self.node_mac).dumps()
        self.network_interface_socket.send(bytes(payload, "utf-8"))
        print("Ethernet frame sent. [Completed]")
        print_brk()

      elif node_input == "ip":
        print("Create a IP packet by entering the following infomration into the console.")
        dest_ip = self.get_input_address()
        if not dest_ip:
          print_error(has_top_break=False)
          continue

        ip_packet = IPPacket.input_sequence(self.node_ip_address, dest_ip)
        if ip_packet:
          self.send_ip_packet(ip_packet, self.network_interface_socket)
        else:
          print_error()

      elif node_input == "arp":
        print("Displaying all ARP tables...")
        self.arp_table.pprint()
        print_brk()

      elif node_input == "dns":
        print("Displaying all local DNS records...")
        self.dns_table.pprint()
        print_brk()

      elif node_input == "reply":
        print_brk()
        arp_response_payload = EthernetFrame.arp_reply_sequence(self.router_interface_address, self.node_mac).dumps()
        self.network_interface_socket.send(bytes(arp_response_payload, "utf-8"))
        print("ARP response sent.")
        print_brk()

      elif node_input == "firewall":
        self.firewall.handle_firewall_input()

      elif node_input == "kill":
        self.kill_protocol.handle_kill_protocol_input()

      elif node_input == "sniff":
        self.sniffer.handle_sniffer_input()

      elif node_input == "spoof":
        spoof_ip = input_ip_sequence("Enter the IP address you want to spoof.\n> ")
        print_brk()

        dest_ip = self.get_input_address()
        if not dest_ip:
          print_error(has_top_break=False)
          continue

        ip_packet = IPPacket.input_sequence(spoof_ip, dest_ip)
        if ip_packet:
          self.send_ip_packet(ip_packet, self.network_interface_socket)
        else:
          print_command_not_found(device = "node")

      elif node_input == "whoami":
        print_brk()
        print(f"{self.device_name}'s IP address is {self.node_ip_address}")
        print(f"{self.device_name}'s MAC address is {self.node_mac}")
        print_brk()

      elif node_input == "mitm":
        # Only allow the mitm command if this is the attacker node (Node2)
        if self.node_mac == "N2":  # Assuming 'N2' is the MAC address of Node2
          self.handle_mitm_attack()
        else:
          print("This command is not recognized on this node.")

      else:
        print_command_not_found(device = "node")

  def run(self) -> None: 
    print_brk()
    print(f"{self.device_name} connecting to router's network interface with mac {self.node_mac}...")
    self.network_interface_socket.connect(self.network_interface_address)
    self.node_connection_request()
    try:
      threading.Thread(target = self.listen).start()
      print_node_help(False)
      self.input()

    except KeyboardInterrupt:
      self.network_interface_socket.close()