from __future__ import annotations
from EthernetFrame import EthernetFrame
from constants import PROTOCOL
from util import print_brk

class IPPacket:
  destination: str = None
  source: str = None
  protocol: str = None
  data_length: int = None
  data: str = None

  def __init__(
    self,
    dest_ip: str,
    src_ip: str,
    protocol: str,
    data: str
  ):
    self.destination = dest_ip
    self.source = src_ip
    self.protocol = protocol
    self.data_length = len(data) if data else 0
    self.data = data

  def dumps(self) -> str:
    return f"{self.destination}|{self.source}|{self.protocol}|{self.data_length}|{self.data}"

  @staticmethod
  def loads(data: str) -> IPPacket:
    dest_ip, src_ip, protocol, data_length, data = data.split("|")
    return IPPacket(dest_ip, src_ip, protocol, data)

  def is_recipient(self, ip_address: str) -> bool:
    if ip_address == self.destination:
      return True
    return False

  def dest_ip_prefix(self) -> str:
    return self.destination[:3]

  def source_ip_prefix(self) -> str:
    return self.source[:3]
  
  def is_broadcast_address(self) -> bool:
    return self.destination[3] == "F"

  def to_eth_frame(self, dest_mac: str, src_mac: str) -> EthernetFrame:
    data_with_headers = f"{self.destination}-{self.source}-{self.protocol}-{self.data}"
    return EthernetFrame(dest_mac, src_mac, data_with_headers)

  @staticmethod
  def input_sequence(src_ip: str, dest_ip:str) -> IPPacket:
    
    print_brk()
    protocol = input("Enter protocol: \n- 0 \t ICMP protocol\n- 1 \t Log protocol\n- 2 \t Kill protocol\n> ")
    while not (protocol.isdigit()) or not (int(protocol) in range(3)):
      protocol = input("Invalid protocol, please enter protocol again: \n- 0 \t Ping protocol\n- 1 \t Log protocol\n- 2 \t Kill protocol\n> ")
    
    print_brk()
    data = input("Please enter message:\n> ")
    return IPPacket(dest_ip, src_ip, protocol, data)