from __future__ import annotations
from models.payload.EthernetData import EthernetData
from models.util import print_brk, encode_data, decode_data
from models.constants import PROTOCOL

class EthernetFrame:
  destination: str = None
  source: str = None
  data_length: int = None
  data: EthernetData = None

  def __init__(
    self,
    dest_mac: str,
    src_mac: str,
    data: str
  ):
    self.destination = dest_mac
    self.source = src_mac
    self.data_length = len(data)
    self.data = EthernetData(data)
  
  def dumps(self) -> str:
    return f"{self.destination}|{self.source}|{self.data_length}|{encode_data(self.data.dumps())}"

  @staticmethod
  def loads(payload: str) -> EthernetFrame:
    dest_mac, src_mac, data_length, data = payload.split("|")
    return EthernetFrame(dest_mac, src_mac, decode_data(data))

  def is_recipient(self, mac_address: str) -> bool:
    if mac_address == self.destination:
      return True
    return False
  
  @staticmethod
  def input_sequence(src_mac: str) -> EthernetFrame:
    print_brk()
    print("Create an ethernet frame by entering the following information into the console.")
    dest_mac = input("Enter destination MAC address:\n> ")
    payload = input("Enter message:\n> ")
    ethernet_frame = EthernetFrame(dest_mac, src_mac, payload)
    ethernet_frame.data.protocol = PROTOCOL["ETH"]
    return ethernet_frame

  @staticmethod
  def arp_reply_sequence(dst_mac: str, src_mac: str) -> EthernetFrame:
    
    data = "arp_response"
    return EthernetFrame(dst_mac, src_mac, data)

