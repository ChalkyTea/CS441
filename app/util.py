import os
import re
from typing import Literal

def encode_data(data: str) -> str:
  return ':'.join(f"{ord(ch):02x}" for ch in data)

def decode_data(data: str) -> str:
  return ''.join([chr(int(ch, 16)) for ch in data.split(":")])

def is_valid_domain_name(address: str) -> bool:
  regex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"
  pattern = re.compile(regex)
  if (address == None):
    return False
  return (re.search(pattern, address))

def print_brk():
  print('-' * os.get_terminal_size().columns)

def print_node_help(has_top_break: bool = True):
  if has_top_break:
    print_brk()

  print("Type these commands to get started:")
  print("- eth \t\t Create an ethernet packet to send.")
  print("- ip \t\t Create an IP packet to send.")
  print("- arp \t\t Display ARP tables.")
  print("- firewall \t Read and/or configure firewall options.")
  print("- sniff \t Configure sniffing functionality.")
  print("- spoof \t IP Address Spoofing.")
  print("- whoami \t Shows your current ip and mac address.")
  print_brk()

def print_network_int_help(has_top_break: bool = True):
  if has_top_break:
    print_brk()

  print("Commands:")
  print("- quit \t Terminate network interface.")
  print("- help \t Display command menu.")
  # print("- reconnect \t Attempt to reconnect to failed connections during start up.")
  # print("- ip route \t Display all routing tables.")
  print("- arp \t\t Display all ARP tables.")
  print("- arp -n \t Display ARP tables with connected nodes.")
  print("- arp -r \t Display ARP tables with connected network interfaces.")
  print("- whoami \t Shows your current ip and mac address.")
  print_brk()


def print_command_not_found(device: Literal["node", "network_interface"]):
  print_brk()
  print("Unidentified command. Please use a registered command...")
  if device == "node":
    print_node_help(has_top_break = False)
  elif device == "network_interface":
    print_network_int_help(has_top_break = False)


def print_error(has_top_break: bool = True):
  if has_top_break:
    print_brk()
  print("Process aborted.")
  print_brk()


def input_ip_sequence(prompt: str) -> str:
    ip_to_add = input(prompt)
    valid_input = True if ip_to_add[:2] == "0x" else False
    while not valid_input:
      ip_to_add = input("Invalid input, please enter a valid IP (e.g., 0x1A).\n> ")
      valid_input = True if ip_to_add[:2] == "0x" else False
    
    return ip_to_add

def clean_ethernet_payload(eth_payload: str) -> str:
  eth_payload = "|".join(eth_payload.split("|")[:4])
  if not eth_payload[-2:].isdigit():
    eth_payload = eth_payload[:-2]
  return eth_payload

def clean_ip_payload(ip_payload: str) -> str:
  ip_payload = "|".join(ip_payload.split("|")[:5])
  if ip_payload[-4:-3] == "0x":
    ip_payload = ip_payload[:-4]
  return ip_payload


if __name__ == "__main__":
  pass