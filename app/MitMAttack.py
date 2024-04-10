import socket

from EthernetFrame import EthernetFrame
from IPPacket import IPPacket
from ARPTable import ARPTable

class MitMAttack:
    def __init__(self, attacker_node):
        self.attacker_node = attacker_node
        self.is_attack_active = False
        self.intercepted_packets = []

    def start_attack(self):
        # Code to initiate MitM attack
        self.is_attack_active = True
        print(f"MitM attack initiated")

    def intercept_packet(self, ethernet_frame: EthernetFrame):
        # Code to intercept packets
        if self.is_attack_active:
            print(f"Packet intercepted by {self.attacker_node.device_name}")
            self.intercepted_packets.append(ethernet_frame)
            return ethernet_frame
        return None

    def modify_packet(self, ethernet_frame: EthernetFrame):
        # Code to modify packets
        if ethernet_frame:
            print(f"Packet being modified by {self.attacker_node.device_name}")
            # This is a simple example, the actual modification will depend on the packet content
            # For the sake of example, let's reverse the data in the packet
            modified_data = "Modified"
            ethernet_frame.data.data = modified_data
            return ethernet_frame
        return None

    def forward_packet(self, ethernet_frame: EthernetFrame, destination_socket):
        # Code to forward the modified packet to the intended recipient
        if ethernet_frame and destination_socket:
            print(f"Forwarding packet from {self.attacker_node.node_mac}")
            payload = ethernet_frame.dumps()
            destination_socket.send(bytes(payload, "utf-8"))

    def execute_attack(self, ethernet_frame: EthernetFrame, destination_socket):
        intercepted_frame = self.intercept_packet(ethernet_frame)
        if intercepted_frame:
            modified_frame = self.modify_packet(intercepted_frame)
            self.forward_packet(modified_frame, destination_socket)

    def send_false_arp_reply(self, victim_ip: str, victim_mac: str, target_socket: socket.socket):
        """
        Sends a false ARP reply to the victim, associating the victim's IP with the attacker's MAC.
        """
        # Constructing an ARP reply Ethernet frame with false information
        false_arp_reply = EthernetFrame.arp_reply_sequence(victim_mac, self.attacker_node.node_mac).dumps()

        # Sending the false ARP reply to the victim's node
        target_socket.send(bytes(false_arp_reply, "utf-8"))
        print(f"False ARP reply sent to {victim_ip} associating it with {self.attacker_node.node_mac}")

    def arp_poisoning(self):
        """
        Performs ARP poisoning by sending false ARP replies to both victims.
        """
        # Assuming the attacker knows the IP and MAC addresses of the victims, and has a socket to communicate
        victim1_ip = "0x1A"
        
        victim3_ip = "0x2B"

        # Send false ARP replies to both victims
        self.send_false_arp_reply(victim1_ip, self.attacker_node.node_mac, self.attacker_node.network_interface_socket)
        self.send_false_arp_reply(victim3_ip, self.attacker_node.node_mac, self.attacker_node.network_interface_socket)
