from models.util import print_brk, print_command_not_found

class Sniffer:
  '''
    Encapsulates sniffing functionality.
  '''
  is_sniffing = False
  is_dns_spoofing = False

  def show_status(self) -> None:
    if self.is_sniffing:
      print("Node sniffing is enabled.")
    else:
      print("Node sniffing is disabled.")
    if self.is_dns_spoofing:
      print("Node is spoofing DNS.")
    else:
      print("Node is not spoofing DNS.")
    print_brk()
      

  def enable_sniffing(self) -> None:
    self.is_sniffing = True
    print("Sniffing successfully enabled.")
    print_brk()

  def disable_sniffing(self) -> None:
    self.is_sniffing = False
    print("Sniffing successfully disabled.")
    print_brk()
  
  def enable_dns_spoofing(self) -> None:
    self.is_dns_spoofing = True
    print("DNS spoofing successfully enabled.")
    print_brk()

  def disable_dns_spoofing(self) -> None:
    self.is_dns_spoofing = False
    print("DNS spoofing successfully disabled.")
    print_brk()

  def sniffer(self, has_top_break: bool = True):
    if has_top_break:
      print_brk()

    print("Commands to configure sniffer:")
    print("- status \t\t Shows if sniffing has been activated.")
    print("- disable \t\t Disable sniffing.")
    print("- enable \t\t Enable sniffing.")
    print("- enablespoofing \t Enable DNS spoofing.")
    print("- disablespoofing \t Disable DNS spoofing.")
    print_brk()

    user_input = input("> ")

    if user_input == "status" or user_input == "s":
      self.show_status()

    elif user_input == "disable" or user_input == "d":
      self.disable_sniffing()

    elif user_input == "enable" or user_input == "e":
      self.enable_sniffing()
    
    elif user_input == "enablespoofing":
      self.enable_dns_spoofing()
    
    elif user_input == "disablespoofing":
      self.disable_dns_spoofing()

    else:
      print_command_not_found(device = "node")
