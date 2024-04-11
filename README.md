# CS441 Project - Network Emulator

# Getting Started 
> While connecting the nodes and routers interfaces, please wait for a few seconds for the connection to be done before proceeding to connect another node.

1. Open five different terminals and run the commands below in order:  

    python app/router_interface1.py

    python app/router_interface2.py

    python app/node1.py

    python app/node2.py

    python app/node3.py



2. ARP routing table will be built in the respective terminals where the node is connecting to.

3. Upon a successful connection, a table of commands will be displayed for router interfaces.
 
        Commands:
        - quit   Terminate network interface.
        - help   Display command menu.
        - arp            Display all ARP tables.
        - arp -n         Display ARP tables with connected nodes.
        - arp -r         Display ARP tables with connected network interfaces.
        - whoami         Shows your current ip and mac address.

    Table of commands will be displayed for node.
    
        Type these commands to get started:
        - eth            Create an ethernet packet to send.
        - ip             Create an IP packet to send.
        - arp            Display ARP tables.
        - firewall       Read and/or configure firewall options.
        - sniff          Configure sniffing functionality.
        - spoof          IP Address Spoofing.
        - whoami         Shows your current ip and mac address. - broadcast  Broadcast an ARP query




* Type `arp` command into the terminal for `router_interface2`for the following output:

    Displaying all ARP tables...
    {
        "0x2A": "N2",
        "0x2B": "N3"
    }
    > ARP tables for with connected network interfaces (IP:MAC).
    {
        "0x11": "R1"
    }



1) Ethernet Broadcast
Ethernet frames are used as the main mode of communication within a LAN. 
The process below demonstrates the example for when `node 2` sends an ethernet frame to `node 3` which are on the same LAN.

1. Enter `eth` into `node 2`'s terminal 

    # Node 2

    Create an ethernet frame by entering the following information into the console.
    Enter destination MAC address:
    > N3
    Enter message:
    > Hello Node3
    Ethernet frame sent. [Completed]



2. There will be success message when `node 3` receives the frame.

    # Node 3

    Ethernet frame received: N3|N2|23|4e:6f:6e:65:2d:4e:6f:6e:65:2d:34:2d:48:65:6c:6c:6f:20:4e:6f:64:65:33
    Intended recipient is retrieving data
    Ethernet frame data: Hello Node3


2) IP Packet Forwarding
IP packet forwarding enables inter LAN communications. 

The process below demonstrates the example for when `node 1` wishes to send a ping to `node 3`.

1. Enter `$ ip` into `node 1`'s terminal and fill up the required data from the sequence.

    #Node1
    ip
    Create a IP packet by entering the following infomration into the console.
    Enter destination address
    > 0x2B

2. Enter the protocol
    Enter protocol:
    - 0      ICMP protocol
    - 1      Log protocol
    - 2      Kill protocol
    > 0

3. You should see the succeed message:
    Pinging 0x2B with 12 bytes of data...
    Ethernet frame received: N1|R1|25|30:78:31:41:2d:30:78:32:42:2d:30:72:2d:48:65:6c:6c:6f:20:4e:6f:64:65:20:33
    Intended recipient is retrieving data
    ICMP response data: Hello Node 3 [Success]


3) IP Spoofing
IP spoofing is altering the source address while sending an IP packet.

The process below demonstrates the example for when `node 1` spoofs as `node 2` and sends a ping to `node 3`.

1. Enter `$ spoof` into `node 1`'s terminal and fill up the required data from the sequence.
    spoof
    Enter the IP address you want to spoof.
    > 0x2A

    Enter destination address
    > 0x2B

    Enter protocol:
    - 0      ICMP protocol
    - 1      Log protocol
    - 2      Kill protocol
    > 0

    Please enter message:
    > Not node 1Ping 0x2B as 0x2A


2. You should get the result
    Ethernet frame received: N3|R2|22|30:78:32:42:2d:30:78:32:41:2d:30:2d:4e:6f:74:20:6e:6f:64:65:20:31
    Intended recipient is retrieving data
    Ping request received, echoing data...
    Data (Not node 1) echoed.

4) Sniffing Attack
We use `node 2` to sniff the communication between `node 1` and `node 3` 

1. Enter `sniff` into `node 2` terminal. This allows `node 2` to sniff any incoming IP packet data.

    sniff

    Commands to configure sniffer:
    - Status                 Shows if sniffing has been activated.
    - Disable                Disable sniffing.
    - Enable                 Enable sniffing.
    - enablespoofing         Enable DNS spoofing.
    - disablespoofing        Disable DNS spoofing.Sniffing successfully enabled.

    > enable
    Sniffing successfully enabled.


2. We sent a packet from `node 1` to `node 3`, and `node2` should be able to sniff.
    # Node 2

    Ethernet frame received: N3|R2|21|30:78:32:42:2d:30:78:31:41:2d:30:2d:48:69:20:4e:6f:64:65:20:33
    Sniffing enabled
    Ethernet frame data: Hi Node 3


5) Firewall
A firewall monitors incoming and outgoing network traffic and decides whether to allow or block specific traffic based on a defined set of security rules

1. We type firewall to get to this menu

    Commands to configure firewall:
    - s              Display current status of firewall.
    - b              View the current blacklist for this node.
    - b -a           Add a node to the blacklist.
    - b -r           Remove a node from the blacklist.
    - b -e           Enable blacklist firewall.
    - b -d           Disable blacklist firewall.
    - w              View the current whitelist for this node.
    - w -a           Add a node to the whitelist.
    - w -r           Remove a node from the whitelist.
    - w -e           Enable whitelist firewall.
    - w -d           Disable whitelist firewall.

2. We add `node 2` as blacklist
    > b -a
    What is the value of the IP you wish to add to blacklist?
    > 0x2A
    IP 0x2A successfully added to blacklist.

6) ARP Spoofing
Starts an ARP spoofing attack with node 2 as the attacker. Not fully functional yet but in theory node 2 send false ARP replies to the LAN and tries to associate the IP address of node 1 and 3 with the MAC address of node 2.

1. Type "arpspoof" into node 2's command line and wait for it to the arp poisoning attack to finish

2. Then try to send an ethernet frame from node 1 to node 3