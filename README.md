Python script using scapy for scan for dhcp server(s) and dhcp starvation attack. There are some options that can be optionally configured, number of packets to send, dhcp server ip, destination mac address, timeout and debug.

Before starting the attack, the script is able to scan for any dhcp servers in the network to get some information on the server.

It crafts a dhcp discover packet before using the srp (send receive packet) function to parse the received dhcp offer packet, discarding the rest of the packets received. It then prints out all the information in the dhcp offer packet, including data such as ip address offered by dhcp server, dhcp server ip, lease time, subnet mask, router and name server.

If there is more than one server, it is also able to get the information on all the servers.

The script sends DHCP discover packets with a default destination MAC of ff:ff:ff:ff:ff:ff:ff, src ip 0.0.0.0:68 and dst ip of 255.255.255.255:67 using UDP. Source MAC address is randomized to appear to the dhcp server as different requests.
Below is a sample of the packet sent using the argument -debug. In this case the mac address at the Ethernet layer is the same as the mac address at the bootstrap layer, thus enabling the port security will allow the router to easily defend against such attacks.
