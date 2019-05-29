import argparse
import os.path
import sys

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)

import pyshark
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP

def render_csv_row(pkt_sh, pkt_sc, fh_csv):

    ether_pkt_sc = Ether(pkt_sc)
    if ether_pkt_sc.type != 0x800:
        print('Ignoring non-IP packet')
        return False

    ip_pkt_sc = ether_pkt_sc[IP]       
	#Assumsi Ethernet + IPv4 here
    proto = ip_pkt_sc.fields['proto']
    if proto == 17:
        udp_pkt_sc = ip_pkt_sc[UDP]
        l4_payload_bytes = bytes(udp_pkt_sc.payload)
        l4_proto_name = 'UDP'
        l4_sport = udp_pkt_sc.sport
        l4_dport = udp_pkt_sc.dport
    elif proto == 6:
        tcp_pkt_sc = ip_pkt_sc[TCP]
        l4_payload_bytes = bytes(tcp_pkt_sc.payload)
        l4_proto_name = 'TCP'
        l4_sport = tcp_pkt_sc.sport
        l4_dport = tcp_pkt_sc.dport
    else:
        # Jika bukan TCP ataupun UDP
        print('Ignoring non-UDP or TCP packet')
        return False

    # Each line of the CSV has this format
    fmt = '{0},{1},{2},{3},{4},{5},{6},{7},{8},{9}'

    print(fmt.format(pkt_sh.time,             # {0}           
                     pkt_sh.protocol,         # {1}
                     pkt_sh.source,           # {2}
                     l4_proto_name,           # {3}
                     pkt_sh.info,             # {4}
                     l4_sport,                # {5}
                     pkt_sh.destination,      # {6}
                     l4_dport,                # {7}
                     pkt_sh.length,           # {8}
                     l4_payload_bytes.hex()), # {9}
          file=fh_csv)

    return True

def pcap2csv(in_pcap, out_csv):
    
    pcap_pyshark = pyshark.FileCapture(in_pcap, only_summaries=True)
    pcap_pyshark.load_packets()
    pcap_pyshark.reset()

    frame_num = 0
    ignored_packets = 0
    with open(out_csv, 'w') as fh_csv:
        
        for (pkt_scapy, _) in RawPcapReader(in_pcap):
            try:
                pkt_pyshark = pcap_pyshark.next_packet()
                frame_num += 1
                if not render_csv_row(pkt_pyshark, pkt_scapy, fh_csv):
                    ignored_packets += 1
            except StopIteration:

                break

    print('{} packets read, {} packets not written to CSV'.
          format(frame_num, ignored_packets))

def command_line_args():
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', metavar='<input pcap file>',
                        help='pcap file to parse', required=True)
    parser.add_argument('--csv', metavar='<output csv file>',
                        help='csv file to create', required=True)
    args = parser.parse_args()
    return args

def main():

    args = command_line_args()

    if not os.path.exists(args.pcap):
        print('Input pcap file "{}" does not exist'.format(args.pcap),
              file=sys.stderr)
        sys.exit(-1)

    if os.path.exists(args.csv):
        print('Output csv file "{}" already exists, '
              'won\'t overwrite'.format(args.csv),
              file=sys.stderr)
        sys.exit(-1)

    pcap2csv(args.pcap, args.csv)

if __name__ == '__main__':
    main()
