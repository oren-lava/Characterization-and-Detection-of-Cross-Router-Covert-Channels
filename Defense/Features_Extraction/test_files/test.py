# from scapy.all import *
# import argparse
# import numpy as np

# # PACKET CONSTS
# ARP_PACKET = 0
# DHCP_PACKET = 1
# DNS_PACKET = 2
# TCP_PACKET = 3

# UDP_PROT = 17
# TCP_PROT = 6

# PI_GUEST_MAC_ADDR = 'b8:27:eb:f7:fc:f5'
# BROADCAST_MAC_ADDR = 'ff:ff:ff:ff:ff:ff'

# def main():
# 	arg_parser = argparse.ArgumentParser(description='Extract PCAP features')
# 	arg_parser.add_argument('pcap_file', type=str, nargs=1, help='Path to the pcap file to process')
# 	args = arg_parser.parse_args()

# 	# read pcap
# 	pcap = rdpcap(args.pcap_file[0])
# 	flows = create_flows(pcap)
# 	flow_res = {}

# 	for (src,dst) in flows.keys():
# 		flow = flows[(src,dst)]
# 		tcp_ans = [] 					# add packets that were already used as tcp answers (tcp ans pkts are not deleted)
# 		responses = read_responses(flow, pcap, tcp_ans)
# 		flow_res[(src,dst)] = responses

# 	for (src,dst) in flow_res.keys():
# 		responses = flow_res[(src,dst)]
# 		try:
# 			med = np.median(responses)
# 			avg = np.mean(responses)
# 			mini = min(responses)
# 			maxi = max(responses)
# 		except:
# 			med = 0
# 			avg= 0
# 			mini = 0
# 			maxi = 0

# 		print(f"Flow {src} --> {dst}: responses: {responses}")
# 		print(f"Flow {src} --> {dst}: median response: {med}, avg response: {avg}, min response: {mini}, max response: {maxi}\n")

# def read_responses(flow, pcap, tcp_ans):
# 	responses = []

# 	for pkt in flow:
# 		if check_pkt_type(pkt) == ARP_PACKET:
# 			res, pcap = get_arp_response(pkt, pcap)

# 		elif check_pkt_type(pkt) == DHCP_PACKET:
# 			res, pcap = get_dhcp_response(pkt, pcap)

# 		elif check_pkt_type(pkt) == DNS_PACKET:
# 			res, pcap = get_dns_response(pkt, pcap)

# 		elif check_pkt_type(pkt) == TCP_PACKET:
# 			res, pcap = get_tcp_response(pkt, pcap, tcp_ans)

# 		else:
# 			continue

# 		if res is not None:
# 			responses.append(res)

# 	return responses
	
# def get_dns_response(pkt, pcap):
# 	new_pcap = pcap.copy()

# 	# pkt is DNS response (1)
# 	if pkt[DNS].qr == 1:
# 		res = None
	
# 	# pkt is DNS query (0)
# 	elif pkt[DNS].qr == 0:
# 		for ans_pkt in pcap:
# 			if check_pkt_type(ans_pkt) != DNS_PACKET:
# 				res = None
# 				continue

# 			if ans_pkt[DNS].qr == 1 and ans_pkt.time > pkt.time and pkt.src == ans_pkt.dst and pkt[DNS].id == ans_pkt[DNS].id:
# 				res = ans_pkt.time - pkt.time
# 				new_pcap.remove(ans_pkt)
# 				new_pcap.remove(pkt)
# 				break
# 			else:
# 				res = None		
# 	else:
# 		res = None
# 		new_pcap.remove(pkt)
		
# 	return res, new_pcap

# def get_tcp_response(pkt, pcap, tcp_ans):
# 	# No support for fragmented packets
# 	if (pkt[IP].flags == 'MF') or (pkt[IP].frag != 0):
# 		return None, pcap
	
# 	new_pcap = pcap.copy()

# 	pkt_seq = pkt[TCP].seq
# 	pkt_tcp_len = pkt[IP].len - (pkt[IP].ihl * 4) - (pkt[TCP].dataofs * 4)

# 	# pkt is SYN (2) or SYN ACK (18) or FIN ACK (17) or FIN (1) or FIN PSH ACK (25) so tcp_len += 1 (special packets)
# 	if pkt[TCP].flags == 2 or pkt[TCP].flags == 18 or pkt[TCP].flags == 17 or pkt[TCP].flags == 1 or pkt[TCP].flags == 25:
# 		pkt_tcp_len += 1
	
# 	# find TCP answer
# 	for ans_pkt in pcap:
# 		if check_pkt_type(ans_pkt) != TCP_PACKET:
# 			res = None
# 			continue

# 		if ans_pkt.time not in tcp_ans and pkt_seq + pkt_tcp_len == ans_pkt[TCP].ack and pkt[TCP].sport == ans_pkt[TCP].dport and pkt[TCP].dport == ans_pkt[TCP].sport and ans_pkt.time > pkt.time and pkt.src == ans_pkt.dst and pkt.dst == ans_pkt.src:
# 			res = ans_pkt.time - pkt.time
# 			print(f"response: {res}, ans_pkt_time: {ans_pkt.time}, pkt time: {pkt.time}")
# 			print(tcp_ans)
# 			new_pcap.remove(pkt)
# 			tcp_ans.append(ans_pkt.time)
# 			break
# 		else:
# 			res = None
		
# 	return res, new_pcap

# def get_arp_response(pkt, pcap):
# 	new_pcap = pcap.copy()

# 	# pkt is ARP reply (2)
# 	if pkt[ARP].op == 2:
# 		res = None
	
# 	# pkt is ARP request (1)
# 	elif pkt[ARP].op == 1:
# 		for ans_pkt in pcap:
# 			if check_pkt_type(ans_pkt) != ARP_PACKET:
# 				res = None
# 				continue

# 			if ans_pkt[ARP].op == 2 and ans_pkt.time > pkt.time and pkt.src == ans_pkt.dst:
# 				res = ans_pkt.time - pkt.time
# 				new_pcap.remove(ans_pkt)
# 				new_pcap.remove(pkt)
# 				break
# 			else:
# 				res = None
# 	else:
# 		res = None
# 		new_pcap.remove(pkt)
		
# 	return res, new_pcap
	
# def get_dhcp_response(pkt,pcap):
# 	new_pcap = pcap.copy()

# 	# pkt is DHCP offer (2) or inform (8)
# 	if pkt[DHCP].options[0][1] == 2 or pkt[DHCP].options[0][1] == 8:
# 		res = None
	
# 	# pkt is DHCP discover (1)
# 	elif pkt[DHCP].options[0][1] == 1:
# 		for ans_pkt in pcap:
# 			if check_pkt_type(ans_pkt) != DHCP_PACKET:
# 				res = None
# 				continue

# 			if ans_pkt[DHCP].options[0][1] == 2 and ans_pkt.time > pkt.time and pkt.src == ans_pkt.dst and pkt.xid == ans_pkt.xid:
# 				res = ans_pkt.time - pkt.time
# 				new_pcap.remove(ans_pkt)
# 				new_pcap.remove(pkt)
# 				break
# 			else:
# 				res = None		
# 	else:
# 		res = None
# 		new_pcap.remove(pkt)
		
# 	return res, new_pcap


# def filter_pi_guest(pcap):
# 	new_pcap = pcap.copy()
# 	for pkt in pcap:
# 		if pkt.src == PI_GUEST_MAC_ADDR or pkt.dst == PI_GUEST_MAC_ADDR:
# 			new_pcap.remove(pkt)
# 	return new_pcap

# def create_flows(pcap):
# 	flows = {} # flow = packets with same src and dest
# 	for pkt in pcap:
# 		if (pkt.src, pkt.dst) in flows:
# 			flows[(pkt.src, pkt.dst)].append(pkt) # add packet to flow
# 		else:
# 			flows[(pkt.src, pkt.dst)] = list(pkt) # create new flow

# 	return flows

# def check_pkt_type(pkt):
# 	try: 
# 		prot_num = pkt[IP].proto
# 		if prot_num == UDP_PROT:
# 			sport = pkt[UDP].sport
# 			dport = pkt[UDP].dport
# 		elif prot_num == TCP_PROT:
# 			sport = pkt[TCP].sport
# 			dport = pkt[TCP].dport
# 		else:
# 			return -1		
# 	except:
# 		sport = "X"
# 		dport = "X"

# 	if ARP in pkt:
# 		return ARP_PACKET

# 	if sport == 68 or dport == 68:
# 		return DHCP_PACKET

# 	if sport == 53 or dport == 53:
# 		return DNS_PACKET

# 	if pkt.haslayer('TCP') and pkt[Ether].type == 2048:		# 2048 = 0x0800 = mark for IPv4
# 		return TCP_PACKET

# 	else:
# 		return -1


# main()
import ntpath
import argparse
# extracts file name from full path
def get_file_name(file_path):
    head, tail = ntpath.split(file_path)
    return tail or ntpath.basename(head)

arg_parser = argparse.ArgumentParser(description='Extract PCAP features')
arg_parser.add_argument('pcap_file', type=str, nargs=1, help='Path to the pcap file to process')
args = arg_parser.parse_args()

filename = get_file_name(args.pcap_file[0])
print(filename.split(".")[0])