from scapy.all import *
import csv, argparse
import numpy as np
import ntpath

FEATURES = ['FLOW serial number','FLOW source', 'FLOW destination', 'FLOW duration', 'FLOW packet count', 'FLOW bytes count',
'FLOW TX time difference median', 'FLOW TX time difference variance', 'FLOW packet length median',
'FLOW packet length variance', 'FLOW to router or broadcast', 'FLOW response time median',
'FLOW response time variance', 'FLOW response time average', 'FLOW response time min', 'FLOW response time max',
'FLOW label']

#CONSTS
ROUTER_ROM_MAC_ADDR = '50:c7:bf:51:1e:3f'
ROUTER_WED_MAC_ADDR = '58:d5:6e:bb:47:4d'
BROADCAST_MAC_ADDR = 'ff:ff:ff:ff:ff:ff'
PI_GUEST_MAC_ADDR = 'b8:27:eb:f7:fc:f5'

# PACKET CONSTS
ARP_PACKET = 0
DHCP_PACKET = 1
DNS_PACKET = 2
VNC_PACKET = 3
TLS_PACKET = 4
TCP_PACKET = 5

UDP_PROT = 17
TCP_PROT = 6

## IMPORTANT: Use this script when your pwd is the folder of the pcap files ##

def main():
	arg_parser = argparse.ArgumentParser(description='Extract PCAP features')
	arg_parser.add_argument('pcap_file', type=str, nargs=1, help='Path to the pcap file to process')
	args = arg_parser.parse_args()

	# read pcap
	global pcap_file_path
	pcap_file_path = args.pcap_file[0]
	pcap = rdpcap(pcap_file_path)

	# remove pi-guest packets
	pcap = filter_pi_guest(pcap)

	# create flows
	flows = create_flows(pcap)

	# get flows features
	flow_data = parse_flows(flows, pcap)

	# save all features to CSV files
	save_to_csv(flow_data)

# Removes any packets that involve pi-guest
# Args: pcap (packet list)
# Returns: pcap (packet list)
def filter_pi_guest(pcap):
	new_pcap = pcap.copy()
	for pkt in pcap:
		if pkt.src == PI_GUEST_MAC_ADDR or pkt.dst == PI_GUEST_MAC_ADDR:
			new_pcap.remove(pkt)
	return new_pcap

# Parse the pcap file (without broadcast packets), creates flows and returns all the flows (broadcast + non-broadcast)
# Args: pcap file, arp_broadcast_flows
# Returns: flows
def create_flows(pcap):
	flows = {} # flow = packets with same src and dest
	for pkt in pcap:
		if (pkt.src, pkt.dst) in flows:
			flows[(pkt.src, pkt.dst)].append(pkt) # add packet to flow
		else:
			flows[(pkt.src, pkt.dst)] = list(pkt) # create new flow

	return flows

# Parse packet flows
# Args: dictionary of flows (keys = (src,dst) tuples)
# Returns: extracted flow data
def parse_flows(flows, pcap):
	flow_data = []
	curr_data = []
	flow_count = 1
	for (src, dst) in flows.keys():
		filename, _ = get_file_name(pcap_file_path)
		flow_serial = filename.split("_")[0] + "." + str(flow_count)
		flow_count += 1
		curr_data.append(flow_serial) # FLOW serial number

		flow = flows[(src, dst)] # flow is a list
		curr_data.append(src) # FLOW source
		curr_data.append(dst) # FLOW destination

		# answer flow is the opposite flow
		try:
			ans_flow = flows[(dst,src)]
		except:
			ans_flow = []

		curr_data.append(flow[-1].time - flow[0].time) # FLOW duration
		curr_data.append(len(flow)) # FLOW packet count

		# FLOW byte count, FLOW TX time difference, FLOW packet length
		count_of_bytes = 0
		TX_time_diff = []
		flow_pkt_length = []

		for i in range(len(flow)):
			count_of_bytes += len(flow[i])
			flow_pkt_length.append(len(flow[i]))
			if(i == len(flow) - 1):
				break
			TX_time_diff.append(flow[i+1].time - flow[i].time)
		TX_time_diff = [float(x) for x in TX_time_diff]

		curr_data.append(count_of_bytes) # FLOW byte count
		if len(flow) > 1:
			curr_data.append(np.median(TX_time_diff)) # FLOW TX time difference median
			curr_data.append(np.var(TX_time_diff)) # FLOW TX time difference variance
		else:
			curr_data.append(0)
			curr_data.append(0)

		curr_data.append(np.median(flow_pkt_length)) # FLOW packet length median
		curr_data.append(np.var(flow_pkt_length)) # FLOW packet length variance

		# FLOW to router\broadcast
		if dst == ROUTER_WED_MAC_ADDR or dst == ROUTER_ROM_MAC_ADDR or dst == BROADCAST_MAC_ADDR:
			curr_data.append(1)
		else:
			curr_data.append(0)


		# FLOW answer count, FLOW answer length, FLOW response time (only if there is an answer flow)

		tcp_ans = []
		response_times = read_responses(flow, pcap, tcp_ans)
		if response_times:
			response_times = [float(x) for x in response_times]

			if len(flow) > 1:
				curr_data.append(np.median(response_times)) # FLOW response time median
				curr_data.append(np.var(response_times)) # FLOW response time variance
				curr_data.append(np.mean(response_times)) # FLOW response time average
				curr_data.append(min(response_times)) # FLOW response time min
				curr_data.append(max(response_times)) # FLOW response time max
			else:
				try:
					curr_data.append(response_times[0])
				except:
					curr_data.append(0)
				curr_data.append(0)
				curr_data.append(0)
				curr_data.append(0)
				curr_data.append(0)

		else:
			curr_data.append(0)
			curr_data.append(0)
			curr_data.append(0)
			curr_data.append(0)
			curr_data.append(0)

		# Add label
		_, is_mal = get_file_name(pcap_file_path)
		if is_mal == 1:
			curr_data.append(1)
		else:
			curr_data.append(0)

		flow_data.append(curr_data)
		curr_data = []

	return flow_data


# Checks whether a packet is ARP\DHCP\DNS\TCP
# Args: pkt
# Returns: int (indicating the packet type)
def check_pkt_type(pkt):
	is_tcp = None
	try:
		prot_num = pkt[IP].proto
		if prot_num == UDP_PROT:
			pkt_udp_layer = pkt[UDP]
			sport = pkt_udp_layer.sport
			dport = pkt_udp_layer.dport
			is_tcp = False
		elif prot_num == TCP_PROT:
			pkt_tcp_layer = pkt[TCP]
			sport = pkt_tcp_layer.sport
			dport = pkt_tcp_layer.dport
			is_tcp = True
		else:
			return -1
	except:
		sport = "X"
		dport = "X"

	if ARP in pkt:
		return ARP_PACKET

	if sport == 68 or dport == 68:
		return DHCP_PACKET

	if sport == 53 or dport == 53:
		return DNS_PACKET

	if is_tcp and pkt[Ether].type == 2048:		# 2048 = 0x0800 = mark for IPv4
		return TCP_PACKET

	else:
		return -1

# get the response times of a given packet flow
# Args: flow (list of packets from a specific (src,dst)), pcap (list of all packets), tcp_ans (used in get_tcp_response)
# Returns: responses (list of response times)
def read_responses(flow, pcap, tcp_ans):
	responses = []

	for pkt in flow:
		if check_pkt_type(pkt) == ARP_PACKET:
			res, pcap = get_arp_response(pkt, pcap)

		elif check_pkt_type(pkt) == DHCP_PACKET:
			res, pcap = get_dhcp_response(pkt, pcap)

		elif check_pkt_type(pkt) == DNS_PACKET:
			res, pcap = get_dns_response(pkt, pcap)

		elif check_pkt_type(pkt) == TCP_PACKET:
			res, pcap = get_tcp_response(pkt, pcap, tcp_ans)

		else:
			continue

		if res is not None:
			responses.append(res)

	return responses

# find DNS reply for a given DNS query and return the response time (deleting from the pcap the packet and its answer)
# Args: packet, pcap (list of packets)
# Returns: response time, new pcap (without the packet and its answer)
def get_dns_response(pkt, pcap):
	new_pcap = pcap.copy()

	# pkt is DNS response (1)
	if pkt[DNS].qr == 1:
		res = None

	# pkt is DNS query (0)
	elif pkt[DNS].qr == 0:

		pkt_index = pcap.index(pkt)
		if pkt_index + 50 > len(pcap):
			end_index = len(pcap)
		else:
			end_index = pkt_index + 50
		for i in range(pkt_index, end_index):
			ans_pkt = pcap[i]
			if check_pkt_type(ans_pkt) != DNS_PACKET:
				res = None
				continue

			if ans_pkt[DNS].qr == 1 and ans_pkt.time > pkt.time and pkt.src == ans_pkt.dst and pkt[DNS].id == ans_pkt[DNS].id:
				res = ans_pkt.time - pkt.time
				new_pcap.remove(ans_pkt)
				new_pcap.remove(pkt)
				break
			else:
				res = None
	else:
		res = None
		new_pcap.remove(pkt)

	return res, new_pcap

# find TCP reply for a given TCP packet and return the response time (deleting from the pcap the packet and its answer)
# Args: packet, pcap (list of packets), tcp_ans (list of timestamps of TCP packets that were already used as answers)
# Returns: response time, new pcap (without the packet and its answer)
def get_tcp_response(pkt, pcap, tcp_ans):
	# No support for fragmented packets
	if (pkt[IP].flags == 'MF') or (pkt[IP].frag != 0):
		return None, pcap

	new_pcap = pcap.copy()

	pkt_tcp_layer = pkt[TCP]
	pkt_IP_layer = pkt[IP]
	pkt_seq = pkt_tcp_layer.seq
	pkt_tcp_len = pkt_IP_layer.len - (pkt_IP_layer.ihl * 4) - (pkt_tcp_layer.dataofs * 4)

	# pkt is SYN (2) or SYN ACK (18) or FIN ACK (17) or FIN (1) or FIN PSH ACK (25) so tcp_len += 1 (special packets)
	if pkt_tcp_layer.flags == 2 or pkt_tcp_layer.flags == 18 or pkt_tcp_layer.flags == 17 or pkt_tcp_layer.flags == 1 or pkt_tcp_layer.flags == 25:
		pkt_tcp_len += 1

	pkt_index = pcap.index(pkt)
	if pkt_index + 50 > len(pcap):
		end_index = len(pcap)
	else:
		end_index = pkt_index + 50

	# find TCP answer
	for i in range(pkt_index, end_index):
		ans_pkt = pcap[i]
		if check_pkt_type(ans_pkt) != TCP_PACKET:
			res = None
			continue

		ans_pkt_tcp_layer = ans_pkt[TCP]
		if ans_pkt.time not in tcp_ans and pkt_seq + pkt_tcp_len == ans_pkt_tcp_layer.ack and pkt_tcp_layer.sport == ans_pkt_tcp_layer.dport and pkt_tcp_layer.dport == ans_pkt_tcp_layer.sport and ans_pkt.time > pkt.time and pkt.src == ans_pkt.dst and pkt.dst == ans_pkt.src:
			res = ans_pkt.time - pkt.time
			new_pcap.remove(pkt)
			tcp_ans.append(ans_pkt.time)
			break
		else:
			res = None

	return res, new_pcap

# find ARP reply for a given ARP request and return the response time (deleting from the pcap the packet and its answer)
# Args: packet, pcap (list of packets)
# Returns: response time, new pcap (without the packet and its answer)
def get_arp_response(pkt, pcap):
	new_pcap = pcap.copy()

	# pkt is ARP reply (2)
	if pkt[ARP].op == 2:
		res = None

	# pkt is ARP request (1)
	elif pkt[ARP].op == 1:
		pkt_index = pcap.index(pkt)
		if pkt_index + 50 > len(pcap):
			end_index = len(pcap)
		else:
			end_index = pkt_index + 50

		for i in range(pkt_index, end_index):
			ans_pkt = pcap[i]
			if check_pkt_type(ans_pkt) != ARP_PACKET:
				res = None
				continue

			if ans_pkt[ARP].op == 2 and ans_pkt.time > pkt.time and pkt.src == ans_pkt.dst:
				res = ans_pkt.time - pkt.time
				new_pcap.remove(ans_pkt)
				new_pcap.remove(pkt)
				break
			else:
				res = None
	else:
		res = None
		new_pcap.remove(pkt)

	return res, new_pcap

# find DHCP offer for a given DHCP discover and return the response time (deleting from the pcap the packet and its answer)
# Args: packet, pcap (list of packets)
# Returns: response time, new pcap (without the packet and its answer)
def get_dhcp_response(pkt,pcap):
	new_pcap = pcap.copy()

	# pkt is DHCP offer (2) or inform (8)
	if pkt[DHCP].options[0][1] == 2 or pkt[DHCP].options[0][1] == 8:
		res = None

	# pkt is DHCP discover (1)
	elif pkt[DHCP].options[0][1] == 1:
		pkt_index = pcap.index(pkt)
		if pkt_index + 50 > len(pcap):
			end_index = len(pcap)
		else:
			end_index = pkt_index + 50

		for i in range(pkt_index, end_index):
			ans_pkt = pcap[i]
			if check_pkt_type(ans_pkt) != DHCP_PACKET:
				res = None
				continue

			if ans_pkt[DHCP].options[0][1] == 2 and ans_pkt.time > pkt.time and pkt.src == ans_pkt.dst and pkt.xid == ans_pkt.xid:
				res = ans_pkt.time - pkt.time
				new_pcap.remove(ans_pkt)
				new_pcap.remove(pkt)
				break
			else:
				res = None
	else:
		res = None
		new_pcap.remove(pkt)

	return res, new_pcap


# extracts file name from full path
# Args: path to file
# Returns: file name (with file type .csv), bool (1 = mal, 0 = beg)
def get_file_name(file_path):
	head, tail = ntpath.split(file_path)
	if head:
		filename = ntpath.basename(head)
	else:
		filename = tail

	if "mal" in filename:
		is_mal = 1
	else:
		is_mal = 0

	filename = filename.split(".")[0] + ".csv"

	return filename, is_mal


# Save data list to csv file
# Args: data (list of lists)
# Returns: None
def save_to_csv(flow_data):
	CSV_FILENAME, _ = get_file_name(pcap_file_path)

	with open(CSV_FILENAME, 'w', newline="") as f:
		csvwriter = csv.writer(f)
		csvwriter.writerow(FEATURES)
		csvwriter.writerows(flow_data)
		print('Created ' + CSV_FILENAME + ' successfully!')


main()
