from scapy.all import *
import csv, argparse
import numpy as np
# from scapy.layers.dns import DNS

# CONSTS
FLOW_CSV_FILENAME = ''
FLOW_FIELDS = ['FLOW source', 'FLOW destination', 'FLOW duration', 'FLOW packet count', 'FLOW bytes count', 'FLOW TX time difference median', 'FLOW TX time difference variance', 'FLOW packet length median', 'FLOW packet length variance', 'FLOW to router or broadcast', 'FLOW answer count', 'FLOW answer length median', 'FLOW answer length variance', 'FLOW response time median', 'FLOW response time variance', 'FLOW response time average', 'FLOW response time min', 'FLOW response time max', 'FLOW label']
ROUTER_MAC_ADDR = '50:c7:bf:51:1e:3f'
BROADCAST_MAC_ADDR = 'ff:ff:ff:ff:ff:ff'
PACKET_DNS_FIELD_INDEX = 3 # Don't touch! used for linking DNS query and response

# Functions
def main():
	global FLOW_CSV_FILENAME
	arg_parser = argparse.ArgumentParser(description='Extract PCAP features')
	arg_parser.add_argument('pcap_file', type=str, nargs=1, help='Path to the pcap file to process')
	arg_parser.add_argument('csv_filename', type=str, nargs=1, help='Path where to output csv should be placed')
	args = arg_parser.parse_args()
	FLOW_CSV_FILENAME = args.csv_filename[0]

	# read pcap
	pcap = rdpcap(args.pcap_file[0])

	# keep only DNS
	port_list = []
	for pkt in pcap:
		try:
			port_list.append([pkt, pkt.sport, pkt.dport])
		except:
			pcap.remove(pkt)
	for p in port_list:
		if str(p[1]) != '53' and str(p[2]) != '53':
			pcap.remove(p[0])

	# get broadcast flows
	no_broadcast_pcap, broadcast_flows = parse_broadcast_flows(pcap)

	# create regular flows
	flows = create_flows(no_broadcast_pcap, broadcast_flows)

	# get flows features
	flow_data = parse_flows(flows)
	
	# save all features to CSV files
	save_to_csv(flow_data)
	print('Created ' + FLOW_CSV_FILENAME + ' successfully!')


# Parse the pcap file (without broadcast packets), creates flows and returns all the flows (broadcast + non-broadcast)
# Args: pcap file, broadcast_flows
# Returns: flows
def create_flows(pcap, broadcast_flows):
	flows = {} # flow = packets with same src and dest
	for pkt in pcap:
		if (pkt.src, pkt.dst) in flows:
			flows[(pkt.src, pkt.dst)].append(pkt) # add packet to flow
		else:
			flows[(pkt.src, pkt.dst)] = list(pkt) # create new flow

	# merge broadcast flows with regular flows
	flows.update(broadcast_flows)

	return flows


# Parse packet flows
# Args: dictionary of flows (keys = (src,dst) tuples)
# Returns: extracted flow data
def parse_flows(flows):
	flow_data = []
	curr_data = []
	for (src, dst) in flows.keys():

		# flows that source from the router are always answer flows
		if src == ROUTER_MAC_ADDR or src == BROADCAST_MAC_ADDR:
			continue

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
		if dst == ROUTER_MAC_ADDR or dst == BROADCAST_MAC_ADDR:
			curr_data.append(1)
		else:
			curr_data.append(0)


		# FLOW answer count, FLOW answer length, FLOW response time (only if there is an answer flow)
		if ans_flow:
			curr_data.append(len(ans_flow)) # FLOW answer count
			
			flow_answer_len = []
			for pkt in ans_flow:
				flow_answer_len.append(len(pkt))

			curr_data.append(np.median(flow_answer_len)) # FLOW answer length median
			curr_data.append(np.var(flow_answer_len)) # FLOW answer length variance

			response_times = read_responses(flow, ans_flow)
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

		else:
			curr_data.append(0)
			curr_data.append(0)
			curr_data.append(0)
			curr_data.append(0)
			curr_data.append(0)
			curr_data.append(0)
			curr_data.append(0)
			curr_data.append(0)

		# Add label place holder (use serial_and_label.py script to fix it)
		curr_data.append(0)

		flow_data.append(curr_data)
		curr_data = []

	return flow_data
		

# Reads the response times from a packet flow and its answer flow
# Arguments: flow, ans_flow (list of packets)
# Returns: list of response times
def read_responses(flow, ans_flow):
	responses = []

	dns_flow = [pkt for pkt in flow if DNS in pkt]
	dns_ans_flow = [pkt for pkt in ans_flow if DNS in pkt]

	# get DNS response time
	for pkt in dns_flow:
		for ans_pkt in dns_ans_flow:
			if ans_pkt[PACKET_DNS_FIELD_INDEX].id == pkt[PACKET_DNS_FIELD_INDEX].id:	
				res = ans_pkt.time - pkt.time
				responses.append(res)

	return responses


# creates broadcast flows (and removes the packets from the general pcap)
# Args: pcap
# Returns: pcap (without broadcast packet + answers), broadcast flows
def parse_broadcast_flows(pcap):
	new_pcap = pcap.copy()
	broadcast_flows = {}
	ans_index_list = []

	for i in range(len(pcap)):
		pkt = pcap[i]
		if pkt.dst != BROADCAST_MAC_ADDR:
			continue

		else: # find broadcast packet
			if (pkt.src, pkt.dst) in broadcast_flows:
				broadcast_flows[(pkt.src, pkt.dst)].append(pkt) # add to broadcast flow
			else:
				broadcast_flows[(pkt.src, pkt.dst)] = [pkt] # create broadcast flow
			new_pcap.remove(pkt)
			
			ans_pkt_index = find_broadcast_ans(pcap, i, ans_index_list) # find broadcast answer
			if ans_pkt_index == -1:
				del broadcast_flows[(pkt.src, pkt.dst)]
				continue
			
			ans_index_list.append(ans_pkt_index)
			ans_pkt = pcap[ans_pkt_index]
			new_pcap.remove(ans_pkt)
			
			if (BROADCAST_MAC_ADDR, ans_pkt.dst) in broadcast_flows:
				broadcast_flows[(BROADCAST_MAC_ADDR, ans_pkt.dst)].append(ans_pkt)
			else:
				broadcast_flows[(BROADCAST_MAC_ADDR, ans_pkt.dst)] = [ans_pkt]

	return new_pcap, broadcast_flows


# Find broadcast answer packet
# Args: list of packet (pcap), index of broadcast pkt in pcap (index), ans_index_list - list of used(!) indices
# Returns: broadcast packet index in pcap
def find_broadcast_ans(pcap, index, ans_index_list):
	pkt = pcap[index]
	if index+200 > len(pcap):
		search_len = len(pcap)
	else:
		search_len = index+200

	for i in range(index, search_len):
		ans_pkt = pcap[i]
		if ans_pkt.dst == pkt.src and ans_pkt.payload.proto == pkt.payload.proto:
			if i in ans_index_list:
				continue
			else:
				return i
	return -1


# Save data list to csv file
# Args: data (list of lists)
# Returns: None
def save_to_csv(flow_data):
	with open(FLOW_CSV_FILENAME, 'w', newline="") as f:
		csvwriter = csv.writer(f)
		csvwriter.writerow(FLOW_FIELDS)
		csvwriter.writerows(flow_data)

main()