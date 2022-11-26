import sys
from scapy.all import *
import matplotlib.pyplot as plt
from scapy.layers.dns import DNS

# This script is meant to plot the response times of a wifi microjamming pcap as a function of time
# first the whole recording, then a zoomed graph of 11-12 seconds
# The data leaked in the original attack was the pseudo random series PN7 (given below)
# To see an example graph for the attack success, put "True" in "SHOW_EXAMPLE_GRAPH" constant (you need to use mal.pcap as an argument)

# PN7: 1000001100001010001111001000101100111010100111110100001110001001001101101011011110110001101001011101110011001010101111111000000

# CONSTS
PACKET_DNS_FIELD_INDEX = 3 # Don't touch! used for linking DNS query and response
SHOW_EXAMPLE_GRAPH = True # put True if you're using mal.pcap
TIME_OF_WINDOW = 1 # here for historical reasons

def main():
	if len(sys.argv) < 2:
		print("plot_microjam.py <pcap_file>")
		return
	pcap_file = sys.argv[1]

	# Get response times (and their timestamps) from the pcap
	pcap = rdpcap(pcap_file)
	response_times_dict, response_timestamp_dict = get_response_times(pcap)

	# a is a list of lists. make b a flattened list (if a = [[1,2], [3,4]] b will be [1,2,3,4])
	a = [response_times_dict[key] for key in response_times_dict]
	response_axis = []
	for x in a:
		response_axis += x

	# print(len(response_axis))
	# with open('mal_short_response_times.txt', 'w') as f:
	# 	for item in response_axis:
	# 		f.write("%s\n" % item)

	c = [response_timestamp_dict[key] for key in response_timestamp_dict]
	time_axis = []
	for x in c:
		time_axis += x

	# Get only the responses between 11 seconds and 12 seconds, for a zoomed graph
	first_ind = -1
	last_ind = -1

	for i in range(len(response_axis)):
		if time_axis[i] > 20.85:
			first_ind = i
			break
	for i in range(len(response_axis)):
		if time_axis[i] > 21.85:
			last_ind = i-1
			break

	# plot_graph(time_axis, response_axis,'time[sec]', 'response time[sec]', 'WiFi Microjamming - DNS packet delays')

	# show the example signal from 20-21 seconds. it should be [0,1,1,1,1,0,0,1,0,0]
	if SHOW_EXAMPLE_GRAPH == True:
		signal_20_to_21_list = []

		ones = [0.017]
		zeros = [0.0029]

		signal_20_to_21_list += ones * 13
		signal_20_to_21_list += zeros * 25
		signal_20_to_21_list += zeros * 19
		signal_20_to_21_list += zeros * 19
		signal_20_to_21_list += zeros * 19
		signal_20_to_21_list += zeros * 25
		signal_20_to_21_list += ones * 13
		signal_20_to_21_list += ones * 11
		signal_20_to_21_list += zeros * 27
		signal_20_to_21_list += zeros * 17


		plot_example_graph(time_axis[first_ind:last_ind], response_axis[first_ind:last_ind], signal_20_to_21_list,'time[sec]', 'response time[sec]', 'WiFi Microjamming - DNS packet delays')
	else:
		plot_graph(time_axis[first_ind:last_ind], response_axis[first_ind:last_ind],'time[sec]', 'response time[sec]', 'WiFi Microjamming - DNS packet delays')

# Function to plot the response times as a function of time of the example (mal.pcap)
def plot_example_graph(x, y, y2 ,x_label, y_label, title):
	plt.style.use('seaborn-notebook')
	_, ax = plt.subplots(figsize=(10, 7))
	y_plt = ax.plot(x, y)
	y2_plt = ax.plot(x,y2, marker='o', color='r')

	ax.set_title(title, fontsize=50)
	ax.set_xlabel(x_label, fontsize=36)
	ax.set_ylabel(y_label, fontsize=36)
	ax.legend([y_plt[0], y2_plt[0]],   # plot items
           ['DNS packet delays', 'Leaked data'],  
           frameon=True,                                   # legend border
           framealpha=1,                                   # transparency of border
           ncol=2,                                         # num columns
           shadow=True,                                    # shadow on
           borderpad=1, fontsize=36) 
	for label in (ax.get_xticklabels() + ax.get_yticklabels()):
		label.set_fontsize(32)
	plt.show()

# Function to plot the response times as a function of time
def plot_graph(x, y ,x_label, y_label, title):
	plt.style.use('seaborn-notebook')
	_, ax = plt.subplots(figsize=(10, 7))
	_ = ax.plot(x, y)

	ax.set_title(title, fontsize=28)
	ax.set_xlabel(x_label, fontsize=18)
	ax.set_ylabel(y_label, fontsize=18)

	for label in (ax.get_xticklabels() + ax.get_yticklabels()):
		label.set_fontsize(14)
	plt.show()


# Function that gets a pcap of microjam traffic (with\without attack) and returns response times 
# dict - keys are windows' serial number and their value is a list of all corresponding response 
# times
def get_response_times(pcap):
	response_times_dict = {}
	window_counter = 0
	window_start_time = 0
	window_start_index = 0
	requests = []
	response_timestamp = {} # actual time of response, for plot
	first_timestamp = 0

	# Finding first DNS request (keeping its time and index) - start of receive window
	for i in range(len(pcap)):
		pkt = pcap[i]
		if i == 0:
			first_timestamp = pkt.time

		if DNS in pkt and pkt.qr == 0: # a dns request
			window_start_time = pkt.time
			window_start_index = i
			break

	# Finding the next DNS packet
	for i in range(window_start_index, len(pcap)):
		pkt = pcap[i]
		if not DNS in pkt:
			continue

		# if the new DNS packet time is over the time of window - it belongs to the next window (and actually starts it)
		if pkt.time - window_start_time > TIME_OF_WINDOW: # move to next window
			window_counter += 1
			window_start_time = pkt.time

		# if there is a new window, add its serial number as a new key and its value will be a blank list
		# (keys are by a counter, so when the counter increases there's a new key)
		if not window_counter in response_times_dict.keys():
			response_times_dict[window_counter] = list()
			response_timestamp[window_counter] = list()

		# deal with dns request\response: ypu gather requests, find their response time and delete them from the requests list

		# if dns request, append to requests list
		if pkt.qr == 0: # a dns request
			requests.append(pkt)

		# if dns response, search its corresponding request and append to the right window list the response time
		else: # a response from the DNS server
			request_index = search_packet_index_by_id(requests, pkt[PACKET_DNS_FIELD_INDEX].id) # find coressponding request
			if request_index == -1: # tf u responding to??? (maybe just MDNS?)
				continue
			response_times_dict[window_counter].append(pkt.time - requests[request_index].time) # add response time to correct window
			response_timestamp[window_counter].append(pkt.time - first_timestamp)
			del requests[request_index]
	
	return response_times_dict, response_timestamp

# Function that gets DNS queries in the first arg and a packet ID of some DNS response and tries to find which query belongs to the response
def search_packet_index_by_id(packets_list, pkt_id):
	for i in range(len(packets_list)):
		if packets_list[i][PACKET_DNS_FIELD_INDEX].id == pkt_id:
			return i
	return -1

if __name__ == "__main__":
	main()