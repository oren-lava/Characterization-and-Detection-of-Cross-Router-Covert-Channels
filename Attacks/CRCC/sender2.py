from scapy.all import *
import time
import datetime
import subprocess
from threading import Thread

# Developer notes:
# ---------------- 
# 1. We use sendpfast to overflow the router with packets.
# 	 This function has a massive overhead which disturbs the sync of the transmission
# 	 (it should be precise accroding to the time windows, specified by WIN_LEN).
# 	 For example, if we want to send packets for 4 seconds, stop and then send 
# 	 another 4 seconds it takes sendpfast approx. one whole second to load!!!
# 	 That's why we used manchester encoding - so we'll never have long series of '0' or '1'
# 	 and we could control the overhead.
#	 How we control it? if we know that sendpfast will need one second to load between transmission
#	 we'll serialize our message (check serialize_payload function for an example), 
# 	 send the '1' bits together and for the zeros, we'll sleep the time needed MINUS the 
# 	 overhead time (if we don't subtract this time, we'll start the next transmission late)
#
# 2. Check out "crcc_conf_tips.txt" to correctly configure the sender.

class sender:

	def __init__(self, conf_dict):
		self.conf_dict = conf_dict

	# "Main"
	# Arguments:
	# Returns:
	def start(self):
		self.__read_data()
		self.__gateway_ip = "192.168.0.1"
		
		# make the packet bits and encode them with manchester code
		packet = self.__build_packet()
		packet = self.__make_manchester(packet)

		# calculate the amount of packets to send in a single time window
		rate = float(self.conf_dict["RATE"])
		win_len = float(self.conf_dict["WIN_LEN"])
		amount = rate * win_len # pps * t = packets

		# build the "scapy_packet" - the packet used to overflow the router when sending '1'
		_, cliMACchaddr = get_if_raw_hwaddr('wlan0')
		cliMAC = get_if_hwaddr('wlan0')
		scapy_packet = None

		if self.conf_dict["TYPE"] == "ARP":
			scapy_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=self.__gateway_ip)
		elif self.conf_dict["TYPE"] == "DHCP":
			scapy_packet = Ether(dst='ff:ff:ff:ff:ff:ff', src=cliMAC, type=0x0800) / IP(src='0.0.0.0', dst='255.255.255.255') / UDP(dport=67,sport=68) / BOOTP(op=1, chaddr=cliMACchaddr, xid=0x10000000) / DHCP(options=[('message-type','inform'), ('end')])

		# start a tcpdump record thread in the background
		record_thread = Thread(target=self.__record)
		record_thread.daemon = True
		record_thread.start()

		# send the information using the scapy packets
		print("Transmission started successfully!")
		self.__send_packet(packet, rate, win_len, scapy_packet, amount)
		print("Transmission ended")

		# let all packets received be processed by tcpdump's filter and end the recording
		time.sleep(2)
		self.__record_process.terminate()


    # Gets an array of bits and encodes them using manchester code
	# Arguments: packet (information to send that sould be encoded)
	# Returns: encoded manchester packet
	def __make_manchester(self, packet):
		man_packet = ""
		for bit in packet:
			if bit == "1":
				man_packet += "10"
			else:
				man_packet += "01"
		return man_packet


    # Reads the data from the file specified in configuration file
	# Arguments:
	# Returns:
	def __read_data(self):
		data_path = self.conf_dict["DATA_PATH"]
		with open(data_path, "r") as f:
			self.data = f.read().rstrip("\n")


	# Builds the packet: Packet is preamble + payload length + payload + suffix
	# Arguments:
	# Returns: the packet (list of bits)
	def __build_packet(self):
		preamble = '10' * 3 + '11'
		const_payload = '1011010'
		suffix = '11111'

		packet = preamble
		packet += self.__make_int_4_bits(len(const_payload))
		packet += const_payload
		packet += suffix
		
		return packet


	# gets a packet (should be after manchester encoding) and makes a list of series of bits
	# for example: the packet: [1 0 0 0 1 1 0 1 0] will become: [[1] [0 0 0] [1 1] [0] [1] [0]]
	# this is done to ease the use of sendpfast (see developer note above)
	# Arguments: the packet (should be after manchester encoding)
	# Returns: serialized packet
	def __serialize_payload(self, packet):
		serialized = []
		temp = ""
		for bit in packet:
			if temp == "":
				temp = bit
			else:
				if bit == temp[0]:
					temp += bit
				else:
					serialized.append(temp)
					temp = bit
		if temp != "":
			serialized.append(temp)
		return serialized


	# Sends a '1' bit ('0' it just sleeps)
	# Arguments: packet (scapy packet), rate, win_len, amount
	# Returns: sendpfast overhead time (see developer notes above)
	def __send_bit(self, packet, rate, win_len, amount):
		start = time.time()
		sendpfast(packet, pps=rate, loop=amount, iface="wlan0")
		end = time.time()
		return end - start - win_len


	# Sends the packet. It uses scapy_packets to overflow the router to send '1'
	# Arguments: packet, rate, win_len, scapy_packet, amount (of scapy_packets to send)
	# Returns:
	def __send_packet(self, packet, rate, win_len, scapy_packet, amount):
		overhead_time = 0
		for seralized_bits in self.__serialize_payload(packet):
			# check current bit series size and change the time (win_len) and amount accordingly
			curr_len = len(seralized_bits)
			new_amount = amount * curr_len
			new_win_len = win_len * curr_len
			if seralized_bits[0] == "1":
				overhead_time = self.__send_bit(scapy_packet, rate, new_win_len, new_amount)
			else:
				print("current bit series win_len:",new_win_len,"overhead time:", overhead_time)
				time.sleep(new_win_len - overhead_time)
					

    # Makes a byte out of a char and pads left side with zeros
	# Arguments: a char
	# Returns: A string that represents a byte
	def __make_char_bits(self, char):
		bits = bin(ord(char))[2:]
		zeros = "0"*(8-len(bits))
		return zeros+bits
	

	# Makes a 4 bits out of an int and pads left side with zeros
	# Arguments: an int
	# Returns: A string that represents 4 bits
	def __make_int_4_bits(self, num):
		bits = bin(num)[2:]
		zeros = "0"*(4-len(bits))
		return zeros+bits


    # Records the network traffic being sent using tcpdump
	# Arguments: 
	# Returns:
	def __record(self):
		# define parameters for tcpdump
		interface_name = "wlan0"
		curr_time = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")

		# create capture file name according to the agreed format
		_, data_filename = os.path.split(self.conf_dict["DATA_PATH"])
		filename = self.conf_dict["ROLE"] + "_" + self.conf_dict["TYPE"] + "_" + self.conf_dict["RATE"] + "pps_" + self.conf_dict["WIN_LEN"] + "s_" + data_filename + ".pcap"
		capture_file_name = self.conf_dict["OUTPUT_PATH"] + "/" + curr_time + "/" + filename
		if not os.path.exists(self.conf_dict["OUTPUT_PATH"] + "/" + curr_time + "/"):
			os.umask(0)
			os.makedirs(self.conf_dict["OUTPUT_PATH"] + "/" + curr_time + "/")

		# start tcpdump
		print("About to create capture with name: " + capture_file_name)
		p = subprocess.Popen(["tcpdump", "-W 1", "-i", interface_name, "-w", capture_file_name], stdout=subprocess.PIPE)
		self.__record_process = p