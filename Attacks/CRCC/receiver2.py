from scapy.all import *
import time
import subprocess
from datetime import datetime, timedelta, date
from threading import Thread
import numpy as np
from math import log10, floor

# Developer notes:
# ---------------- 
# 1. Note that besides the config file, you need to change T according to the sender's 
#    WIN_LEN.
#    if you start the sender script, in the end it'll print T. update the value here
#    so the receiver could work properly.
#    Also, update bit_threshold and message_start_threshold variable (in __decode function)
#    according to the sender's TYPE and RATE (in its config file). see "crcc_conf_tips.txt"
#    for help in the configuration.
#
# 2. Because of sendpfast huge overhead (see developer notes in the sender), we just
#    transmit continously (until num_sec_to_measure). If you try to divide the transmission
#    you'll get delays of one second between them.
#
# 3. Usually, when decoding the time windows responses, we take each window's median (not 
#    average) as the representive value of this window.
#    why use the median? sometimes the window division is not optimal and we mistakely take
#    take large response times from the next window (assuming its a '1'). So, if we're not
#    wrong by half a window (or more), the median will be around the normal response time
#    (because at least half the values are normal sized)
# 
# 4. We noticed that when the receiver is transmiting at a high rate, it stuffs the router
#    and makes it answer lots of requests in a batch (instead of answering one by one)
#    This causes high response times with no justification. So we lowered the receiver rate
#    and it helped (too high rate: 20pps, acceptable rate 5pps with WIN_LEN=2) 


class receiver:

    def __init__(self, conf_dict):
        self.conf_dict = conf_dict
    
    # "Main"
    # Arguments: 
    # Returns: True\False - depends on the success of receiving the data by protocol
    def start(self):
        # config parameters
        T = 98 # whenever you change the sender's WIN_LEN, measure it again.
        num_sec_to_measure = T + 60
        packet_type = self.conf_dict["TYPE"]
        rate = float(self.conf_dict["RATE"])

        # measure normal response times
        print("Measuring normal responses..")
        normal_response_times = self.__measure_normal_response_times()
        print("Done measuring normal responses. Starting to record and measure. Please start the Sender")
        
        # create output filename
        output_filename = self.__create_output_filename()

        # record the traffic (while measuring the actual message's reponse times)
        Thread(target=self.__record, args=[output_filename]).start()

        # measure the actual response times
        amount = num_sec_to_measure * rate
        self.__send_packet(packet_type, rate, amount)
        print("Done measuring.")

        # read the response times from the recorded pcap
        actual_response_times = self.__read_responses(output_filename)

        # decode the actual reponse times to bits
        print("Starts decoding..")
        decoded_bits = self.__decode(normal_response_times, actual_response_times)
        
        # parse the decoded bits by the protocol (preamble, packet size, payload, suffix)
        parse_ret = self.__parse(decoded_bits)
        if parse_ret == False:
            print("Parsing failed..")
        
        # everything was successful, return True (the payload is printed by the parse func)
        time.sleep(2)
        self.__record_process.terminate()
        print("Stopped recording successfully!")
        return True


    # Sends a packet list accodring to type, rate and amount
    # Arguments: packet type, amount, rate (in pps)
    # Returns:
    def __send_packet(self, packet_type, rate, amount):
        # get wlan parameters (router IP, raw headers)
        gateway_ip = '192.168.0.1'
        _, cliMACchaddr = get_if_raw_hwaddr('wlan0')
        cliMAC = get_if_hwaddr('wlan0')
        packet = None
        
        # generate packet list according to TYPE
        pl = [] # pl = packet list
        for i in range(1,int(amount)+1):
            if packet_type == "ARP":
        	    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=gateway_ip)
            elif packet_type == "DHCP":
                packet = Ether(dst='ff:ff:ff:ff:ff:ff', src=cliMAC, type=0x0800) / IP(src='0.0.0.0', dst='255.255.255.255') / UDP(dport=67,sport=68) / BOOTP(op=1, chaddr=cliMACchaddr, xid=int(i)) / DHCP(options=[('message-type','discover'), ('end')])
            else:
                raise Exception("Bad packet type")

            pl.append(packet)

        # send the packet list
        sendpfast(pl, pps=rate, loop=1, file_cache=True, iface="wlan0")


    # Decodes Manchester encoding
    # Arguments: the bits received
    # Returns: a list of bits that were decoded from manchester encoding
    def __decode_manchester(self, packet):
        decoded = []
        false_val_before_msg_counter = 0

        # check number of false bits before the first true
        for bit in packet:
            if bit == False:
                false_val_before_msg_counter += 1
            else:
                break

        # if before the message started, we get an odd number of 0 bits (cause the sender didn't send anything) it could mess up the manchester decode
        if false_val_before_msg_counter % 2 == 1:
            packet.pop(0)
        if len(packet) % 2 == 1:
            packet.pop()
        
        # decode the bits with manchester code
        for i in range(0, len(packet), 2):
            if i + 1 >= len(packet):
                self.__record_process.terminate()
                print("Stopped recording successfully!")
                raise Exception("Manchester error: odd number of bits")
            
            if packet[i] == True and packet[i+1] == False:
                decoded.append(True)
            elif packet[i] == False and packet[i+1] == True:
                decoded.append(False)
            else:
                decoded.append(None)
        return decoded
                
    
    # Measures normal response times. sends 50 packet at a rate of 5pps
    # Arguments:
    # Returns: list of normal reponse times
    def __measure_normal_response_times(self):
        packet_type = self.conf_dict["TYPE"]
        response_times = []
        normal_response_filename = "/home/pi/CRCC_output/normal.pcap"

        # start a record thread
        Thread(target=self.__record, args=[normal_response_filename]).start()

        # send packets at a low rate (50 packet with 5pps)
        self.__send_packet(packet_type, 5, 50)
        
        # stop record thread
        time.sleep(2)
        self.__record_process.terminate()
        print("Stopped recording normal responses successfully!")

        # read the response times and delete the recording
        response_times = self.__read_responses(normal_response_filename)
        os.remove(normal_response_filename)
        
        # print the avg and std and return the normal response times list
        print("Average response time: ", str(np.mean(response_times)))
        return response_times
    

    # Gets the wlan0 interface's MAC address
    # Arguments:
    # Returns: wlan0 interface's MAC address (as a string)
    def __get_my_mac(self):
        my_ifs = get_if_list()
        for iface in my_ifs:
            if iface == 'wlan0':
                my_mac = get_if_hwaddr(iface)

        return (str(my_mac))


    # Gets the transaction ID (xid) from a DHCP packet
    # Arguments: scapy packet
    # Returns: xid (int)
    def __get_dhcp_xid(self, packet):
        if (DHCP not in packet):
            print("NOT DHCP!!")
            return -1
        
        dhcp_layer = packet.getlayer(BOOTP)
        xid = dhcp_layer.xid
        return xid


    # Reads the response times from the recorded pcap file
    # Arguments: pcap file path
    # Returns: list of response times
    def __read_responses(self, file_path):
        # read pcap recording file
        pkts = rdpcap(file_path)
        
        ARP_request = []
        ARP_reply = []
        DHCP_discover = []
        DHCP_offer = []
        
        # get self wlan0 MAC and IP address
        rec_mac = self.__get_my_mac()

        # handle ARP case
        if(self.conf_dict["TYPE"] == "ARP"):
            # divide the packets to request and reply lists
            for pkt in pkts:
                if (ARP not in pkt):
                    continue
                # ARP request --> type = 1
                if(pkt[ARP].op == 1 and rec_mac == pkt[Ether].src): 
                    ARP_request.append(pkt.time)
                # ARP reply --> type = 2   
                if(pkt[ARP].op == 2 and rec_mac == pkt[Ether].dst): 
                    ARP_reply.append(pkt.time)
            
            print("ARP_request len: ", str(len(ARP_request)))
            print("ARP_reply len: ", str(len(ARP_reply)))
            
            # subtract the time of corresponding request\reply to get response time
            responses = []
            for i in range(len(ARP_reply)):
                x = ARP_reply[i] - ARP_request[i]
                responses.append(x)
        
        # handle DHCP case
        elif(self.conf_dict["TYPE"] == "DHCP"):
            for pkt in pkts:
                if (DHCP not in pkt):
                    continue
                # DHCP discover --> type = 1
                if(pkt[DHCP].options[0][1] == 1 and rec_mac == pkt[Ether].src):
                    DHCP_discover.append([pkt.time, self.__get_dhcp_xid(pkt)])

                # DHCP offer --> type = 2  
                if(pkt[DHCP].options[0][1] == 2 and rec_mac == pkt[Ether].dst):
                    DHCP_offer.append([pkt.time, self.__get_dhcp_xid(pkt)])

            print("DHCP_discover len: ", str(len(DHCP_discover)))
            print("DHCP_offer len: ", str(len(DHCP_offer)))

            # get dhcp response times
            responses = []
            miss = bool(1)
            found_match = 0

            # case 1: found discovery-offer match: append response time
            for disc in DHCP_discover:
                for off in DHCP_offer:
                    if(disc[1] == off[1]):
                        x = off[0] - disc[0]
                        responses.append(x)
                        found_match = 1
                        break
                
            # case 2: didn't find match: append alternating 0\1 to reduce effect on median
                if(found_match == 0):
                    responses.append(miss)
                    print("popping discover #" + str(disc[1]))
                    miss = bool(miss) ^ bool(1)
                else:
                    found_match = 0
            
        else:
            raise Exception("invalid TYPE in config file")

        # write the responses to txt file (for testing)
        with open('responses.txt', 'w') as filehandle:
            for listitem in responses:
                filehandle.write('%s\n' % listitem)

        return responses
    

    # Rounds number to 3 significant digits
    # Arguments: num
    # Returns: rounded num
    def __round_num(self, num):
        new_num = round(num, 3-int(floor(log10(abs(num))))-1)
        return new_num


    # Take the responses list and divide it into time windows (according to WIN_LEN)
    # Arguments: actual responses list, message start index
    # Returns: window list (each contains a constant number of responses)
    def __make_win_list(self, responses, message_start_index):
        # Start dividing from the found start index
        responses = responses[message_start_index:]

		# Calculate the number of response times samples in a single T-window
        win_response_num = float(self.conf_dict["WIN_LEN"]) * float(self.conf_dict["RATE"])
        win_response_num = int(win_response_num)
        win_response_num = max(1,win_response_num) # avoid infinite loops

        # create the windows and append them to a list
        win_list = []
        i=0
        while i < len(responses):
            if i+win_response_num > len(responses):
                break
            win = responses[i:i+win_response_num]
            i += win_response_num
            win_list.append(win)

        return win_list


    # Decodes the response times to bits.
    # Arguments: normal_response_times, actual_response_times
    # Returns: decoded_bits (boolean list). Those are manchester encoded bits
    def __decode(self, normal_response_times, actual_response_times):
        # calculate average response time and std of normal response times
        avg_normal_response = sum(normal_response_times) / len(normal_response_times)

        # define the message start threshold
        message_start_index = -1
        message_start_threshold = 1.5*float(avg_normal_response)

        # turn the responses to 'float' (they're decimal.Decimal)
        actual_response_times = [float(x) for x in actual_response_times]
        
        # find where the message starts by finding a response bigger than the threshold
        for i in range (len(actual_response_times)):
            if actual_response_times[i] > message_start_threshold:
                message_start_index = i
                break
        print("message_start_index:",message_start_index)

        if message_start_index == -1:
            raise Exception("Couldn't find out-of-normal response time")

        # divide to windows - each window will contain the amount of responses that is supposed to be in WIN_LEN time
        win_list = self.__make_win_list(actual_response_times, message_start_index)
        
        # get the median of the responses from each time window
        j=0
        median_list = []
        for win in win_list:
            median_win = np.median(win)
            median_list.append(self.__round_num(median_win))
            print("Window number",str(j),"length:",str(len(win)))
            print("Window number",str(j),"first sample:",str(win[0]))
            print("Window number",str(j),"median:",str(median_win))
            print("\n")
            j += 1
        
        # define the bit threshold - above it, the window is equivalent to '1'
        bit_threshold = float(np.mean(median_list[-6:])) + 0.005
        print("Bit threshold:", str(bit_threshold))
        print("avg_normal_response:", str(avg_normal_response))

        # decode the windows according to the bit threshold
        decoded_bits = []
        for median_win in median_list:
            if median_win > bit_threshold:
                decoded_bits.append(True)
            else:
                decoded_bits.append(False)
        
        print("Median list: ", median_list)
        print("current bit threshold: ", bit_threshold)
        print("Manchester bits:",decoded_bits)

        return decoded_bits


    # Creates the output pcap filename according to the time and date
    # Arguments: 
    # Returns: output filename (string)
    def __create_output_filename(self):
        curr_time = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
        _, data_filename = os.path.split(self.conf_dict["DATA_PATH"])
        filename = self.conf_dict["ROLE"] + "_" + self.conf_dict["TYPE"] + "_" + self.conf_dict["RATE"] + "pps_" + self.conf_dict["WIN_LEN"] + "s_" + data_filename + ".pcap"
        capture_file_name = self.conf_dict["OUTPUT_PATH"] + "/" + curr_time + "/" + filename
        if not os.path.exists(self.conf_dict["OUTPUT_PATH"] + "/" + curr_time + "/"):
        	os.umask(0)
        	os.makedirs(self.conf_dict["OUTPUT_PATH"] + "/" + curr_time + "/")

        return capture_file_name


    # Records the network traffic being sent using tcpdump
    # Arguments: output pcap filename
    # Returns:
    def __record(self, capture_file_name):

        # define parameters for tcpdump
        interface_name = "wlan0"

        # start tcpdump and save the process handle
        print("About to create capture with name: " + capture_file_name)
        p = subprocess.Popen(["tcpdump", "-W 1", "-i", interface_name, "-w", capture_file_name], stdout=subprocess.PIPE)
        self.__record_process = p


    # Parses the decoded bits
    # Arguments: decoded_bits
    # Returns: 0 = success, 1 = failed to parse
    # TODO: add support for variable packet size (so it wont be const size of 4 bits)
    def __parse(self, decoded_bits):
        # find preamble '10101011' (encoded with Manchester)
        preamble = [True, False, False, True, True, False, False, True, True, False, False, True, True, False, True, False]
        pre_index = -1

        for i in range(len(decoded_bits)):
            if decoded_bits[i] == preamble[0] and decoded_bits[i:i+len(preamble)] == preamble:
                pre_index = i
        
        if pre_index == -1:
            print("Couldn't find preamble")
            return False

        # decode Manchester
        decoded_bits = self.__decode_manchester(decoded_bits[pre_index:])
        preamble_len = int(len(preamble)/2)
        # get packet size (will always be 4 bits)
        packet_size_bits = []

        for j in range(preamble_len, preamble_len+4):
            packet_size_bits.append(decoded_bits[j])

        packet_size = sum(v<<i for i, v in enumerate(packet_size_bits[::-1])) # turn the bits to int

        if packet_size <= 0:
            print("Zero or negative packet size")
            return False
        
        # get payload
        payload_bits = []

        for k in range(preamble_len+4, preamble_len+4+packet_size):
            payload_bits.append(decoded_bits[k])

        # make sure suffix is right, otherwise return false
        suffix = [True, True, True, True, True]
        found_suffix_flag = 0

        for l in range(preamble_len+4+packet_size, preamble_len+4+packet_size+5):
            if decoded_bits[l] == suffix[0] and decoded_bits[l:l+len(suffix)] == suffix:
                found_suffix_flag = 1

        if found_suffix_flag == 0:
            print("Couldn't find suffix")
            return False

        print("Parsing successful!")
        print("The message received: " + str(payload_bits))

        # calculate BER (for testing)
        sender_payload = [True, False, True, True, False, True, False]
        err_bits_count = 0
        for i in range(len(sender_payload)):
            if sender_payload[i] != payload_bits[i]:
                err_bits_count += 1
		
        BER = err_bits_count / len(payload_bits)
        print("BER: " + str(BER))

        return True