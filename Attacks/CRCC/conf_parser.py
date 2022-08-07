import json

class conf_parser:

	def __init__(self, conf_file_path):
		self.conf_file_path = conf_file_path
		conf_name_prefix = "CRCC_conf"
		conf_name_suffix = ".json"
		if not (self.conf_file_path.startswith(conf_name_prefix) and self.conf_file_path.endswith(conf_name_suffix)):
			raise Exception('Configuration file should be named with "CRCC_conf" as prefix and ".json" as suffix.')

	# Reads configuration file and parses as json
	# Returns: None
	def read_conf(self):
		with open(self.conf_file_path, "r") as f:
			try:
				self.conf_dict = json.loads(f.read())
			except:
				raise Exception("Could not parse configuration file as json")

		if not self.__verify_conf():
			raise Exception("There's a problem with the configuration file")
		return self.conf_dict

	# Verifies configuration file is as expected
	# Returns: None
	def __verify_conf(self):
		conf_params = {"ROLE" : 0, "TYPE" : 0, "RATE" : 0, "WIN_LEN" : 0, "DATA_PATH" : 0, "DATA_PRINT" : 0, "OUTPUT_PATH" : 0}

		# Check if it contains only necessary params (and in caps)
		for k in self.conf_dict.keys():
			if k != k.upper():
				return False

			if k not in conf_params.keys():
				return False 
			else:
				conf_params[k] += 1

		# Check if params are given exactly once
		for val in conf_params.values():
			if val != 1:
				return False 

		# Check if role is not soemthing other than SEN or REC
		if self.conf_dict["ROLE"] != "SEN" and self.conf_dict["ROLE"] != "REC":
			return False

		# Check if type is not soemthing other than ARP or DHCP
		if self.conf_dict["TYPE"] != "ARP" and self.conf_dict["TYPE"] != "DHCP":
			return False

		# Check if data_print is not soemthing other than 1 or 0
		if self.conf_dict["DATA_PRINT"] != "1" and self.conf_dict["DATA_PRINT"] != "0":
			return False

		return True

	def get_conf_dict(self):
		return self.conf_dict