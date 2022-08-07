## This is the main file of CRCC.
## This should be on two different computers - one will act as a receiver, the other as a sender.
## Before starting the script, use sync_time.sh on both computers to sync their time

import sys
import argparse
import conf_parser
from sender import sender
#from receiver_backup import receiver
#from receiver import receiver
from receiver2 import receiver


def main():
	parser = argparse.ArgumentParser(description="") # TODO: add description
	parser.add_argument("conf_file_path", type=str, nargs=1, help="Configuration file path")
	args = parser.parse_args()

	conf_p = conf_parser.conf_parser(args.conf_file_path[0])
	conf_dict = conf_p.read_conf()

	# We're the sender
	if conf_dict["ROLE"] == "SEN":
		sen = sender(conf_dict)
		sen.start()

	# We're the receiver
	elif conf_dict["ROLE"] == "REC":
		rec = receiver(conf_dict)
		msg = rec.start()
#		print(msg)


main()