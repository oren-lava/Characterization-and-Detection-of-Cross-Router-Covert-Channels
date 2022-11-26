# This script's goal is to run crcc_feature_extractor.py on all the files of its current folder
# Pay attention it runs crcc_feature_extractor.py from a specific path. If it wont be there, this script wont work
# Also, remember to change the desired label (0 or 1) in the crcc_feature_extractor.py script before running this script (divide malicious
# and benign pcaps to different folders)

#!/bin/bash

for file in *.pcap
do
	python3 -W ignore /home/cc/orenGit/1_Data_collection/cross-router_CC/feature_extraction/crcc_feature_extractor.py "$file" features_"$file".csv
done

echo "Done!"
