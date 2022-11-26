# Features Extraction

This folder contains the files used to extract features from the network traffic recordings (can be found in the link in the main README).

The scripts included:
* feature_extractor.py - a Python3 script that extract features from a specific .pcap file.
* extract_features.sh - a BASH script that extract features from all the pcap files in a specific folder.
* merge_csv.py - a Python3 script that merges CSV files in a specific folder to one big CSV file. Mostly used after the extract_features.sh script is done.

The test_files folder include small network traffic recordings to test the feature extractor script.
