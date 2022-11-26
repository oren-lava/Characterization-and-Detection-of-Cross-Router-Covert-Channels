import os
import glob
import pandas as pd

os.chdir("/home/cc/orenGit/1_Data_collection/cross-router_CC/split_pcap_full_1/features")

extension = 'csv'
all_filenames = [i for i in glob.glob('*.{}'.format(extension))]

#combine all files in the list
combined_csv = pd.concat([pd.read_csv(f) for f in all_filenames ])
#export to csv
combined_csv.to_csv( "combined_csv.csv", index=False, encoding='utf-8-sig')
