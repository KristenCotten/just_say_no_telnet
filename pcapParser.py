#!/usr/bin/env python3
# A script to work to manipulate a suspcious pcap using pyshark and pandas

# REQUIREMENTS
# apt-get install python3 python3-pip
# pip3 install python-pyshark
# pip3 install pandas
# pip3 install plotly

import pyshark
import pandas as pd
import numpy
from matplotlib import pyplot as plt
import networkx as nx


# LIVE CAPTURE (just for doc purposes)
# liveCap = pyshark.LiveCapture(interface='wlan0')
# print("starting live packet capture")
# for pkt in liveCap.sniff_continuously(packet_count=5):
#     print(pkt)

pcap = pyshark.FileCapture("./malware.pcap")                         # read pcap from file

print(type(pcap))                                                   # is a pyshark capture file
#print(pcap[0])                                                     # displays info from 1st packet

#filter pcap with pyshark (2 methods-display and bpf)
#https_filtered = pyshark.FileCapture('./emotet.pcap', display_filter='https')
#http_filtered = pyshark.FileCapture('./emotet.pcap', bpf_filter='tcp port 80')

# use pandas to create a DF
# used wiresharks pcap to csv functionality for ease 
# pyshark cap object --> csv would be a separate project
df = pd.read_csv('./malware.csv', delimiter = ',')

# data cleaning
df = df.iloc[: , 1:]                                                # drop redundant first column of dataframe
df['Source Port'] = df['Source Port'].fillna(0).astype(int)         # format ports to int instead of floar-fill NaN with 0
df['Dest. Port'] = df['Dest. Port'].fillna(0).astype(int)

print(df)                                                           # will only print first 5 and last 5 rows / same as df.head() or df.tail()
print(df.info())


#Some pcap statisitcs
# Top Source IP
print("\n\n# Top Source IP")
print(df['Source'].describe(),'\n\n')                               # .describe() is used to view basic stats of a dataframe, filtering by Source here

# Top Destination IP
print("# Top Destination IP")
print(df['Destination'].describe(),"\n\n")                          # basic stats re: Destiation

top_src = df['Source'].describe()['top']                            # grabbing just the top ip address to use below

# Who is the top IP talking to
print("# Who is Top IP talking to?")
print(df[df['Source'] == top_src]['Destination'].unique(),"\n\n")   # .unique() for unique values only / no duplicates

# What destination ports is the top IP talking to
print("# What dest. ports is the top IP talking to?")
print(df[df['Source'] == top_src]['Dest. Port'].unique(),"\n\n")

# top IP source ports
print("# What are the top IP's source ports?")
print(df[df['Source'] == top_src]['Source Port'].unique(),"\n\n")

# Unique Source IPs
print("Unique Source IPs")
uniqueSrcIps = df['Source'].unique()
print(uniqueSrcIps,"\n\n")


# Unique Destination IP addresses
print("Unique Destination IP Addresses")
uniqueDestIps = df['Destination'].unique()
print(uniqueDestIps, "\n\n")

# group by protocol
groupByProto = df.groupby('Protocol').Source.count()
print(groupByProto.sort_values())                                   # sort them in number order (instead of alphabetical by protocol)

# visualizing the data
# crosstab to show frequency of source ip to particular dest port
data_crosstab = pd.crosstab(df['Source'], df['Dest. Port'])
print(data_crosstab)

# # display network graph
# ngdf = pd.concat(df['Source'], df["Destination"], keys = ['Source', 'Destination']) #not quite right

# netgraph = nx.Graph()
# netgraph.add_nodes_from(ngdf.Source.unique()) # add source IPs
# netgraph.add_nodes_from(ngdf.Destination.unique()) #add destination IPs
# netgraph.add_edges_from(ngdf.valuess) #add all edges
# nx.draw(netgraph, with_labels=True)
# plt.show()