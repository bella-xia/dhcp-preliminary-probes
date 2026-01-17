# Trial 1
This section dedicates to basic passive probes on existing DHCP pattern in public Wi-Fi environments

The structure is organized as:
```
trial 1/
    
    data/ -> stores pcap and csv measurement data

    img/ -> stores statistic analysis graphs

    stats.c -> script used to analyze raw pcap and produce subsequent csv file
    
    disp.py -> script used to convert csv data to matplotlib visuals

    requirements.txt -> requirements for python module used in 'disp.py'
```

## starts measurement
Measurement may be conducted in any mode that produces raw .pcap file. I used tshark cli as primary probe tool. The parser should be able to distinguish exclusively DHCP packets, but for the efficiency of post-analysis the terminal command below may be able to effectively filter only DHCP traffic:
```
sudo tshark -i [wifi interface] -f "udp port 67 or udp port 68" -w [some file name for output]
```
This should produce a raw pcap file that can be used for later parsing and analysis.

## parse measurement
Raw pcap packets are parsed using stats.c, which iteratively filters through ip header, udp header, and ultimately dhcp header to parse relevant information. Currently the script parses raw data into csv with the following format:
```
ts,msgtype,lease
1768619769.765970,REQUEST,0
1768619769.779781,ACK,156467
...
```
ts: the time stamp of each packet

msgtype: whether the packet is DISCOVER, REQUEST, OFFER or ACK

lease: the lease duration specified, only on OFFER and ACK packets

To compile and run the packet, do:
```
gcc -lpcap stats.c
./a.out [name of input pcap file] [name of output csv file]
```

## analyze measurement 
We used Matplotlib module to help visualize processed data. 

To run the visualization, first ensure all pip packages inside requirements.txt are fully installed

To run the script, do
```
python disp.py -i [input csv file name] -o [output tag]
```

For example, if the output tag is specified as "starbucks", then the subsequent visuals will be stored at img/starbuck\_stats.png, etc.

# Trial 2

This section dedicates to creating contained DHCP server-client cluster in docker.
