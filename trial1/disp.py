import argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--inp", type=str, required=True)
    parser.add_argument("-o", "--out_tag", type=str)
    args = parser.parse_args()

    input_csv = args.inp
    assert input_csv.endswith('.csv'), f"Error: invalid file type, expected csv, but got {input_csv}"
    output_tag = args.out_tag if args.out_tag else "dhcp_measure"

    df = pd.read_csv(input_csv)
    colors = {'DISCOVER': 'blue',
              'OFFER': 'green',
              'REQUEST': 'orange',
              'ACK': 'red'}
    
    bin_width = 10
    df['ts'] = df['ts'] - df['ts'].min()
    max_time = df['ts'].max()
    bins = np.arange(0, max_time + bin_width, bin_width)
   
    plt.figure(figsize=(12, 5))
    
    bottom = np.zeros(len(bins)-1)
    count_dict = {}
    for msg_type in df['msgtype'].unique():
        type_times = df[df['msgtype'] == msg_type]['ts']
        counts, _ = np.histogram(type_times, bins)
        count_dict[msg_type] = counts

    for msg_type, counts in count_dict.items():
        plt.bar(bins[:-1], counts, width=bin_width, color=colors[msg_type], alpha=0.4, label=msg_type, bottom=bottom)
        bottom += counts
    
    plt.xlabel('Time (s)')
    plt.ylabel('Packet Number')
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"img/{output_tag}_stats.png")
    
    plt.figure(figsize=(12, 5))
    for msg_type in ['OFFER', 'ACK']:
        type_df = df[df['msgtype'] == msg_type]
        plt.scatter(type_df['ts'], type_df['lease'], color=colors[msg_type], s=30, alpha=0.4, marker='x', label=f"{msg_type} lease")
    
    plt.xlabel("Time (s)")
    plt.ylabel("Lease Time (s)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"img/{output_tag}_leases.png")
