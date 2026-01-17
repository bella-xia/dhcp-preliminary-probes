#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define DHCP_ACK 5
#define DHCP_DISCOVER 1
#define DHCP_REQUEST 3
#define DHCP_OFFER 2


struct eth_header {
    uint8_t     dest[6];
    uint8_t     src[6];
    uint16_t    type;
};


struct ip_header {
    uint8_t     ver_ihl;
    uint8_t     tos;
    uint16_t    len;
    uint16_t    id;
    uint16_t    frag_off;
    uint8_t     ttl;
    uint8_t     proto;
    uint16_t    cksum;
    uint32_t    src_ip;
    uint32_t    dst_ip;
};


struct udp_header {
    uint16_t    src_port;
    uint16_t    dst_port;
    uint16_t    len;
    uint16_t    cksum;
};


struct dhcp_header {
    uint8_t     op;
    uint8_t     htype;
    uint8_t     hlen;
    uint8_t     hops;
    uint32_t    xid;
    uint16_t    secs;
    uint16_t    flags;
    uint32_t    ciaddr;
    uint32_t    yiaddr;
    uint32_t    siaddr;
    uint32_t    giaddr;
    uint8_t     chaddr[16];
    uint8_t     sname[64];
    uint8_t     file[128];
    uint8_t     options[312];
};


int get_dhcp_msgtype(const u_char *options) {
    int i = 4;
    while (i < 312) {
        if (options[i] == 53) // DHCP message type option
            return options[i+2];
        else if (options[i] == 255) // end option
            break;
        else 
            i += 2 + options[i+1]; // move to next option    
    }
    return 0; // unknown
}

uint32_t get_dhcp_lease(const u_char *options) {
    int i = 4;
    while (i < 312) {
        if (options[i] == 51) // lease time option
        {
            uint32_t lease;
            memcpy(&lease, options + i + 2, 4);
            return ntohl(lease);
        }
        else if (options[i] == 255) // end option
            break;
        else 
            i += 2 + options[i+1]; // move to next option    
    }
    return 0; // unknown / not found
}

int main(int argc, char *argv[]) {
    if (argc != 2 && argc != 3) {
        printf("Usage: %s <pcap file> [Optional <expected output file name>]\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening file: %s\n", errbuf);
        return 1;
    }
    
    struct pcap_pkthdr *header;
    const u_char *packet;
    int res;
    FILE *fp = (argc == 2) ? fopen("data/dhcp_ts.csv", "w") : fopen(argv[2], "w");
    if (!fp) {
        perror("Error opening csv");
        return 1;
    }

    fprintf(fp, "ts,msgtype,lease\n");
    int num_ack = 0, num_disc = 0, num_req = 0, num_off = 0;

    while ((res = pcap_next_ex(handle, &header, &packet)) > 0) {
        if (res == 0) continue; // timeout
        // parse time                    
        double frame_time = header->ts.tv_sec + header->ts.tv_usec / 1e6;

        // parse ip
        struct ip_header *ip = (struct ip_header *)(packet + sizeof(struct eth_header));
        if (ip->proto != 17) continue;

        // parse udp
        int ip_len = (ip->ver_ihl & 0x0F) * 4;
        struct udp_header *udp = (struct udp_header *)((u_char *)ip + ip_len);
        if (ntohs(udp->src_port) != 67 && ntohs(udp->src_port) != 68 &&
            ntohs(udp->dst_port) != 67 && ntohs(udp->dst_port) != 68)
            continue;

        // parse dhcp
        struct dhcp_header *dhcp = (struct dhcp_header *)((u_char *)udp + sizeof(struct udp_header));
        int msg_type = get_dhcp_msgtype(dhcp->options);

        switch (msg_type) {
            case DHCP_ACK:
                {
                    uint32_t lease_time = get_dhcp_lease(dhcp->options);
                    fprintf(fp, "%.6f,%s,%d\n", frame_time, "ACK", lease_time);
                    num_ack++;
                }
                break;
            case DHCP_DISCOVER:
                {
                    fprintf(fp, "%.6f,%s,0\n", frame_time, "DISCOVER");
                    num_disc++;
                }
                break;
            case DHCP_REQUEST:
                {
                    fprintf(fp, "%.6f,%s,0\n", frame_time, "REQUEST");
                    num_req++;
                }
                break;
            case DHCP_OFFER:
                {
                    uint32_t lease_time = get_dhcp_lease(dhcp->options);
                    fprintf(fp, "%.6f,%s,%d\n", frame_time, "OFFER", lease_time);
                    num_off++;
                }
                break;
            default:
                break;
        }

    }
    fclose(fp);

    printf("DHCP statistics\n");
    printf("DISCOVER: %d\n", num_disc);
    printf("OFFER: %d\n", num_off);
    printf("REQUEST: %d\n", num_req);
    printf("ACK: %d\n", num_ack);

    pcap_close(handle);
    return 0;

}
