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

typedef struct {
    // meta: timestamp
    double ts; 

    // ethernet
    uint8_t src_mac[6];
    uint8_t dst_mac[6];

    // ip
    uint32_t src_ip;
    uint32_t dst_ip;

    // dhcp fixed
    uint8_t msg_type;
    uint32_t xid;
    uint32_t yiaddr;
    uint8_t chaddr[6];

    // dhcp options
    uint32_t request_ip;
    uint32_t server_id;
    uint32_t lease_time;
} dhcp_event_t;

void parse_dhcp_options(const uint8_t *opts, dhcp_event_t *ev) {
    int i = 4;

    while (i < 312) {

        uint8_t code = opts[i];

        if (code == 0) { // padding
            i++;
            continue;
        }
        if (code == 255) break; // end of options
        
        uint8_t len = opts[i+1];
        const uint8_t *data = opts + i + 2;

        switch (code) {
            case 50: 
                {
                    memcpy(&ev->request_ip, data, 4); 
                }
                break;
            case 51:
                {
                    memcpy(&ev->lease_time, data, 4);
                }
                break;
            case 53:
                {
                    ev->msg_type = data[0];
                }
                break;
            case 54:
                {
                    memcpy(&ev->server_id, data, 4);
                }
                break;
            default:
                break;
        }
        i += 2 + len;
    }
}

int parse_dhcp_packet(const u_char *pkt,
                      const struct pcap_pkthdr *hdr,
                      dhcp_event_t *ev) {
    
    // parse time
    ev->ts = hdr->ts.tv_sec + hdr->ts.tv_usec / 1e6;
    
    // parse ethernet
    struct eth_header *eth = (struct eth_header *)pkt;
    memcpy(ev->src_mac, eth->src, 6);
    memcpy(ev->dst_mac, eth->dest, 6);

    // parse ip
    struct ip_header *ip = (struct ip_header *)(pkt + sizeof(struct eth_header));
    if (ip->proto != 17) return 0;
    ev->src_ip = ip->src_ip;
    ev->dst_ip = ip->dst_ip;

    // parse udp
    int ip_len = (ip->ver_ihl & 0x0F) * 4;
    struct udp_header *udp = (struct udp_header *)((u_char *)ip + ip_len);
    if (ntohs(udp->src_port) != 67 && ntohs(udp->src_port) != 68 &&
        ntohs(udp->dst_port) != 67 && ntohs(udp->dst_port) != 68)
        return 0;

    // parse dhcp
    struct dhcp_header *dhcp = (struct dhcp_header *)((u_char *)udp + sizeof(struct udp_header));
    ev->xid = ntohl(dhcp->xid);
    ev->yiaddr = dhcp->yiaddr;
    memcpy(ev->chaddr, dhcp->chaddr, 6);
    parse_dhcp_options(dhcp->options, ev);

    return (ev->msg_type != 0);
}

void emit_csv(FILE *fp, const dhcp_event_t *ev) {
    char src_mac[18], dst_mac[18];
    sprintf(src_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
            ev->src_mac[0], ev->src_mac[1], ev->src_mac[2],
            ev->src_mac[3], ev->src_mac[4], ev->src_mac[5]);
    sprintf(dst_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
            ev->dst_mac[0], ev->dst_mac[1], ev->dst_mac[2],
            ev->dst_mac[3], ev->dst_mac[4], ev->dst_mac[5]);

    
    struct in_addr a;

    fprintf(fp, "%.6f,%d,%s,%s,",
                ev->ts,
                ev->msg_type,
                src_mac,
                dst_mac);
    a.s_addr = ev->src_ip;
    fprintf(fp, "%s,", inet_ntoa(a));
    a.s_addr = ev->dst_ip;
    fprintf(fp, "%s,", inet_ntoa(a));
    a.s_addr = ev->yiaddr;
    fprintf(fp, "%s,", inet_ntoa(a));
    a.s_addr = ev->request_ip;
    fprintf(fp, "%s,", inet_ntoa(a));
    a.s_addr = ev->server_id;
    fprintf(fp, "%s,", inet_ntoa(a));
    fprintf(fp, "%u\n",
            ntohl(ev->lease_time));
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

    fprintf(fp, 
            "ts,msgtype,src_mac,dst_mac,src_ip,dst_ip,yiaddr,requested_ip,server_id,lease\n");

    dhcp_event_t ev;

    while ((res = pcap_next_ex(handle, &header, &packet)) > 0) {
        if (res == 0) continue; // timeout
        
        memset(&ev, 0x00, sizeof(dhcp_event_t));

        if (parse_dhcp_packet(packet, header, &ev)) 
            emit_csv(fp, &ev);

    }
    fclose(fp);
    pcap_close(handle);
    return 0;
}
