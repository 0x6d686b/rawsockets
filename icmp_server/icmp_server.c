#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <netpacket/packet.h>

#define MAX_MTU 1500 /* random */

/* calculates a checksum specified in rfc1701 for len bytes over memory area
 * specified in addr
 * 
 * ret: unsigned short int - the checksum
 * 
 * unsigned short int *addr - pointer to memory area
 * (signed) int len - amount of bytes to build checksum upon
 * 
 */
uint16_t
rfc1701_cksum(uint16_t *addr, unsigned short int len)
{
    uint16_t sum = 0;

    while (len > 1) {
        sum += *addr++;
        len -= sizeof(uint16_t);
    }

    if (len == 1) {
        sum += *(uint8_t *)addr;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (~sum);
}

int
main(int argc, char **argv)
{
    /* ICMP variables */
    int ret = 0;
    int sock_eth;
    struct ether_header *eth_hdr_in, *eth_hdr_out;
    struct ip *ip_hdr_in, *ip_hdr_out;
    char buf_in[MAX_MTU], buf_out[MAX_MTU];
    struct icmp *icmp_hdr_in, *icmp_hdr_out;
    int ip_len, icmp_len, icmp_data_len;
    struct ifreq *ifinfo = NULL;
    struct sockaddr_ll sockinfo;

    if ((sock_eth = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /* get interface index */ 
    ifinfo = malloc(sizeof(ifinfo));
    memset(ifinfo, 0, sizeof(ifinfo));
    strncpy(ifinfo->ifr_name, "lo", IFNAMSIZ); /* @FIXIT sorry, hardcoded */
    if ( -1 == ioctl(sock_eth, SIOCGIFINDEX, ifinfo)) {
      perror("can't get interface index");
      exit(EXIT_FAILURE);
    }

    /* bind socket to specific interface */
    memset(&sockinfo, 0, sizeof(sockinfo));
    sockinfo.sll_family = PF_PACKET;
    sockinfo.sll_protocol = htons(ETH_P_ALL);
    sockinfo.sll_ifindex = ifinfo->ifr_ifindex;
    if (-1 == bind(sock_eth, (struct sockaddr*) &sockinfo, sizeof(struct sockaddr_ll))) {
      switch (errno) {
        case EACCES:
        case EPERM:
          perror("not enough privileges to bind socket (are you root?)");
          exit(EXIT_FAILURE);
        default:
          perror("can't bind socket");
          exit(EXIT_FAILURE);
      }
    }
    
    eth_hdr_in  = (struct ether_header *)buf_in;
    eth_hdr_out  = (struct ether_header *)buf_out;
    ip_hdr_in   = (struct ip *)(buf_in + sizeof(struct ether_header));
    icmp_hdr_in = (struct icmp *)((unsigned char *)ip_hdr_in +
                                                   sizeof(struct ip));

    ip_hdr_out   = (struct ip *)(buf_out + sizeof(struct ether_header));
    icmp_hdr_out = (struct icmp *)((unsigned char *)ip_hdr_out + sizeof(struct ip));

    while(1) { /* ICMP processing loop */

        if ((ret = recvfrom(sock_eth, buf_in, sizeof(buf_in), 0, NULL, NULL)) < 1) {
            perror("recv");
            exit(1);
        }
        
        if (ip_hdr_in->ip_p == IPPROTO_ICMP) {
            if (icmp_hdr_in->icmp_type == ICMP_ECHO) {
                /* set MAC header */
                memcpy(eth_hdr_out->ether_shost, eth_hdr_in->ether_dhost, 6);
                memcpy(eth_hdr_out->ether_dhost, eth_hdr_in->ether_shost, 6);
                eth_hdr_out->ether_type = htons(ETH_P_IP);

                /* Prepare outgoing IP header. */
                ip_hdr_out->ip_v          = ip_hdr_in->ip_v;
                ip_hdr_out->ip_hl         = ip_hdr_in->ip_hl;
                ip_hdr_out->ip_tos        = 0;
                ip_hdr_out->ip_len        = ip_hdr_in->ip_len;
                ip_hdr_out->ip_id         = ip_hdr_in->ip_id + 5321;
                ip_hdr_out->ip_off        = htons(IP_DF);
                ip_hdr_out->ip_ttl        = 64;
                ip_hdr_out->ip_p          = IPPROTO_ICMP;
                ip_hdr_out->ip_sum        = 0;
                ip_hdr_out->ip_src.s_addr = ip_hdr_in->ip_dst.s_addr;
                ip_hdr_out->ip_dst.s_addr = ip_hdr_in->ip_src.s_addr;

                ip_hdr_out->ip_sum = rfc1701_cksum((unsigned short *)ip_hdr_out,
                                              ip_hdr_out->ip_hl * 4);

                printf("0x%02x 0x%02x\n", htons(ip_hdr_in->ip_sum), htons(ip_hdr_out->ip_sum));

                /* Prepare outgoing ICMP header. */
                icmp_hdr_out->icmp_type  = 0;
                icmp_hdr_out->icmp_code  = 0;
                icmp_hdr_out->icmp_cksum = 0;
                icmp_hdr_out->icmp_id    = icmp_hdr_in->icmp_id;
                icmp_hdr_out->icmp_seq   = icmp_hdr_in->icmp_seq;
                
                ip_len = ntohs(ip_hdr_out->ip_len);
                icmp_len = ip_len - sizeof(struct ip);
                icmp_data_len =  icmp_len - sizeof(struct icmphdr);

                printf("ICMP_ECHO request.\n");

                memcpy(icmp_hdr_out->icmp_data, icmp_hdr_in->icmp_data,
                       icmp_data_len);

                icmp_hdr_out->icmp_cksum =
                    rfc1701_cksum((unsigned short *)icmp_hdr_out, icmp_len);

                ret = sendto(sock_eth, buf_out, ret, 0,
                                             (struct sockaddr *)&sockinfo,
                                             sizeof(sockinfo));
                 if (ret < 0) {
                   perror("sendto");
                }
           }
        }
    }

    close(sock_eth);
} 

/* __END__ */
