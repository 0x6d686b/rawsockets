/* LICENSE:
 * Copyright (c) 2013, Mathias Hablützel <mathias@mathiashabluetzel.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * Neither the name of the author nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* NOTE:
 * Be sure not to use this on the loopback interface or you will encounter
 * very strange behaviour like wrong checksums. If you don't believe me fire
 * up any network sniffer and have a look for yourself.
 *
 * If you happen to extend this code with further options and/or functionality
 * please send patches. The purpose of this code is to provide a possibility
 * to play around with ICMP messages.
 *
 * Supported ICMP types/messages:
 * - ICMP ECHO reply (Mathias)
 *
 */

/* how to compile:
 * clang -o icmp_server icmp_server.c
 *   OR
 * gcc -o icmp_server icmp_server.c
 *
 * how to execute:
 * sudo ./icmp_server -i <INTERFACE>
 */

#define __USE_MISC

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

#include "debug.h"

#define MAX_MTU 1500 /* random */

/* calculates a checksum specified in rfc1701 for len bytes over memory area
 * specified in addr
 * 
 * ret: unsigned 16bit int - the checksum
 * 
 * unsigned 16bit int *addr - pointer to memory area
 * unsigned short int len - amount of bytes to build checksum upon
 * 
 */
uint16_t
rfc1701_cksum(uint16_t *addr, unsigned short int len)
{
    /* we need a 32bit int for the carry over */
    uint32_t sum = 0;

    /* first we sum up all words */
    while (len > 1) {
        sum += *addr++;
        len -= sizeof(uint16_t);
    }

    /* if we have a byte left, we sum it up too */
    if (len == 1) {
        sum += *(uint8_t *)addr;
    }

    /* the first nibble is the carry over and we add it to the lower word */
    sum = (sum >> 16) + (sum & 0xffff);
    /* lastly we flip all bits and return the lower word */
    return ((uint16_t) ~sum);
}

static int
is_arg_missing(const int option, const char* optarg, char* argv[])
{
  if (0 == strncmp("-", optarg, 1)) {
    fprintf(stderr, "%s: option requires an argument -- '%c'\n", argv[0], option);
    return 1;
  } else {
    return 0;
  }
}

int
main(int argc, char **argv)
{
    /* ICMP variables */
    int c, ret = 0;
    char *iface = "eth0";
    int sock_eth = 0;
    char buf_in[MAX_MTU], buf_out[MAX_MTU];
    struct ether_header *eth_hdr_in, *eth_hdr_out = NULL;
    struct ip *ip_hdr_in, *ip_hdr_out = NULL;
    struct icmp *icmp_hdr_in, *icmp_hdr_out = NULL;
    int ip_len, icmp_len, icmp_data_len = 0;
    struct ifreq *ifinfo = NULL;
    struct sockaddr_ll sockinfo;

    while ((c = getopt(argc, argv, "i:")) != -1 ) {
      switch (c) {
        case 'i':
          is_arg_missing(c, optarg, argv);
          iface = optarg;
          break;
        default:
          exit(EXIT_FAILURE);
      }
    }

    if ((sock_eth = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /* get interface index */ 
    ifinfo = malloc(sizeof(struct ifreq));
    memset(ifinfo, 0, sizeof(struct ifreq));
    strncpy(ifinfo->ifr_name, iface, IFNAMSIZ);
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

    /* our input is a raw ethernet frame */    
    eth_hdr_in  = (struct ether_header *)buf_in;
    eth_hdr_out  = (struct ether_header *)buf_out;
    /* after the ethernet header comes the ipv4 header */
    ip_hdr_in   = (struct ip *)(buf_in + sizeof(struct ether_header));
    ip_hdr_out   = (struct ip *)(buf_out + sizeof(struct ether_header));
    /* and finally after the ipv4 header comes the icmp packet */
    icmp_hdr_in = (struct icmp *)((unsigned char *)ip_hdr_in + sizeof(struct ip));
    icmp_hdr_out = (struct icmp *)((unsigned char *)ip_hdr_out + sizeof(struct ip));

    while(1) { /* ICMP processing loop */

        /* reading from the raw socket into buf_in */
        if ((ret = recvfrom(sock_eth, buf_in, sizeof(buf_in), 0, NULL, NULL)) < 1) {
            perror("recv");
            exit(1);
        }
       
        /* if we received an ICMP and ICMP-Echo packet we continue */ 
        if (ip_hdr_in->ip_p == IPPROTO_ICMP) {
            if (icmp_hdr_in->icmp_type == ICMP_ECHO) {
                debug("ICMP_ECHO request.\n");

                /* we switch the MAC fields for sending it back */
                memcpy(eth_hdr_out->ether_shost, eth_hdr_in->ether_dhost, 6);
                memcpy(eth_hdr_out->ether_dhost, eth_hdr_in->ether_shost, 6);
                /* it is an ipv4 packet we want to send back */
                eth_hdr_out->ether_type = htons(ETH_P_IP);

                /* Prepare outgoing IP header. */
                ip_hdr_out->ip_v          = ip_hdr_in->ip_v;
                ip_hdr_out->ip_hl         = ip_hdr_in->ip_hl;
                ip_hdr_out->ip_tos        = 0;
                ip_hdr_out->ip_len        = ip_hdr_in->ip_len;
                ip_hdr_out->ip_id         = ip_hdr_in->ip_id;
                /* we set the IP Don't Fragment mask */
                ip_hdr_out->ip_off        = htons(IP_DF);
                ip_hdr_out->ip_ttl        = 64;
                ip_hdr_out->ip_p          = IPPROTO_ICMP;
                ip_hdr_out->ip_sum        = 0;
                /* we switch the dst and src ipv4 */
                ip_hdr_out->ip_src.s_addr = ip_hdr_in->ip_dst.s_addr;
                ip_hdr_out->ip_dst.s_addr = ip_hdr_in->ip_src.s_addr;
                /* calculate the ip header checksum 
                 * bear in mind that ip_hl is a double-word and the parameter
                 * wants a byte number (8bits)
                 */
                ip_hdr_out->ip_sum = rfc1701_cksum((unsigned short *)ip_hdr_out,
                                              ip_hdr_out->ip_hl * 4);

                debug("0x%02x 0x%02x\n", htons(ip_hdr_in->ip_sum), htons(ip_hdr_out->ip_sum));

                /* Prepare outgoing ICMP header. */
                icmp_hdr_out->icmp_type  = 0;
                icmp_hdr_out->icmp_code  = 0;
                icmp_hdr_out->icmp_cksum = 0;
                icmp_hdr_out->icmp_id    = icmp_hdr_in->icmp_id;
                icmp_hdr_out->icmp_seq   = icmp_hdr_in->icmp_seq;
                
                ip_len = ntohs(ip_hdr_out->ip_len);
                icmp_len = ip_len - sizeof(struct ip);
                icmp_data_len = icmp_len - sizeof(struct icmphdr);

                /* we just need to echo the incoming data */
                memcpy(icmp_hdr_out->icmp_data, icmp_hdr_in->icmp_data,
                       icmp_data_len);
                /* finally a little checksum */
                icmp_hdr_out->icmp_cksum =
                    rfc1701_cksum((unsigned short *)icmp_hdr_out, icmp_len);

                /* send it on the wire */
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

