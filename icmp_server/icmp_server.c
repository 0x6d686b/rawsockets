/*
 * The Towers Of Hanoi
 * ping (ICMP) implementation
 * Copyright (C) 2002 Amit Singh. All Rights Reserved.
 * http://hanoi.kernelthread.com
 *
 * Tested on RedHat Linux 8.0, kernel 2.4.18
 *
 * a) Compile the program by simply doing:
 *
 *      gcc -o hanoicmp hanoicmp.c
 *
 * b) Disable the "normal" ICMP echo response in the kernel by doing:
 *
 *      echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
 *
 *    Thereafter you should not be able to ping the host and get a response.
 *
 * c) Start hanoicmp, which would act as an (single threaded - not too useful
 *    for production use) ICMP server. You should be able to ping the host
 *    and get a response. You should certainly terminate hanoicmp and enable
 *    ICMP echo (if you want it) in /proc/sys.
 *
 * d) Now you can "ping" this host (either from localhost or a remote machine)
 *    and the ping should "work" normally. However, if you use the TOS (type
 *    of service) option of your ping command to pass a TOS value, this value
 *    will be treated as N, the number of disks for the Hanoi puzzle. If N
 *    happens to fall within acceptable limits (say, between 1 and 10, both
 *    inclusive), then instead of getting your usual ICMP echo replies, you
 *    will get a ping packet for each move of the puzzle, with the sequence
 *    number of the packet being in the following format:
 *
 *      pmn
 *
 *    m and n are single digit numbers, one of 1, 2 or 3. mn represents
 *    a move from tower 'm' to tower 'n'. Thus, the three towers in the
 *    puzzle are '1', '2' and '3', with the source tower being '1' and
 *    the destination tower being '3'.
 *
 *    p is an integer representing the number of the move.
 *
 *    For example: pmn = 113 means:
 *
 *      p = 1, it's the first move
 *      m = 1, move the disk from tower '1' ...
 *      n = 3, ... to tower '3'
 *
 * e) The way to ping (on the client side) is as follows:
 *
 *    Linux:
 *
 *      ping -Q N hostname
 *
 *    Solaris:
 *
 *      ping -P N' hostname
 *
 *    There is one final complication. N is the number of disks in the
 *    puzzle if you are pinging from a little endian machine. So, Linux
 *    on x86 is fine, and you can do "ping -Q 3 hostname" to solve a
 *    3 disk puzzle.
 *
 *    However, if you are pinging from SPARC Solaris (big endian), you
 *    must use N' as the number of disks + 128. Thus, to solve the same
 *    3 disk puzzle from Solaris you would do "ping -P 131 -s hostname".
 */

/* Maintain sanity and integrity: 10 disks is enough. */

#ifndef linux
#error "*** Must be compiled on Linux"
#endif

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

#define MAX_MTU 1500 /* random */

unsigned short in_cksum(unsigned short *addr, int len);

/* From Stevens, UNP2ev1 */
unsigned short
in_cksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

int
main(int argc, char **argv)
{
    /* ICMP variables */
    int ret = 0;
    int one = 1;
    int endian = 0;
    int done_id = 0;
    int sock_eth, sock_icmp;
    struct sockaddr_in dst;
    struct ether_header *eth_hdr_in, *eth_hdr_out;
    struct ip *ip_hdr_in, *ip_hdr_out;
    char buf_in[MAX_MTU], buf_out[MAX_MTU];
    struct icmp *icmp_hdr_in, *icmp_hdr_out;
    int ip_len, icmp_len, icmp_data_len;
    struct ifreq *ininfo;

    if ((sock_eth = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
 
    /* get interface index */ 
    memset(ifinfo, 0, sizeof(struct ifreq));
    strncpy(ifinfo->ifr_name, "eth0", IFNAMSIZ); /* @FIXIT sorry, hardcoded */
    if ( -1 == ioctl(sock_eth, SIOCGIFINDEX, ifinfo)) {
      perror("can't get interface index");
      exit(EXIT_FAILURE);
    }

    /* bind socket to specific interface */
    memset(sockinfo, 0, sizeof(*sockinfo));
    sockinfo->sll_family = PF_PACKET;
    sockinfo->sll_protocol = htons(ETH_P_ALL);
    sockinfo->sll_ifindex = ifinfo->ifr_ifindex;
    if (-1 == bind(sock, (struct sockaddr*)sockinfo, sizeof(*sockinfo))) {
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

    ip_hdr_out   = (struct ip *)buf_out;
    icmp_hdr_out = (struct icmp *)(buf_out + sizeof(struct ip));

    while(1) { /* ICMP processing loop */

        if ((ret = recvfrom(sock_eth, buf_in, sizeof(buf_in), 0, NULL, NULL)) < 1) {
            perror("recv");
            exit(1);
        }

        if (ip_hdr_in->ip_p == IPPROTO_ICMP) {
            if (icmp_hdr_in->icmp_type == ICMP_ECHO) {
                /* set MAC header */
                memcpy(eth_hdr_out, eth_hdr_in + 6, 6);
                memcpy(eth_hdr_out + 6, eth_hdr_in, 6);

                /* Prepare outgoing IP header. */
                ip_hdr_out->ip_v          = ip_hdr_in->ip_v;
                ip_hdr_out->ip_hl         = ip_hdr_in->ip_hl;
                ip_hdr_out->ip_tos        = ip_hdr_in->ip_tos;
                ip_hdr_out->ip_tos        = 0;
                ip_hdr_out->ip_len        = ip_hdr_in->ip_len;
                ip_hdr_out->ip_id         = ip_hdr_in->ip_id;
                ip_hdr_out->ip_off        = 0;
                ip_hdr_out->ip_ttl        = 255;
                ip_hdr_out->ip_p          = IPPROTO_ICMP;
                ip_hdr_out->ip_sum        = 0;
                ip_hdr_out->ip_src.s_addr = ip_hdr_in->ip_dst.s_addr;
                ip_hdr_out->ip_dst.s_addr = ip_hdr_in->ip_src.s_addr;

                ip_hdr_out->ip_sum = in_cksum((unsigned short *)buf_out,
                                              ip_hdr_out->ip_hl);

                /* Prepare outgoing ICMP header. */
                icmp_hdr_out->icmp_type  = 0;
                icmp_hdr_out->icmp_code  = 0;
                icmp_hdr_out->icmp_cksum = 0;
                icmp_hdr_out->icmp_id    = icmp_hdr_in->icmp_id;
                icmp_hdr_out->icmp_seq   = icmp_hdr_in->icmp_seq;
                
                ip_len = ntohs(ip_hdr_out->ip_len);
                icmp_len = ip_len - sizeof(struct iphdr);
                icmp_data_len =  icmp_len - sizeof(struct icmphdr);

                printf("ICMP_ECHO request.\n");

                memcpy(icmp_hdr_out->icmp_data, icmp_hdr_in->icmp_data,
                       icmp_data_len);

                icmp_hdr_out->icmp_cksum =
                    in_cksum((unsigned short *)icmp_hdr_out, icmp_len);

                bzero(&dst, sizeof(dst));
                dst.sin_family = AF_INET;
                dst.sin_addr.s_addr = ip_hdr_out->ip_dst.s_addr;

                ret = sendto(sock_eth, buf_out, ip_len, 0,
                                             (struct sockaddr *)&dst,
                                             sizeof(dst));
                 if (ret < 0) {
                   perror("sendto");
                }
           }
        }
    }

    close(sock_eth);
    close(sock_icmp);
} 

/* __END__ */
