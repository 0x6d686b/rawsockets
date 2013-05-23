/*******************************************************************************
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* 
 * How-to-compile: gcc -lrt -std=c99 -pedantic -Werror -Wall -W -O0 -g -o <file>
 * sendframes.c
 */

/* Defining this macro causes header files to expose definitions, required by
 * clock_gettime (see clock_gettime(3) and feature_test_macros(7))
 */
#define _POSIX_C_SOURCE  200112L

/* Hack if we are not under linux, see clock_gettime(3) */
#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif 

const char* VERSION_STRING = __DATE__" KT1 Release";

#define MIN_FRAME_LENGTH 60 /* without preamble SFD and CRC32 */

/* regular ethernet frames: */
#define MAX_FRAMESIZE 1514 /* without preamble SFD and CRC32 */

/* If you want jumboframe support enable this macro: 
#define MAX_FRAMESIZE 65535
*/

/* enables calculation of output rate */
/* #define Teacherversion 1 */

/* adds extra output for internal debugging purposes */
/* #define DEBUG */

#define HEADER_LENGTH 14 /* addresses and type */

#define MAX_FRAMECOUNT 10000000 /* top limit.. to be defined*/

#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <linux/if.h>
#include <stdbool.h>

#include "debug.h"

static uint8_t frame[MAX_FRAMESIZE];
static long int payload_size, frame_count, frame_size = 0;
static bool sig_abort = false;

static void help() {
	printf("\nsendframes %s, sends a number of frames and reports the time needed\n", VERSION_STRING);
	puts("Usage: sendframes [options] -c <frame count> -s <payload size>\n");
	puts("-h help; prints this text");
	puts("-i interface used to send");
	puts("-v verbose output");
	puts("-V prints program version");
	puts("Example: sendframes -i eth0 -c 100 -s 1200");
  exit(EXIT_FAILURE);
}

static void version() {
  printf("\nsendframes %s\n", VERSION_STRING);
  exit(EXIT_FAILURE);
}

int setup_raw_socket(const char *if_name,
                      struct ifreq *ifinfo,
                      struct sockaddr_ll *sockinfo)
{
  int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (-1 == sock) {
    switch (errno) {
      case EACCES:
      case EPERM:
        perror("not enough privileges to create raw socket (are you root?)");
        exit(EXIT_FAILURE);
      default:
        perror("can't create raw socket");
        exit(EXIT_FAILURE);
    }
  }
    
  /* get interface index number */
  memset(ifinfo, 0, sizeof(struct ifreq));
  strncpy(ifinfo->ifr_name, if_name, IFNAMSIZ);
  if ( -1 == ioctl(sock, SIOCGIFINDEX, ifinfo)) {
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
  return sock;
}

void generate_frame(const uint8_t *src_mac,
                      const uint8_t *dst_mac)
{
  int i;
  if (frame == NULL) exit(EXIT_FAILURE);
 
  /* copy destination mac */
  memcpy((char *)frame, (char *)dst_mac, 6);
  /* copy source mac */
  memcpy((char *)frame + 6, (char *)src_mac, 6);
  /* Ethertype */
  memcpy((char *)frame + 12, "\xff\xff", 2);

  /* fill with payload */
  for (i = 0; i < payload_size; ++i) {
    frame[HEADER_LENGTH + i] = 'A' + (i % 26);
  }
  
  /* padding */
  frame_size = HEADER_LENGTH + payload_size;
  while (frame_size < MIN_FRAME_LENGTH) {
    frame[frame_size] = 0;
    ++frame_size;
  }
    
}

static void signal_handler(int sig)
{
  if (sig == SIGINT) {
    /* don't forget to re-set the signal handler, otherwise you'll quit the
     * programm, see signal(2) */
    signal(SIGINT, &signal_handler);
    sig_abort = true;
  }
}

static bool is_arg_missing(const int option, const char* optarg, char* argv[])
{
  if (0 == strncmp("-", optarg, 1)) {
    fprintf(stderr, "%s: option requires an argument -- '%c'\n", argv[0], option);
    help();
    return true;
  } else {
    return false;
  }
}

int main(int argc, char *argv[])
{
  
  /* destination MAC */
  const uint8_t dst_mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}; /* Multicast */
  /* will be the MAC address of the sending NIC */
  uint8_t *src_mac;

  /* For time measurement */ 
  struct timespec time1, time2;
  long double time_used;
 
  /* Socket and frame manipulating pointer
   * (increments a number in the frame) */
  int sock;
  long *frame_nr = (long*) &frame[HEADER_LENGTH];
  struct ifreq ifinfo_lre;
  struct sockaddr_ll sockinfo_lre;

  /* socket buffer options */  
  socklen_t optlen, sendbuff;

  /* interface from argv */
  /* if the user happens to forget the interface */
  char *iface = "eth0";

  bool flag_count = false;
  bool flag_size = false;
  bool verbose = false;
  bool flag_usable_br = false;
  bool flag_nominal_br = false;
  long double bit_rate;

  int c;

  /* catching ctrl-c */
  signal(SIGINT, &signal_handler);

  while ((c = getopt(argc, argv, "Vhnui:c:s:")) != -1) {
    switch (c) {
    case 'h':
      help();
    case 'V':
      version();
    case 'v':
      verbose = true;
      break;
    case 'n':
      flag_nominal_br = true;
      break;
    case 'u':
      flag_usable_br = true;
      break;
    case 'i':
      is_arg_missing(c, optarg, argv);
      iface = optarg;
      break;
    case 'c':
      is_arg_missing(c, optarg, argv);
      flag_count = true;
      frame_count = strtol(optarg, NULL, 10);
      break;
    case 's':
      is_arg_missing(c, optarg, argv);
      flag_size = true;
      payload_size = strtol(optarg, NULL, 10);
      break;
    default:
      help();
    }
  }

	if (!flag_count) {
		fprintf(stderr, "missing parameter -c <frame count>\n");
		help();
	}
	if (!flag_size) {
		fprintf(stderr, "missing parameter -s <payload size>\n");
		help();
	}

  if ((payload_size < 1) || (payload_size > (MAX_FRAMESIZE - HEADER_LENGTH))) {
    fprintf(stderr, "<payload size> must be in range 1..%u\n",
              (MAX_FRAMESIZE - HEADER_LENGTH));   
    exit(EXIT_FAILURE);
  }

  if ((frame_count < 1) || (frame_count > MAX_FRAMECOUNT)) {
    fprintf(stderr, "<frame count> must be in range 1..%u\n", MAX_FRAMECOUNT);
    exit(EXIT_FAILURE);
  }
 
  /* create raw socket */
  sock = setup_raw_socket(iface, &ifinfo_lre, &sockinfo_lre);
    
  /* get own mac address */
  if (ioctl(sock, SIOCGIFHWADDR, &ifinfo_lre) < 0) {
    perror("could not get MAC address");
    exit(EXIT_FAILURE);
  }
  src_mac = (uint8_t*) &ifinfo_lre.ifr_hwaddr.sa_data; 


  /* try setting a higher buffer size */
  optlen = sizeof(sendbuff);

  /* get initial buffer size */
  if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sendbuff, &optlen))
     perror("error getsockopt one");
  else
     debug("buffer size = %d; ", sendbuff);

  /* set new socket buffer size */
  sendbuff = 400000;
  debug("setting buffer to %d; ", sendbuff);

  if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff)))
     fprintf(stderr, "Error setsockopt");

  optlen = sizeof(sendbuff);
  
  /* verify the new buffer size */
  if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sendbuff, &optlen))
     perror("error getsockopt two");
  else
     debug("new send buffer size = %d\n", sendbuff);


  /* generate frame */
  generate_frame(src_mac, dst_mac);
  if (verbose) {
    printf
      ("sending on interface %s %lu frames of size %lu with payload %lu bytes\n",
          argv[1],  frame_count, frame_size, payload_size);
  }
  

  /* get first clock time */ 
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &time1)) {
    perror("could not get first timestamp");
    exit(EXIT_FAILURE);
  }

  /* sending frames on wire */ 
  for ((*frame_nr) = 0; (*frame_nr) < frame_count; ++(*frame_nr)) {
    if (sig_abort) break;
    if ((sendto(sock, frame, frame_size, 0, (struct sockaddr*) &sockinfo_lre, 
           sizeof(sockinfo_lre))) != frame_size) {
      perror("sendto() failed");
      exit(EXIT_FAILURE);
    }
  }
  
  /* Wait until all frames are sent */
  if (close(sock)) {
    perror("closing socket failed");
    exit(EXIT_FAILURE);
  } 

  /* get second clock time */
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &time2)) {
    perror("could not get second timestamp");
    exit(EXIT_FAILURE);
  }

  /* calculate the time difference */
  time_used = (time2.tv_sec - time1.tv_sec) + ((time2.tv_nsec - time1.tv_nsec) / 1e9L) ; 
  if (time_used >= 1.0) 
     printf("time used: %2.9Lf s", time_used);
  else
     printf("time used: %2.9Lf s - result will be inaccurate", time_used);

  if (flag_usable_br) {
    bit_rate =  (8 * (long double)frame_count * (long double)payload_size) * 1e-6 / time_used;
    printf(" : usable bit rate [Mbps] : %4.4Lf", bit_rate);
  }

  if (flag_nominal_br) {
    /* Framerate * (Framesize + Preamble + SFD + CRC + Interframe_Gap) */
    bit_rate = ((long double)frame_count * 8 * ((long double)frame_size + 7 + 1 + 4 + 12) * 1e-6 / time_used);
    printf(" : nominal bit rate [Mbps] : %4.4Lf", bit_rate);
  }

  puts("\n");


#ifdef Teacherversion 
  printf("netto  bitrate [Mbps] : %4.2Lf  : ",
          (8 * frame_count * payload_size) / time_used / 1e6);
  
  /* Framesize + Preamble + SFD + CRC + Interframegap */ 
  printf("brutto bitrate [Mbps] : %4.2Lf \n",
          (frame_count * 8 * (frame_size + 7 + 1 + 4 + 12) / time_used / 1e6));
#endif 

  exit(EXIT_SUCCESS);
}
 
