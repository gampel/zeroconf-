// Simple IPv4 Link-Local addressing (see <http://www.zeroconf.org/>)
// @(#)llip.c, 1.5, Copyright 2003 by Arthur van Hoff (avh@strangeberry.com)
//  
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// See <http://www.gnu.org/copyleft/lesser.html>
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
//
// modify source for LINUX by Itai Fonio (itai@supernasystems.com)
// Modified By Eran Gampel 


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/poll.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <sys/socket.h>

#define LINKLOCAL_ADDR          0xa9fe0000
#define LINKLOCAL_MASK          0xFFFF0000
#define NPROBES                 3
#define PROBE_INTERVAL          200
#define NCLAIMS                 3
#define CLAIM_INTERVAL          200
#define FAILURE_INTERVAL        14000
#define DEFAULT_INTERFACE       "eth0"
#define DEFAULT_SCRIPT          "/usr/sbin/network.script"
#define DEFAULT_ADDRESS         "169.254.x.x"

static char *prog;
#ifdef DEBUG
static int verbose = 0;
#endif

static struct in_addr null_ip = {0};
static struct ether_addr null_addr = {{0, 0, 0, 0, 0, 0}};
static struct ether_addr broadcast_addr = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};

/**
 * ARP packet.
 */
struct arp_packet {
  struct arphdr arp_hdr;
  struct ether_addr source_addr;
  struct in_addr source_ip;
  struct ether_addr target_addr; 
  struct in_addr target_ip;
  unsigned char pad[18];
} __attribute__ ((__packed__));

#ifdef DEBUG
/**
 * Convert an ethernet address to a printable string.
 */
static char *ether2str(const struct ether_addr *addr)
{
  static char str[32];
  snprintf(str, sizeof(str), "%02X:%02X:%02X:%02X:%02X:%02X",
	   addr->ether_addr_octet[0], addr->ether_addr_octet[1],
	   addr->ether_addr_octet[2], addr->ether_addr_octet[3],
	   addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
  return str;
}
#endif

/**
 * Pick a random link local IP address.
 */
static void pick(struct in_addr *ip)
{
  ip->s_addr = htonl(LINKLOCAL_ADDR | ((abs(random()) % 0xFD00) + 0x0100));
}

static int send_pack(int sock,struct sockaddr_ll *ME,struct sockaddr_ll *HE, int op,
		     struct ether_addr *src_eth_addr, struct in_addr *src_addr,
		     struct ether_addr *dst_eth_addr, struct in_addr *dst_addr)
{
  int err;
  unsigned char buf[256];
  struct arphdr *ah = (struct arphdr *) buf;
  unsigned char *p = (unsigned char *) (ah + 1);
  
  ah->ar_hrd = htons(ME->sll_hatype);
  ah->ar_hrd = htons(ARPHRD_ETHER);
  ah->ar_pro = htons(ETH_P_IP);
  ah->ar_hln = ME->sll_halen;
  ah->ar_pln = 4;
  ah->ar_op = htons(ARPOP_REQUEST);
  
  memcpy(p, &ME->sll_addr, ah->ar_hln);
  p += ME->sll_halen;
  
  memcpy(p, src_addr, 4);
  p += 4;
  
  memcpy(p, &HE->sll_addr, ah->ar_hln);
  p += ah->ar_hln;
  
  memcpy(p, dst_addr, 4);
  p += 4;
  
#ifdef DEBUG
  printf("\n **** SENDING ARP **** \n");
  printf("sender_ether_addr: %s\n", ether_ntoa(src_eth_addr));
  printf("target_ether_addr: %s\n", ether_ntoa(dst_eth_addr));
  printf("sender_ip_addr: %s\n", inet_ntoa(*src_addr));
  printf("target_ip_addr: %s\n", inet_ntoa(*dst_addr));
  printf("******************\n");
#endif
  
  err = sendto(sock, buf, p - buf, 0, (struct sockaddr *) HE, sizeof(*HE));
  if (err != (p - buf)) {
    perror("sendto failed");
    return err;
  }
  
  return 1;
}

/**
 * Send out an ARP packet.
 */
static void arp(int fd, struct sockaddr_ll *saddr, int op,
                struct ether_addr *source_addr, struct in_addr source_ip,
                struct ether_addr *target_addr, struct in_addr target_ip)
{
  struct sockaddr_ll he;
  
  // set broadcust mode
  he = *saddr;
  memset(he.sll_addr, -1, he.sll_halen);
  
  send_pack(fd, saddr, &he, op, source_addr, &source_ip, target_addr, &target_ip);
  
  return;
}

/**
 * Run a script.
 */
void run(char *script, char *arg, char *intf, struct in_addr *ip)
{
  int pid, status;
  
  if (script != NULL) {
#ifdef DEBUG
    if (verbose) {
      fprintf(stderr, "%s %s: run %s %s\n", prog, intf, script, arg);
    }
#endif
    pid = fork();
    if (pid < 0) {
      perror("fork failed");
      exit(1);
    }
    if (pid == 0) {
      // child process
      setenv("interface", intf, 1);
      if (ip != NULL) {
	setenv("ip", inet_ntoa(*ip), 1);
      }
      
      execl(script, script, arg, NULL);
      perror("execl failed");
      exit(1);
    }
    if (waitpid(pid, &status, 0) <= 0) {
      perror("waitpid failed");
      exit(1);
    }
    if (WEXITSTATUS(status) != 0) {
      fprintf(stderr, "%s: script %s failed, exit=%d\n", prog, script, WEXITSTATUS(status));
      exit(1);
    }
  }
}

int recv_pack(unsigned char *buf, int len, struct sockaddr_ll *FROM, struct arp_packet *arp_pack)
{
  struct arphdr *ah = (struct arphdr *) buf;
  unsigned char *p = (unsigned char *) (ah + 1);
  
    struct in_addr src_ip, dst_ip;
  
  	/* Filter out wild packets */
  	if (FROM->sll_pkttype != PACKET_HOST &&
  		FROM->sll_pkttype != PACKET_BROADCAST &&
  		FROM->sll_pkttype != PACKET_MULTICAST)
  		return 0;
  
  	/* Only these types are recognised */
  	if (ah->ar_op != htons(ARPOP_REQUEST) && ah->ar_op != htons(ARPOP_REPLY))
  		return 0;
  
  	/* ARPHRD check and this darned FDDI hack here :-( */
  	if (ah->ar_hrd != htons(FROM->sll_hatype) &&
  		(FROM->sll_hatype != ARPHRD_FDDI
  		 || ah->ar_hrd != htons(ARPHRD_ETHER)))
  		return 0;
  
  	/* Protocol must be IP. */
  	if (ah->ar_pro != htons(ETH_P_IP))
  		return 0;
  	if (ah->ar_pln != 4)
  		return 0;
  	if (len < sizeof(*ah) + 2 * (4 + ah->ar_hln))
  		return 0;
  
  // copying information to arp_packet
  memcpy(&(arp_pack->arp_hdr), buf, sizeof(struct arphdr));
  memcpy(&(arp_pack->source_ip), p + ah->ar_hln, sizeof(struct in_addr));
  memcpy(&(arp_pack->source_addr), p, ETH_ALEN);
  memcpy(&(arp_pack->target_ip), p + ah->ar_hln + 4 + ah->ar_hln, sizeof(struct in_addr));
  memcpy(&(arp_pack->target_addr), p + ah->ar_hln + 4, ETH_ALEN);
  
#ifdef DEBUG
  
  printf("RECIEVING ARP WITH:\n");
  printf("sender_ether_addr: %s\n", ether_ntoa((struct ether_addr *)&(arp_pack->source_addr)));
  printf("target_ether_addr: %s\n", ether_ntoa((struct ether_addr *)&(arp_pack->target_addr)));
  printf("sender_ip_addr: %s\n", inet_ntoa(arp_pack->source_ip));
  printf("target_ip_addr: %s\n", inet_ntoa(arp_pack->target_ip));
  printf("******************\n");
  
#endif
  return 1;
}

/**
 * Print usage information.
 */
static void usage(char *msg)
{
  fprintf(stderr, "%s: %s\n\n", prog, msg);
  //    fprintf(stderr, "Usage: %s [OPTIONS]\n");
  fprintf(stderr, "Usage: [OPTIONS]\n");
#ifdef DEBUG
  fprintf(stderr, " -v                verbose\n");
#endif
  fprintf(stderr, " -q                quit after obtaining address\n");
  fprintf(stderr, " -f                do not fork a daemon\n");
  fprintf(stderr, " -n                exit with failure if no address can be obtained\n");
  fprintf(stderr, " -i <interface>    network interface (default %s)\n", DEFAULT_INTERFACE);
  fprintf(stderr, " -s <script>       network script (default %s)\n", DEFAULT_SCRIPT);
  fprintf(stderr, " -ip 169.254.x.x   try this address first (default %s)\n", DEFAULT_ADDRESS);
  exit(1);
}

/**
 * main program
 */
int main(int argc, char *argv[])
{
  char *intf = DEFAULT_INTERFACE;
  char *script = NULL;
  struct sockaddr_ll sockAddr;
  
  struct pollfd fds[1];
  struct arp_packet arpPack;
  struct ifreq ifr;
  struct ether_addr ethAddr;
  struct timeval tv;
  struct in_addr ip = {0};
  int fd;
  int quit = 0;
  int ready = 0;
  int foreground = 0;
  int timeout = 0;
  int nprobes = 0;
  int nclaims = 0;
  int failby = 0;
  int i = 1;
  int ret = 0;
  int ifindex=0;
  int listenfd;
  
  // receive patch - recv_pack args
  int packet_size = 0;
  char packet[4096];
  struct sockaddr_ll from;
  int alen;
  
  // init
  gettimeofday(&tv, NULL);
  prog = argv[0];
  
  // parse arguments
  while (i < argc) {
    char *arg = argv[i++];
    if (strcmp(arg, "-q") == 0) {
      quit = 1;
    } else if (strcmp(arg, "-f") == 0) {
      foreground = 1;
    } else if (strcmp(arg, "-v") == 0) {
#ifdef DEBUG
      verbose = 1;
#endif
    } else if (strcmp(arg, "-n") == 0) {
      failby = time(0) + FAILURE_INTERVAL / 1000;
    } else if (strcmp(arg, "-i") == 0) {
      if ((intf = argv[i++]) == NULL) {
	usage("interface name missing");
      }
    } else if (strcmp(arg, "-s") == 0) {
      if ((script = argv[i++]) == NULL) {
	usage("script missing");
      }
    } else if (strcmp(arg, "-ip") == 0) {
      char *ipstr = argv[i++];
      if (ipstr == NULL) {
	usage("ip address missing");
      }
      if (inet_aton(ipstr, &ip) == 0) {
	usage("invalid ip address");
      }
#ifndef DEBUG
      if ((ntohl(ip.s_addr) & LINKLOCAL_MASK) != LINKLOCAL_ADDR) {
	usage("invalid linklocal address");
      }
#endif
    } else {
      usage("invald argument");
    }
  }
  
  // get a socket handle
  
  fd = socket(PF_PACKET, SOCK_DGRAM, 0);
  if (fd < 0){
    perror("open failed");
    exit(fd);
  }
  
  // interface set up and connectivity tests 
  
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, intf, IFNAMSIZ - 1);
  if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
    perror("Interface not found");
    exit(2);
  }
  
  ifindex = ifr.ifr_ifindex;
  
  if (ioctl(fd, SIOCGIFFLAGS, &ifr)) {
    perror("SIOCGIFFLAGS");
    exit(2);
  }
  
  if (!(ifr.ifr_flags & IFF_UP)) {
    perror("Interface is down");
    exit(2);
  }
  
  if (ifr.ifr_flags & (IFF_NOARP | IFF_LOOPBACK)) {
    perror("Interface is not ARPable");
    exit(2);
  }
  if (ret = ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
    perror("ioctl failed");
    exit(ret);
  }
  
  memcpy(&ethAddr, &ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
  
#ifdef DEBUG
  printf("interface: %s\n",ether2str(&ethAddr));
#endif
  
  // initialize socket address
  memset( &sockAddr, 0, sizeof( sockAddr ) );
  sockAddr.sll_family = AF_PACKET;
  sockAddr.sll_ifindex = ifindex;
  sockAddr.sll_protocol = htons(ETH_P_ARP);
  

  // bind to the ARP socket
  {
    ret = bind(fd, ( struct sockaddr * ) &sockAddr, sizeof(sockAddr));
    if (ret < 0) {
      perror("bind failed");
      exit(ret);
    }
    
    alen = sizeof(sockAddr);
    if (getsockname(fd, (struct sockaddr *) &sockAddr, &alen) == -1) {
      perror("getsockname");
      exit(2);
    }
  }

  // initialize the interface
  run(script, "init", intf, NULL);
  

  // initialize pseudo random selection of IP addresses
  {
    srandom((ethAddr.ether_addr_octet[ETHER_ADDR_LEN-4] << 24) |
	    (ethAddr.ether_addr_octet[ETHER_ADDR_LEN-3] << 16) |
	    (ethAddr.ether_addr_octet[ETHER_ADDR_LEN-2] <<  8) |
	    (ethAddr.ether_addr_octet[ETHER_ADDR_LEN-1] <<  0));
    
    // pick an ip address
    if (ip.s_addr == 0) {
      pick(&ip);
    }
  }

  // prepare for polling
  fds[0].fd = fd;
  fds[0].events = POLLIN | POLLERR;
  
  while (1) {
#ifdef DEBUG
    if (verbose) {
      printf("%s %s: polling %d, nprobes=%d, nclaims=%d\n", prog, intf, timeout, nprobes, nclaims);
    }
#endif
    fds[0].revents = 0;
    
    switch (poll(fds, 1, timeout)) {
    case 0: //sending
      
      // timeout
      if ((failby != 0) && (failby < time(0))) {
	fprintf(stderr, "%s %s: failed to obtain address\n", prog, intf);
	exit(1);
      }

      if (nprobes < NPROBES) {
	// ARP probe

#ifdef DEBUG
	if (verbose) {
	  fprintf(stderr, "%s %s: ARP probe %s\n", prog, intf, inet_ntoa(ip));
	}
#endif	
	arp(fd, &sockAddr, ARPOP_REQUEST, &ethAddr, null_ip, &null_addr, ip);
	nprobes++;
	timeout = PROBE_INTERVAL;

      } else if (nclaims < NCLAIMS) {

	// ARP claim
#ifdef DEBUG
	if (verbose) {
	  fprintf(stderr, "%s %s: ARP claim %s\n", prog, intf, inet_ntoa(ip));
	}
#endif
	arp(fd, &sockAddr, ARPOP_REQUEST, &ethAddr, ip, &ethAddr, ip);
	nclaims++;
	timeout = CLAIM_INTERVAL;
      } else {

	// ARP take
#ifdef DEBUG
	if (verbose) {
	  fprintf(stderr, "%s %s: use %s\n", prog, intf, inet_ntoa(ip));
	}
#endif
	ready = 1;
	timeout = -1;
	failby = 0;
	run(script, "config", intf, &ip);
	
	if (quit) {
	  shutdown( fd, 0x02 );
	  close( fd );
	  exit(0);
	}
	if (!foreground) {
	  if (daemon(0, 0) < 0) {
	    perror("daemon failed");
	    exit(1);
	  }
	}
      }
      break;
      
    case 1:
      
      // i/o event
      if ((fds[0].revents & POLLIN) == 0) {
	if (fds[0].revents & POLLERR) {
	  fprintf(stderr, "%s %s: I/O error\n", prog, intf);
	  exit(1);
	}
	continue;
      }
      
      // read ARP packet to a buffer 
      alen = sizeof(from);
      if ((packet_size = recvfrom(fd, packet, sizeof(packet), 0,
				  (struct sockaddr *) &from, &alen)) < 0) {
	perror("recv failed");
	exit(1);
      }
      
      // parse arp packet into arp_packet p
      if (!recv_pack(packet, packet_size, &from, &arpPack ))
	continue;
      
#ifdef DEBUG
      if (verbose) {
	printf("%s %s: recv arp op=%d, ", prog, intf, ntohs(arpPack.arp_hdr.ar_op));
	printf("source=%s %s,", ether2str(&arpPack.source_addr), inet_ntoa(arpPack.source_ip));
	printf("target=%s %s\n", ether2str(&arpPack.target_addr),inet_ntoa(arpPack.target_ip));
      }
#endif     
      if (arpPack.source_ip.s_addr == ip.s_addr) {
	
#ifdef DEBUG
	if (verbose) {
	  fprintf(stderr, "%s %s: ARP conflict %s\n", prog, intf, inet_ntoa(ip));
	}
#endif	

	//restart ip request
	pick(&ip);
	timeout = 0;
	nprobes = 0;
	nclaims = 0;
	if (ready) {
	  ready = 0;
	  run(script, "deconfig", intf, 0);
	}
      }
      break;
      
    default:
      perror("poll failed");
      exit(1);
    }
  }
}
