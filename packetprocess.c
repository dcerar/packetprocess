#include <pcap.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct ethernetheader {
        unsigned char ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        unsigned char ether_shost[ETHER_ADDR_LEN];    /* source host address */
        unsigned short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct ipheader {
        unsigned char  ip_vhl;                 /* version << 4 | header length >> 2 */
        unsigned char  ip_tos;                 /* type of service */
        unsigned short ip_len;                 /* total length */
        unsigned short ip_id;                  /* identification */
        unsigned short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        unsigned char  ip_ttl;                 /* time to live */
        unsigned char  ip_p;                   /* protocol */
        unsigned short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef unsigned int tcp_seq;

struct tcpheader {
        unsigned short th_sport;               /* source port */
        unsigned short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        unsigned char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        unsigned char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        unsigned short th_win;                 /* window */
        unsigned short th_sum;                 /* checksum */
        unsigned short th_urp;                 /* urgent pointer */
};

struct udpheader {
	unsigned short int udp_srcport;
	unsigned short int udp_destport;
        unsigned short int udp_len;
        unsigned short int udp_chksum;
};

struct icmpheader {
	u_int8_t type;		/* message type */
	u_int8_t code;		/* type sub-code */
	u_int16_t checksum;
	union {
		struct {
		      u_int16_t	id;
		      u_int16_t	sequence;
	        } echo;			/* echo datagram */
	        u_int32_t	gateway;	/* gateway address */
		struct {
		      u_int16_t	__unused;
		      u_int16_t	mtu;
	        } frag;			/* path mtu discovery */
        } un;
};

/* Codes for ICMP Type*/
#define ICMP_ECHOREPLY		0	
#define ICMP_DEST_UNREACH	3
#define ICMP_SOURCE_QUENCH	4	
#define ICMP_REDIRECT		5	
#define ICMP_ECHO		8	
#define ICMP_TIME_EXCEEDED	11	
#define ICMP_PARAMETERPROB	12	
#define ICMP_TIMESTAMP		13	
#define ICMP_TIMESTAMPREPLY	14	
#define ICMP_INFO_REQUEST	15	
#define ICMP_INFO_REPLY		16	
#define ICMP_ADDRESS		17	
#define ICMP_ADDRESSREPLY	18	
#define NR_ICMP_TYPES		18

FILE *tcplog,*udplog,*icmplog;

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_app_usage(void);

void
print_app_usage(void)
{

	printf("Usage: packetdata [interface]\n");
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");
}


void
packet_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	char buffer[10240]="\0";
	time_t the_local_time=time(NULL);
	struct tm *local_time_values=localtime(&the_local_time);
	const struct ethernetheader *ethernet;  
	const struct ipheader *ip;              
	const struct tcpheader *tcp;            
	const struct udpheader *udp;            
	const struct icmpheader *icmp;            

	int size_ip;
	int size_tcp;
	int size_payload;
	
	ethernet = (struct ethernetheader*)(packet);
	ip = (struct ipheader*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip >= 20) {
		switch(ip->ip_p) {
			case IPPROTO_TCP:
        			tcplog=fopen("tcplog.csv","a+");
				tcp = (struct tcpheader*)(packet + SIZE_ETHERNET + size_ip);
				size_tcp = TH_OFF(tcp)*4;
				if (size_ip >= 20){
					snprintf(buffer,10240,"%i,%i,%i,%i,%i,%i,%s,%i\n",local_time_values->tm_year+1900,local_time_values->tm_mon+1,local_time_values->tm_mday,local_time_values->tm_hour,local_time_values->tm_min,local_time_values->tm_sec,inet_ntoa(ip->ip_src),ntohs(tcp->th_sport));
					fputs(buffer,tcplog);
				}
				fclose(tcplog);
				return;
			case IPPROTO_UDP:
        			udplog=fopen("udplog.csv","a+");
				udp = (struct udpheader*)(packet + SIZE_ETHERNET + size_ip);
				snprintf(buffer,10240,"%i,%i,%i,%i,%i,%i,%s,%i\n",local_time_values->tm_year+1900,local_time_values->tm_mon+1,local_time_values->tm_mday,local_time_values->tm_hour,local_time_values->tm_min,local_time_values->tm_sec,inet_ntoa(ip->ip_src),ntohs(udp->udp_srcport));
				fputs(buffer,udplog);
				fclose(udplog);
				return;
			case IPPROTO_ICMP:
        			icmplog=fopen("icmplog.csv","a+");
				icmp = (struct icmpheader*)(packet + SIZE_ETHERNET + size_ip);
				snprintf(buffer,10240,"%i,%i,%i,%i,%i,%i,%s,%i\n",local_time_values->tm_year+1900,local_time_values->tm_mon+1,local_time_values->tm_mday,local_time_values->tm_hour,local_time_values->tm_min,local_time_values->tm_sec,inet_ntoa(ip->ip_src),icmp->type);
				fputs(buffer,icmplog);
				fclose(icmplog);
				return;
			default:
				printf("   Protocol: unknown\n");
				return;
		}
	}
}

int main(int argc, char **argv)
{

	char *dev = NULL;			
	char errbuf[PCAP_ERRBUF_SIZE];	
	pcap_t *handle;				

	char filter_exp[] = "ip";		
	struct bpf_program fp;			
	bpf_u_int32 mask;			
	bpf_u_int32 net;			

	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find capture device: %s\n",errbuf);
			exit(EXIT_FAILURE);
		}
	}
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	pcap_loop(handle, 0, packet_process, NULL);
	pcap_freecode(&fp);
	pcap_close(handle);
	fclose(tcplog);
	fclose(udplog);
	fclose(icmplog);
	return 0;
}

