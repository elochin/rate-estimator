/*
 * Emmanuel Lochin 
 * emmanuel.lochin@enac.fr 
 * TSW throughput estimator 
 * last update : 2021/03/04 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <pcap.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <math.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/time.h>

#define SNAPLEN 100
#define AVG_INTERVAL 1		// 1 second

#define FLAG_IP         0x0001
#define FLAG_PORT       0x0002
#define FLAG_PROTO      0x0004

int verbose = 0;

void quit()
{
	printf("\n<Ctrl>+C closing\n");
	exit(0);
}

void float_error()
{
	fprintf(stderr, "\nFloat error\n");
	exit(0);
}

void manage_signals(void)
{
	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, quit);
	signal(SIGFPE, float_error);
	signal(SIGTERM, quit);
	signal(SIGKILL, quit);
	signal(SIGQUIT, quit);
}

int get_protocol_number(char *name)
{
	int s;
	int buflen = 1024;
	int erange_cnt = 0;
	int MAXBUF = 10000;
	char buf[MAXBUF];
	char **p;
	struct protoent result_buf;
	struct protoent *result;

	/*
	 * This code is extract from getprotobyname_r manpage 
	 */

	do {
		s = getprotobyname_r(name, &result_buf, buf, buflen, &result);

		if (s == ERANGE) {
			if (erange_cnt == 0 && verbose)
				printf("ERANGE! Retrying with larger buffer\n");
			erange_cnt++;

			/*
			 * Increment a byte at a time so we can see exactly what size
			 * buffer was required 
			 */

			buflen++;

			if (buflen > MAXBUF) {
				fprintf(stderr, "Exceeded buffer limit (%d)\n",
					MAXBUF);
				exit(EXIT_FAILURE);
			}
		}
	} while (s == ERANGE);

	if (verbose) {
		printf("p_name=%s; p_proto=%d; aliases=",
		       result_buf.p_name, result_buf.p_proto);
		for (p = result_buf.p_aliases; *p != NULL; p++)
			printf("%s ", *p);
		printf("\n");

	}
	return result_buf.p_proto;
}

void usage(char *name)
{
	printf
	    ("%s gives a throughput estimation (based on the Time Sliding Window algorithm) of a specific flow or all traffic crossing an interface.\n",
	     name);
	printf
	    ("The measured flow can be identified by a destination address, a destination port a protocol or a combination of the three.\n");
	printf
	    ("Syntaxe : %s -i <iface> [-a <dest-ip address>] [-p <dest-port>] [-t <protocol name>] [-v]\n",
	     name);
	printf("\nGeneric options:\n");
	printf("\t-i <iface> \t\tname or idx of interface\n");
	printf
	    ("\t[-a <ip address>] \tmeasure applied to a given destination ip address, can be combined with -p and -t\n");
	printf
	    ("\t[-p <port>] \t\tmeasure applied to a given destination port, can be combined with -a and -t\n");
	printf
	    ("\t[-t <protocol name>] \tmeasure applied to a given protocol, can be combined with -a and -p\n");
	printf("\t[-v] \t\t\tverbose mode\n");
	printf("\nExample : \n");
	printf("%s -i eth0 -p 7789\n", name);
	printf("\t mean rate for traffic with destination port number 7789 \n");
	printf("\n%s -i eth0 -p 7789 -t udp\n", name);
	printf
	    ("\t mean rate for UDP traffic with destination port number 7789 \n");
	printf("\n%s -i eth0 -a 192.168.1.1 -p 7789 -t udp\n", name);
	printf
	    ("\t mean rate for UDP traffic with destination 192.168.1.1:7789 \n");
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{

	struct timeval lasttime, curtime, lasttime2;
	struct timezone tz;

	float avg_rate, Bytes_in_win = 0, New_bytes = 0;

	float interval_us;
	float interval_sec;
	long len_pkt;
	double Pktsize;
	char *dev;
	char c;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *descr;
	const u_char *packet;

	struct pcap_pkthdr hdr;
	struct ether_header *eptr;
	struct iphdr *iptr;
	struct tcphdr *tptr;

	char target_ip[16];
	char *protocol_name;
	u_int protocol = 0;
	u_int dport = 0;
	struct hostent *host;

	u_int localnet, netmask;
	struct in_addr getip;

	int flags = 0;

	while ((c = getopt(argc, argv, "hvi:a:p:t:")) != -1) {
		switch (c) {
		case 'i':
			dev = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'a':
			host = gethostbyname(optarg);
			if (host == NULL) {
				perror("gethostbyname");
				fprintf(stderr, "Cannot resolve host %s.\n",
					optarg);
				exit(EXIT_FAILURE);
			}
			getip.s_addr = *((uint32_t *) host->h_addr_list[0]);
			strcpy(target_ip, inet_ntoa(getip));
			flags |= FLAG_IP;
			break;
		case 'p':
			dport = atoi(optarg);
			flags |= FLAG_PORT;
			break;
		case 't':
			protocol_name = optarg;
			protocol = get_protocol_number(optarg);
			flags |= FLAG_PROTO;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
		case '?':
			if (optopt == 'a' || optopt == 'p' || optopt == 't'
			    || optopt == 'i')
				fprintf(stderr,
					"Option -%c requires an argument.\n",
					optopt);
			else if (isprint(optopt))
				fprintf(stderr, "Unknown option `-%c'.\n",
					optopt);
			else
				fprintf(stderr,
					"Unknown option character `\\x%x'.\n",
					optopt);
			exit(EXIT_FAILURE);
		default:
			usage(argv[0]);
		}
	}

	if ((descr = pcap_open_live(dev, SNAPLEN, 1, 1, errbuf)) == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		fprintf(stderr, "You must be root to run %s\n", argv[0]);
		return -1;
	}

	if (protocol == 1 && (flags & FLAG_PORT)) {	/* if ICMP */
		printf("WARNING port number not considered with ICMP\n");
		if (flags & FLAG_IP) {
			flags = FLAG_PROTO;
			flags |= FLAG_IP;
		} else
			flags = FLAG_PROTO;
	}

	if (dev == NULL)
		usage(argv[0]);

	if (verbose) {
		printf("Throughput measured from %s ", dev);
		if (flags == 0)
			printf("for the whole traffic");
		if (flags & FLAG_IP)
			printf("ip address %s ", target_ip);
		if (flags & FLAG_PORT)
			printf("port %d ", dport);
		if (flags & FLAG_PROTO)
			printf("protocol %s (%d)", protocol_name, protocol);
		printf("\n");
	}

	if (pcap_lookupnet(dev, &localnet, &netmask, errbuf) < 0)
		printf("%s\n", errbuf);

	/*
	 * Time initialisation 
	 */
	if (gettimeofday(&lasttime, &tz) != 0) {
		perror("gettimeofday");
		exit(EXIT_FAILURE);
	}

	if (gettimeofday(&lasttime2, &tz) != 0) {
		perror("gettimeofday");
		exit(EXIT_FAILURE);
	}
	
    /*
	 * Signal handling
	 */
	manage_signals();

	/*
	 * progression bar 
	 */
	char a[4] = { '|', '/', '-', '\\' };
	int i = 0;

	while (1) {

		if ((packet = pcap_next(descr, &hdr)) != NULL) {
			eptr = (struct ether_header *)packet;
			iptr = (struct iphdr *)(14 + packet);
			tptr = (struct tcphdr *)(14 + 20 + packet);

			/*
			 * Type of pkt 
			 */

			if (ntohs(eptr->ether_type) == ETHERTYPE_IP) {

				if (gettimeofday(&curtime, &tz) != 0) {
					perror("gettimeofday");
					exit(EXIT_FAILURE);
				}

				if (flags & FLAG_PORT) {
					if ((int)ntohs(tptr->th_dport) != dport) {
						continue;
					}
				}

				if (flags & FLAG_IP) {
					if (strcmp(target_ip, inet_ntoa(*((struct in_addr *)&iptr->daddr))))	
                       /*
                        * returns 0 if match, a return value lower or higher than 0
                        * means not found then continue
                        */
						continue;
				}

				if (flags & FLAG_PROTO) {
					if ((int)(iptr->protocol) != protocol) {
						continue;
					}
				}

				interval_us =
				    ((curtime.tv_sec * 1000000L +
				      curtime.tv_usec)
				     - (lasttime.tv_sec * 1000000L +
					lasttime.tv_usec));
				interval_sec = (float)interval_us / 1000000;

				len_pkt = ntohs(iptr->tot_len);

				Pktsize = (8 * (float)len_pkt) / (1024 * 1024);

				Bytes_in_win = avg_rate * AVG_INTERVAL;
				New_bytes = Bytes_in_win + Pktsize;
				avg_rate =
				    New_bytes / (interval_sec + AVG_INTERVAL);

				lasttime = curtime;

				if ((curtime.tv_sec * 1000000L +
				     curtime.tv_usec)
				    - (lasttime2.tv_sec * 1000000L + lasttime2.tv_usec) >= 100000) {	// display every 100ms
					if (avg_rate < 1)
						printf
						    (" mean rate %.2f kbit/s  %c                 \r",
						     1000 * avg_rate, a[i]);
					else
						printf
						    (" mean rate %.2f mbit/s  %c                 \r",
						     avg_rate, a[i]);
					lasttime2 = curtime;
					i++;
					if (i >= 4)
						i = 0;
					fflush(stdout);
				}
			}
		}
	}
	return 0;
}
