/*
 ============================================================================
 Name        : Netdesign.c
 Author      : 
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

/*
 ============================================================================
 Name        : ceshi.c
 Author      :
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include "pcap.h"
#include<stdio.h>
#include<string.h>
/* 4字节的IP地址 */
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ip_address;
typedef struct eth_header {
	u_char DestMac[6];
	u_char SrcMac[6];
	u_char Etype[2];
} eth_header;
/* IPv4 首部 */
typedef struct ip_header {
	u_char ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
	u_char tos;            // 服务类型(Type of service)
	u_short tlen;           // 总长(Total length)
	u_short identification; // 标识(Identification)
	u_short flags_fo;   // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
	u_char ttl;            // 存活时间(Time to live)
	u_char proto;          // 协议(Protocol)
	u_short crc;            // 首部校验和(Header checksum)
	ip_address saddr;      // 源地址(Source address)
	ip_address daddr;      // 目的地址(Destination address)
	u_int op_pad;         // 选项与填充(Option + Padding)
} ip_header;

/* UDP 首部*/
typedef struct udp_header {
	u_short sport;          // 源端口(Source port)
	u_short dport;          // 目的端口(Destination port)
	u_short len;            // UDP数据包长度(Datagram length)
	u_short crc;            // 校验和(Checksum)
} udp_header;

main() {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	u_int *net_ip;
	int res;
	char packet_filter[50];
	char s[50];
	struct bpf_program fcode;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	struct tm *ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short u_sport, u_dport;
	u_short t_sport, t_dport;
	time_t local_tv_sec;
	u_int acknum;
	eth_header *eh;
	pcap_dumper_t *dumpfile;
	/* 获得设备列表 */
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
}


