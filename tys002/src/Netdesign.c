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
/* TCP 首部*/
typedef struct tcp_header {
	u_short sport;         //源端口号16bit
	u_short dport;         //目的端口号16bit
	u_int sequnum;         //序列号32bit
	u_int acknum;         //确认号32bit
	u_short headerlenandflag;  //前4位：TCP头长度；中6位：保留；后6位：标志位
	u_short windowsize;         //窗口大小16bit
	u_short checknum;         //检验和16bit
	u_short spointer;         //紧急数据偏移量16bit
} tcp_header;
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
	tcp_header *th;
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


	/* 打印列表 */
	for (d = alldevs; d; d = d->next) {
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0) {
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	printf("Enter the Protocol(like port 20/ src .../udp || tcp :");
	fgets(s, 50, stdin);
	strcpy(packet_filter, s);
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);
	if (inum < 1 || inum > i) {
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳转到已选设备 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* 打开适配器 */
	if ((adhandle = pcap_open_live(d->name,  // 设备名
			65536,     // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
			1,         // 混杂模式
			1000,      // 读取超时时间
			errbuf     // 错误缓冲池
			)) == NULL) {
		fprintf(stderr,
				"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 检查数据链路层，为了简单，我们只考虑以太网 */
	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		pcap_lookupnet(d->name, &net_ip, &netmask, errbuf);
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;

	//编译过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) {
		fprintf(stderr,
				"\nUnable to compile the packet filter. Check the syntax.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode) < 0) {
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	/* 开始捕捉 */
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {

		if (res == 0)
			/* 超时时间到 */
			continue;
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
		eh = (eth_header *) (pkt_data);
			printf("----------------显示数据帧内容-----------------\n");
			for (i = 0; i < (int) header->len; ++i) {
				printf(" %02x", pkt_data[i]);


				if ((i + 1) % 16 == 0) {
					printf("\n");

				}
			}

		}
		if (eh->Etype[0] == 0x08 && eh->Etype[1] == 0x00) {
			/* 获得IP数据包头部的位置 */
			ih = (ip_header *) (pkt_data + 14); //以太网头部长度
			if (ih->proto == 17) {
				/* 获得UDP首部的位置 */
				ip_len = (ih->ver_ihl & 0xf) * 4;

				uh = (udp_header *) ((u_char*) ih + ip_len);

				/* 将网络字节序列转换成主机字节序列 */
				u_sport = ntohs(uh->sport);
				u_dport = ntohs(uh->dport);
				printf("\n");
				printf(" --------------UDP-------------------\n");
				printf("数据包的时间戳：%s.%.6d  数据包长度： len:%d \n", timestr,
						header->ts.tv_usec, header->len);
				printf("源MAC : %02X-%02X-%02X-%02X-%02X-%02X--->",
						eh->SrcMac[0], eh->SrcMac[1], eh->SrcMac[2],
						eh->SrcMac[3], eh->SrcMac[4], eh->SrcMac[5]);
				printf("目的MAC  : %02X-%02X-%02X-%02X-%02X-%02X\n",
						eh->DestMac[0], eh->DestMac[1], eh->DestMac[2],
						eh->DestMac[3], eh->DestMac[4], eh->DestMac[5]);
				printf(
						"IP版本首部长度:%d\n服务类型:%d\n总长:%d\n标识:%d\n存活时间:%d\n协议:%d\n首部校验和:%d\n",
						ih->ver_ihl, // 版本 (4 bits) + 首部长度 (4 bits)
						ih->tos,            // 服务类型(Type of service)
						ntohs(ih->tlen),          // 总长(Total length)
						ntohs(ih->identification),          //标识
						ih->ttl,			//TTL
						ih->proto,          // 协议(Protocol)
						ntohs(ih->crc)            // 首部校验和(Header checksum)
								);
				printf("---------------------------------------------\n");
				printf("UDP数据包长度:%d\nUDP检验和:%d\n", ntohs(uh->len),
						ntohs(uh->crc));
				/* 打印IP地址和UDP端口 */
				printf("UDP: %d.%d.%d.%d 端口号：%d -> %d.%d.%d.%d 端口号：%d\n",
						ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3,
						ih->saddr.byte4, u_sport, ih->daddr.byte1,
						ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4,
						u_dport);
				printf("----------------显示数据帧内容-----------------\n");

				for (i = 0; i < (int) header->len; ++i) {
					printf(" %02x", pkt_data[i]);

					if ((i + 1) % 16 == 0) {
						printf("\n");

					}
				}
			}
			if (ih->proto == 6) {
							ip_len = (ih->ver_ihl & 0xf) * 4;
							th = (tcp_header *) ((u_char*) ih + ip_len);
							t_sport = ntohs(th->sport);
							t_dport = ntohs(th->dport);
							acknum = ntohs(th->acknum);
							printf("\n");
							printf(" ---------------TCP-------------------\n");
							printf("数据包的时间戳：%s.%.6d  数据包长度： len:%d \n", timestr,
									header->ts.tv_usec, header->len);
							printf("源MAC : %02X-%02X-%02X-%02X-%02X-%02X--->",
									eh->SrcMac[0], eh->SrcMac[1], eh->SrcMac[2],
									eh->SrcMac[3], eh->SrcMac[4], eh->SrcMac[5]);
							printf("目的MAC : %02X-%02X-%02X-%02X-%02X-%02X\n",
									eh->DestMac[0], eh->DestMac[1], eh->DestMac[2],
									eh->DestMac[3], eh->DestMac[4], eh->DestMac[5]);
							printf(
									"IP版本首部长度:%d\n服务类型:%d\n总长:%d\n标识:%d\n存活时间:%d\n协议:%d\n首部校验和:%d\n",
									ih->ver_ihl, // 版本 (4 bits) + 首部长度 (4 bits)
									ih->tos,            // 服务类型(Type of service)
									ntohs(ih->tlen),          // 总长(Total length)
									ntohs(ih->identification),          //标识符
									ih->ttl,			//TTL
									ih->proto,          // 协议(Protocol)
									ntohs(ih->crc)            // 首部校验和(Header checksum)
											);
							printf("---------------------------------------------\n");
							printf("TCP序列号:%d\n确认号:%d\n窗口大小:%d\n检验和:%d\n紧急数据偏移量:%d\n",
									ntohs(th->sequnum), ntohs(th->acknum),
									ntohs(th->windowsize), ntohs(th->checknum),
									ntohs(th->spointer));
							printf("TCP: %d.%d.%d.%d 端口号：%d  -> %d.%d.%d.%d 端口号：%d \n",
									ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3,
									ih->saddr.byte4, t_sport, ih->daddr.byte1,
									ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4,
									t_dport);
			}
		}







	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}

	return 0;

}


