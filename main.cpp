#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

#pragma pack(push, 1)
struct RstTcpPacket final {
	EthHdr eth;
	IpHdr ip;
	TcpHdr tcp;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct FinTcpPacket final {
	EthHdr eth;
	IpHdr ip;
	TcpHdr tcp;
	char http[56]; 
};
#pragma pack(pop)

pcap_t* handle;

uint16_t calCheckSum(uint16_t* data, int size);
void sendForwardPacket(EthHdr* org_ether, IpHdr* org_ip, TcpHdr* org_tcp, Mac my_Mac, int org_data_size);
void sendBackwardPacket(EthHdr* org_ether, IpHdr* org_ip, TcpHdr* org_tcp, Mac my_Mac, int org_data_size);

void usage() {
	fprintf(stdout, "syntax : tcp-block <interface> <pattern>\n");
	fprintf(stdout, "sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}


int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}


	//pcap handle
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "error: couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}


	//get my Mac & Ip
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd < 0){
		fprintf(stderr, "error: socket()\n");
		return -1;
	}
	
	struct ifreq ifr;
	strncpy(ifr.ifr_name, argv[1], IFNAMSIZ);
	
	int chk = ioctl(fd, SIOCGIFHWADDR, &ifr);	//get my Mac
	if(chk < 0){
		fprintf(stderr, "error: ioctl()\n");
		close(fd);
		return -1;
	}
	Mac my_Mac = Mac((unsigned char*)ifr.ifr_hwaddr.sa_data);
	
	chk = ioctl(fd, SIOCGIFADDR, &ifr);	//get my Ip
	if(chk < 0){
		fprintf(stderr, "error: ioctl()\n");
		close(fd);
		return -1;
	}
	Ip my_Ip=Ip(ntohl(*(uint32_t*)(ifr.ifr_addr.sa_data+2)));
	
	close(fd);
	fprintf(stdout, "success: get my Mac & Ip\n");


	//block tcp
	while(true){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		EthHdr* ether = (EthHdr*)packet;	//find offset of Ethernet, Ip, Tcp, Data
		if(ether->type != htons(EthHdr::Ip4)) continue;
		IpHdr* ip = (IpHdr*)((u_char*)ether + sizeof(EthHdr));
		if(ip->protocol != IpHdr::Tcp) continue;
		TcpHdr* tcp = (TcpHdr*)((u_char*)ip + (ip->hln())*4);
		u_char* data_offset = (u_char*)((u_char*)tcp + (tcp->dataOff())*4);
		
		char data[65536] = {0};	//pattern search
		int data_size = ntohs(ip->tln) - (ip->hln())*4 - (tcp->dataOff())*4;
		strncpy(data, (char*)data_offset, data_size);
		if(strstr(data, argv[2])==0) continue;
		
		sendForwardPacket(ether, ip, tcp, my_Mac, data_size);
		sendBackwardPacket(ether, ip, tcp, my_Mac, data_size);
		
		printf("block!!\n");
	}		
	pcap_close(handle);
}


uint16_t calCheckSum(uint16_t* data, int size){
	uint32_t ret = 0;
	for(int i=0; i<size/2; i++){
		ret += data[i];
	}
	if(size%2==1){
		ret += *((uint8_t*)data+size-1);
	}
	while(ret>0xFFFF){
		ret = (ret&0xFFFF) + (ret>>16);
	}
	ret = ret ^ 0xFFFF;
	return (uint16_t)ret;
}

void sendForwardPacket(EthHdr* org_ether, IpHdr* org_ip, TcpHdr* org_tcp, Mac my_Mac, int org_data_size){
	RstTcpPacket packet;
	memset(&packet, 0, sizeof(packet));
	
	packet.eth.sMac = my_Mac;
	packet.eth.dMac = org_ether->dMac;
	packet.eth.type = htons(EthHdr::Ip4);
	
	packet.ip.ver_hln = 0x40 | (sizeof(IpHdr)/4);
	//packet.ip.type
	packet.ip.tln = htons(sizeof(IpHdr) + sizeof(TcpHdr));
	//packet.ip.id
	//packet.ip.fragOff
	packet.ip.ttl = org_ip->ttl;
	packet.ip.protocol = IpHdr::Tcp;
	packet.ip.sIp = org_ip->sIp;
	packet.ip.dIp = org_ip->dIp;
	packet.ip.checkSum = calCheckSum((uint16_t*)&packet.ip, sizeof(IpHdr));
	
	packet.tcp.sPort = org_tcp->sPort;
	packet.tcp.dPort = org_tcp->dPort;
	packet.tcp.seq = htonl(ntohl(org_tcp->seq) + org_data_size);
	packet.tcp.ack = org_tcp->ack;
	packet.tcp.flag = 0x0050 | 0x1400;	//20bytes | ACK, RST
	packet.tcp.winSize = org_tcp->winSize;	//???
	//packet.tcp.urgPoint
	
	char pseudoHdr[12 + sizeof(TcpHdr)] = {0};
	memcpy(pseudoHdr, &packet.ip.sIp, 8);
	pseudoHdr[9] = IpHdr::Tcp;
	*(uint16_t*)(pseudoHdr+10) = htons((uint16_t)sizeof(TcpHdr));
	memcpy(pseudoHdr+12, &packet.tcp, sizeof(TcpHdr));
	packet.tcp.checkSum = calCheckSum((uint16_t*)pseudoHdr, 12+sizeof(TcpHdr));
	
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
	if (res != 0) {
		fprintf(stderr, "error: pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}
void sendBackwardPacket(EthHdr* org_ether, IpHdr* org_ip, TcpHdr* org_tcp, Mac my_Mac, int org_data_size){
	FinTcpPacket packet;
	memset(&packet, 0, sizeof(packet));
	
	packet.eth.sMac = my_Mac;
	packet.eth.dMac = org_ether->sMac;
	packet.eth.type = htons(EthHdr::Ip4);
	
	packet.ip.ver_hln = 0x40 | (sizeof(IpHdr)/4);
	//packet.ip.type
	packet.ip.tln = htons(sizeof(IpHdr) + sizeof(TcpHdr) + 55);
	//packet.ip.id
	//packet.ip.fragOff
	packet.ip.ttl = 128;
	packet.ip.protocol = IpHdr::Tcp;
	packet.ip.sIp = org_ip->dIp;
	packet.ip.dIp = org_ip->sIp;
	packet.ip.checkSum = calCheckSum((uint16_t*)&packet.ip, sizeof(IpHdr));
	
	packet.tcp.sPort = org_tcp->dPort;
	packet.tcp.dPort = org_tcp->sPort;
	packet.tcp.seq = org_tcp->ack;
	packet.tcp.ack = htonl(ntohl(org_tcp->seq) + org_data_size);
	packet.tcp.flag = 0x0050 | 0x1100;	//20bytes | ACK, FIN
	packet.tcp.winSize = org_tcp->winSize;	//???
	//packet.tcp.urgPoint
	
	strcpy(packet.http, "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n");
	
	char pseudoHdr[12 + sizeof(TcpHdr) + 55] = {0};
	memcpy(pseudoHdr, &packet.ip.sIp, 8);
	pseudoHdr[9] = IpHdr::Tcp;
	*(uint16_t*)(pseudoHdr+10) = htons((uint16_t)sizeof(TcpHdr)+55);
	memcpy(pseudoHdr+12, &packet.tcp, sizeof(TcpHdr)+55);
	packet.tcp.checkSum = calCheckSum((uint16_t*)pseudoHdr, 12+sizeof(TcpHdr)+55);
	
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet)-1);
	if (res != 0) {
		fprintf(stderr, "error: pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

