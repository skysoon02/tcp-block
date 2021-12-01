#pragma once

#include <arpa/inet.h>

#pragma pack(push, 1)
struct TcpHdr final {
	uint16_t sPort;
	uint16_t dPort;
	uint32_t seq;
	uint32_t ack;
	uint16_t flag;
	uint16_t winSize;
	uint16_t checkSum;
	uint16_t urgPoint;
	
	uint8_t dataOff() { return (flag & 0x00F0)>>4; }
};
typedef TcpHdr *PTcpHdr;
#pragma pack(pop)
