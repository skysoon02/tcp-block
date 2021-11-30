#pragma once

#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
	uint8_t ver_hln;
	uint8_t type;
	uint16_t totalLen;
	uint16_t id;
	uint16_t fragOff;
	uint8_t ttl;
    uint8_t protocol;
    uint16_t checkSum;
    Ip sIp;
    Ip dIp;
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)
