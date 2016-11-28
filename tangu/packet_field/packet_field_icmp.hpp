#pragma once
#ifndef _PACKETFIELD_ICMP
#define _PACKETFIELD_ICMP

#include <packet_field\packet_field_icmp.hpp>
#include <packet_field\packet_field_ip.hpp>

#include <Random>

NAMESPACE_BEGIN(Packet)

using _STD random_device;
using _STD mt19937;
using _STD uniform_int_distribution;

#pragma pack(push, 1)
typedef struct ICMP_ARCHITECTURE
{

	enum class ICMPType
	{
		ICMP_ECHO_REPLY = 0,
		ICMP_TIME_EXCEEDED = 1,
		ICMP_DEST_UNREACH =  3,
		ICMP_SOURCE_QUENCH = 4,
		ICMP_REDIRECT = 5,
		ICMP_ECHO = 8,
		ICMP_PARAMETERPROB = 12,
		ICMP_TIMESTAMP = 13,
		ICMP_TIMESTAMPREPLY = 14,
		ICMP_INFO_REQUEST = 15,
		ICMP_INFO_REPLY = 16,
		ICMP_ADDRESS = 17,
		ICMP_ADDRESSREPLY = 18,
		NR_ICMP_TYPES = 19
	};
	UCHAR Type;		
	UCHAR Code;		/* Sub Type */
	USHORT Checksum;

	USHORT Identifier;
	USHORT Sequence;

	BYTE Data[32];

} ICMP_ARCH, *PICMP_ARCH;
#pragma pack(pop)

typedef class TANGU_API __ICMP
{
private:
	random_device RdFromHW;
	/* A Mersenne Twister pseudo-random generator of 32-bit numbers with a state size of 19937 bits. */
	mt19937 Seed;
	uniform_int_distribution<> Distributer;
	
public:
	ETHERNET_HEADER EthernetHeader;
	IP_HEADER IPHeader;
	ICMP_ARCH	ICMPPacket;

	BYTE _Msg[_MAX_ETHERNETLEN];
	Net::L3ID _Rsrc;
	USHORT Iden;
	USHORT Seq;

public:
	__ICMP::__ICMP(void);

public:
	void __ICMP::GetICMP(ICMP_ARCH::ICMPType);
} ICMP, *PICMP;

NAMESPACE_END /* Packet */

#endif /* _PACKETFIELD_ICMP */