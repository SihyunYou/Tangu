#pragma once
#ifndef _PACKETFIELD_IP
#define _PACKETFIELD_IP

#include "net_manager.hpp"

NAMESPACE_BEGIN(Packet)

// Refer to	https://en.wikipedia.org/wiki/IPv4#Protocol (Wiki)
//				https://tools.ietf.org/html/rfc790 (RFC790)

// enum IPProtocol -> IPPROTO

#pragma pack(push, 1)
typedef struct _IP_HEADER
{

#define IP_VERSION(x)			((x << 4) & 0xF0)
#define IP_HEADER_LENGTH(x)	((x / 4) & 0x0F)
	UCHAR IHL;

	// Type of Service (Differentiated Services Field)
	/*	Differentiated Services Codepoint */
	/* Refer to https://en.wikipedia.org/wiki/Differentiated_services */
#define	DSCP_CS_N(x)			((x * 8) << 2) & 0xFD
	/* Explicit Congestion Notification */
	/* Refer to https://en.wikipedia.org/wiki/Explicit_Congestion_Notification */
#define	ECN(x)						(x & 0x02)
	UCHAR ServiceType;

	UCHAR TotalLength;
	USHORT ldentification;

	// Fragment Identifier Field
	/* Fragment Flags */
#define IP_FLAG(x)		(x << 13)
#define DONT_FRAGMENTS(s)	(s << 1)
#define MORE_FRAGMENTS(s)	(s)
	/* Fragment Offset */
	USHORT Fragmention;

	UCHAR TTL;

	enum class IPProto
	{
		ICMP = 0x01,

		GATEWAY_TO_GATEWAY = 0x03,
		CMCC_GATEWAY_MONITORING_MESSAGE = 0x04,
		ST = 0x05,
		TCP = 0x06,
		UCL = 0x07,

		SECURE = 0x09,
		BBN_RCC_MONITORING = 0x0A,
		NVP = 0x0B,
		PUP = 0x0C,
		PLURIBUS = 0x0D,
		TELENET = 0x0E,
		XNET = 0x0F,
		CHAOS = 0x10,
		USER_DATAGRAM = 0x11,
		MULTIPLEXING = 0x12,
		DCN = 0x13,
		TAC_MONITORING = 0x14,

		ANY_LOCAL_NETWORK = 0x3F,
		SATNET_BACKROOM_EXPAK = 0x40,
		MIT_SUBNET_SUPPORT = 0x41,

		SATNET_MONITORING = 0x45,

		INTERNET_PACKET_CORE_UTILITY = 0x47,

		BACKROOM_SATNET_MONITORING = 0x4C,

		WIDEBAND_MONITORING = 0x4E,
		WIDEBAND_EXPAK = 0x4F,
	};
	UCHAR	 Protocol;

	USHORT Checksum;

	BYTE SrcIP[4];
	BYTE DestIP[4];

} IP_HEADER, *PIP_HEADER;
#pragma pack(pop)

USHORT IPCheckSum(Packet::PIP_HEADER);

NAMESPACE_END /* Packet */

#endif /* _PACKETFIELD_IP */