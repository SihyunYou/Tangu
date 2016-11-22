#pragma once
#ifndef _TANGU_ANALYZER
#define _TANGU_ANALYZER

#include <net_manager\net_manager.hpp>
#include <packet_field\packet_field.hpp>
#include <tangu\tangu_interface.hpp>

enum class PKTBEGIN
{
	LAYER_DATALINK,
	LAYER_NETWORK,
	LAYER_TRANSPORT,
};

typedef struct TANGU_API _PCAPTOOL
{
protected:
	PPCAP Interface;
	PPCAP_PKTHDR PacketHeader;
	const LPBYTE PacketData;

protected:
	_PCAPTOOL::_PCAPTOOL(void);
	explicit _PCAPTOOL::_PCAPTOOL(PPCAP);
} PCAPTOOL, *PPCAPTOOL;

typedef class TANGU_API PACKET_INFO
{
public:
	//
	// Layer 2
	//
	Packet::ETHERNET_HEADER EthernetHeader;
	
	//
	// Layer 3
	//
	Packet::ARP_ARCH ARPFrame;
	Packet::IP_HEADER IPHeader;
	
	//
	// Layer 4
	//
	Packet::ICMP_ARCH ICMPPacket;
	Packet::TCP_HEADER TCPHeader;

	LPBYTE ApplicationPayload;

public:
	PACKET_INFO::PACKET_INFO(void);

public:
	string PACKET_INFO::PktParseString(const LPBYTE, PKTBEGIN = PKTBEGIN::LAYER_DATALINK);
	void PACKET_INFO::PktParseData(const LPBYTE, PKTBEGIN = PKTBEGIN::LAYER_DATALINK);
} *PPCAKET_INFO;


#endif /* _ANALYZER */