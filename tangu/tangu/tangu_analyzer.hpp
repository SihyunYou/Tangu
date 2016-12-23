//
// tangu_analyzer.hpp
// Copyright © jynis2937, all rights reserved,
// This program is under the GNU Lesser General Public License.
//

#pragma once
#ifndef _TANGU_ANALYZER
#define _TANGU_ANALYZER

#include <net_manager\net_manager.hpp>
#include <packet_field\packet_field.hpp>
#include <tangu\tangu_interface.hpp>

/*
* @brief    An indicator where TCP/IP stack begins.
*/
enum class PKTBEGIN
{
	LAYER_DATALINK,
	LAYER_NETWORK,
	LAYER_TRANSPORT,
	LAYER_APPLICATION
};

/*
* @brief    Required elements for parameters sending/receiving packet through Pcap
*           interface.
*/
typedef struct TANGU_API _PCAPTOOL
{
protected:
	PPCAP Interface;
	PPCAP_PKTHDR PacketHeader;
	const LPBYTE PacketData;

protected:
	/*
	* @brief    Constructor
	*/
	_PCAPTOOL::_PCAPTOOL(void);
	/*
	* @brief    Constructor
	* @param	    Pcap interface pointer
	*/
	explicit _PCAPTOOL::_PCAPTOOL(PPCAP);
} PCAPTOOL, *PPCAPTOOL;

/*
* @brief    A huge container all fields of packet can be in
*/
typedef class TANGU_API PACKET_INFO
{
public:
	LPCBYTE PacketData;
	UINT PacketLength;

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

	BYTE ApplicationPayload[_MAX_ETHERNETLEN 
		- sizeof(Packet::ETHERNET_HEADER) 
		- sizeof(Packet::IP_HEADER) 
		- sizeof(Packet::TCP_HEADER)];
	UINT PayloadLength;

public:
	/*
	* @brief    Constructor
	*/
	PACKET_INFO::PACKET_INFO(void);
	/*
	* @brief    Constructor
	* @param	    Packet data
	*/
	PACKET_INFO::PACKET_INFO(LPCBYTE);

public:
	/*
	* @brief    Parse packet data to each field structure.
	* @param	    An indicator where TCP/IP stack begins.
	*/
	void PACKET_INFO::ParseData(PKTBEGIN = PKTBEGIN::LAYER_DATALINK);
} *PPACKET_INFO;


#endif /* _ANALYZER */