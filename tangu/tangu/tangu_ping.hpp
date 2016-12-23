//
// tangu_ping.hpp
// Copyright © jynis2937, all rights reserved,
// This program is under the GNU Lesser General Public License.
//

#pragma once
#ifndef _TANGU_PING
#define _TANGU_PING

#include <tangu\tangu_analyzer.hpp>

/*
* @brief    A computer network administration software utility used to test the 
*          reachability of a host on an Internet protocol network
*/
class TANGU_API PacketGrouper : protected PCAPTOOL
{
private:
	PACKET_INFO ICMPPacketHole;
	Packet::ICMP ICMPPacket;
	
public:
	/*
	* @brief    ping result statistics
	*/
	typedef struct _STATISTICS
	{
		UINT Sent;
		UINT Received;
		UINT Lost;
	} STATISTICS;
	STATISTICS Stat;

public:
	/*
	* @brief    Constructor
	*          Initializes Pcap interface.
	*          Initialize source address and destination address.
	* @param    Pcap interface
	* @param    Target IP 
	*/
	PacketGrouper::PacketGrouper(PPCAP*, Net::IPInfo);

private:
	/*
	* @brief    Send icmp echo packet
	* @param    Type in ICMP field
	*/
	void PacketGrouper::Request(Packet::ICMP_ARCH::ICMPType = Packet::ICMP_ARCH::ICMPType::ICMP_ECHO);
	/*
	* @brief    Receive icmp echo reply packet
	* @param    Type in ICMP field
	* @param    Time limit
	* @return   Whether reply is timed out. 
	*/
	bool PacketGrouper::Reply(Packet::ICMP_ARCH::ICMPType, long long);
	
public:
	/*
	* @brief    Send icmp echo packet and receive icmp echo reply packet
	* @param    Time limit
	* @return   Whether reply is timed out.
	*/
	bool PacketGrouper::Echo(long long TimeLimit);
	/*
	* @return   Statistics of ping requests and replies.
	*/
	STATISTICS& PacketGrouper::GetStats(void);
};

#endif /* _TANGU_PING */