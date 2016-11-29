//
// tangu_ping.hpp
// Copyright © jynis2937, all rights reserved,
// This program is under the GNU Lesser General Public License.
//

#pragma once
#ifndef _TANGU_PING
#define _TANGU_PING

#include <tangu\tangu_analyzer.hpp>

using namespace std::chrono;

typedef struct TANGU_API _TIME_POINT
{
	time_point<system_clock> Start;
	time_point<system_clock> End;
	long long _TIME_POINT::operator()(void);
} TIME_POINT, *PTIME_POINT;

class TANGU_API PacketGrouper : protected PCAPTOOL
{
private:
	PACKET_INFO ICMPPacketHole;
	Packet::ICMP ICMPPacket;
	
public:
	typedef struct _STATISTICS
	{
		UINT Sent;
		UINT Received;
		UINT Lost;
	} STATISTICS;
	STATISTICS Stat;

public:
	PacketGrouper::PacketGrouper(PPCAP*, Net::IPInfo);

private:
	void PacketGrouper::Request(Packet::ICMP_ARCH::ICMPType);
	bool PacketGrouper::Reply(Packet::ICMP_ARCH::ICMPType, long long);
	
public:
	bool PacketGrouper::Echo(long long TimeLimit);
	STATISTICS& PacketGrouper::GetStats(void);
};

#endif /* _TANGU_PING */