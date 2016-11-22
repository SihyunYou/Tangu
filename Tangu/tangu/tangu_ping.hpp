#pragma once
#ifndef _TANGU_PING
#define _TANGU_PING

#include <tangu\tangu_analyzer.hpp>

using namespace std::chrono;

typedef struct TANGU_API _TIME_POINT
{
	time_point<system_clock> Start;
	time_point<system_clock> End;
	long long _TIME_POINT::operator()(void)
	{
		return duration_cast<milliseconds>(End - Start).count();
	}
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
	PacketGrouper::PacketGrouper(pcap_t** Interface, Net::IPInfo Target) :
		PCAPTOOL(*Interface),
		Stat{ 0, 0, 0 }
	{
		Net::PIPAdapterInfo AddressInfo = Net::IPAdapterInfo::GetInstance();
		Net::PIPNetTableInfo NetTableInfo = Net::IPNetTableInfo::GetInstance();

		ICMPPacket._Rsrc.ISrc = Net::Utility::GetIPAddress(AddressInfo);
		ICMPPacket._Rsrc.IDst = Target;
		ICMPPacket._Rsrc.MSrc = Net::Utility::GetMACAddress(AddressInfo);
		ICMPPacket._Rsrc.MDst = Net::Utility::GetGatewayMACAddress(NetTableInfo);
	}

private:
	void PacketGrouper::Request(Packet::ICMP_ARCH::ICMPType Type)
	{
		ICMPPacket.GetICMP(Type);
		pcap_sendpacket(Interface, ICMPPacket._Msg,
			sizeof(Packet::ETHERNET_HEADER) + sizeof(Packet::IP_HEADER) + sizeof(Packet::ICMP_ARCH));
	}
	bool PacketGrouper::Reply(Packet::ICMP_ARCH::ICMPType Type, long long TimeLimit)
	{
		TIME_POINT TimePoint;
		TimePoint.Start = system_clock::now();

		do
		{
			if (0 == pcap_next_ex(Interface, &PacketHeader, (const UCHAR**)&PacketData))
			{
				TimePoint.End = system_clock::now();
				continue;
			};

			ICMPPacketHole.PktParseData(PacketData, PKTBEGIN::LAYER_DATALINK);
			if (Net::IPInfo{ ICMPPacketHole.IPHeader.Source } == ICMPPacket._Rsrc.IDst)
			{
				if (static_cast<Packet::ICMP_ARCH::ICMPType>(ICMPPacketHole.ICMPPacket.Type) == Type)
				{
					return true;
				}
			}

			TimePoint.End = system_clock::now();
		} while (TimePoint() < TimeLimit);
		
		return false;
	}
	
public:
	bool PacketGrouper::Echo(long long TimeLimit)
	{
		++Stat.Sent;
		Request(Packet::ICMP_ARCH::ICMPType::ICMP_ECHO);
		
		if (false != Reply(Packet::ICMP_ARCH::ICMPType::ICMP_ECHO_REPLY, TimeLimit))
		{
			++Stat.Received;
			return true;
		}

		++Stat.Lost;
		return false;
	}
	STATISTICS& PacketGrouper::GetStats(void)
	{
		return Stat;
	}
};

#endif /* _TANGU_PING */