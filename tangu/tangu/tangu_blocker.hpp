#pragma once
#ifndef _TANGU_BLOCK
#define _TANGU_BLOCK

#include <net_manager\net_manager.hpp>
#include <packet_field\packet_field.hpp>
#include <boost\algorithm\string.hpp>
#include <tangu\tangu_analyzer.hpp>
#include <tangu\tangu_interface.hpp>
#include <tangu\tangu_divert.hpp>

namespace Algorithm = boost::algorithm;
using namespace Packet;

typedef class TANGU_API HIJACK
{
private:
	LPCSTR BlockData =
		"HTTP/1.1 200 OK\r\n"
		"Connection: close\r\n"
		"Content-Type: text/html\r\n"
		"\r\n"
		"<!doctype html>\n"
		"<html>\n"
		"\t<head>\n"
		"\t\t<title>BLOCKED!</title>\n"
		"\t</head>\n"
		"\t<body>\n"
		"\t\t<h1>BLOCKED!</h1>\n"
		"\t\t<hr>\n"
		"\t\t<p>This URL has been blocked!</p>\n"
		"\t</body>\n"
		"</html>\n";

	shared_ptr<PACKET_INFO> HijackPtr;
	PPACKET_INFO PacketInfoPtr;
	PACKET_INFO& PacketInfoRef;

public:
	HIJACK::HIJACK(PACKET_INFO& _PacketInfoRef) :
		HijackPtr(new PACKET_INFO[3], 
			std::default_delete<PACKET_INFO[]>()),
		PacketInfoRef(_PacketInfoRef)
	{
		PacketInfoPtr = HijackPtr.get();
		
		//
		// PacketInfoPtr[0] : Reset 
		// PacketInfoPtr[1] : Block
		// PacketInfoPtr[2] : Finish
		//
		for (auto i = 0; i != 3; ++i)
		{
			PacketInfoPtr[i] = _PacketInfoRef;
		}
	}

public:
	void HIJACK::Reset()
	{
		//
		// Send a TCP RST to the server; immediately closing the
		// connection at the server's end.
		//
		PacketInfoPtr[0].TCPHeader.FHL = 0;
		PacketInfoPtr[0].TCPHeader.FHL |= TCP_FLAGS_RST;
		PacketInfoPtr[0].TCPHeader.FHL |= TCP_FLAGS_ACK;
		PacketInfoPtr[0].TCPHeader.Checksum =
			PktUtil::TCPCheckSum(&PacketInfoPtr[0].IPHeader, &PacketInfoPtr[0].TCPHeader);
	}
	void HIJACK::Block()
	{
		//
		// Send the blockpage to the browser.
		//
		PacketInfoPtr[1].IPHeader.TotalLength = htons(sizeof(IP_HEADER) + sizeof(TCP_HEADER) + sizeof(BlockData) - 1);
		PacketInfoPtr[1].IPHeader.Source = PacketInfoRef.IPHeader.Destination;
		PacketInfoPtr[1].IPHeader.Destination = PacketInfoRef.IPHeader.Source;
		PacketInfoPtr[1].IPHeader.Checksum =
			PktUtil::IPCheckSum(&PacketInfoPtr[1].IPHeader);

		PacketInfoPtr[1].TCPHeader.FHL = 0;
		PacketInfoPtr[1].TCPHeader.FHL |= TCP_FLAGS_PSH;
		PacketInfoPtr[1].TCPHeader.FHL |= TCP_FLAGS_ACK;
		PacketInfoPtr[1].TCPHeader.SrcPort = htons(80);
		PacketInfoPtr[1].TCPHeader.DstPort = PacketInfoRef.TCPHeader.SrcPort;
		PacketInfoPtr[1].TCPHeader.Sequence = PacketInfoRef.TCPHeader.Acknowledgemnet;
		PacketInfoPtr[1].TCPHeader.Acknowledgemnet =
			htonl(ntohl(PacketInfoRef.TCPHeader.Sequence) + PacketInfoRef.PayloadLength);
		PacketInfoPtr[1].TCPHeader.Checksum =
			PktUtil::TCPCheckSum(&PacketInfoPtr[1].IPHeader, &PacketInfoPtr[1].TCPHeader);
	}
	void HIJACK::Finish()
	{
		//
		// Send a TCP FIN to the browser; closing the connection at the
		// browser's end.
		PacketInfoPtr[2].IPHeader.Source = PacketInfoRef.IPHeader.Destination;
		PacketInfoPtr[2].IPHeader.Destination = PacketInfoRef.IPHeader.Source;
		PacketInfoPtr[2].IPHeader.Checksum = PktUtil::IPCheckSum(&PacketInfoPtr[2].IPHeader);

		PacketInfoPtr[2].TCPHeader.FHL = 0;
		PacketInfoPtr[2].TCPHeader.FHL |= TCP_FLAGS_FIN;
		PacketInfoPtr[2].TCPHeader.FHL |= TCP_FLAGS_ACK;
		PacketInfoPtr[2].TCPHeader.SrcPort = htons(80);
		PacketInfoPtr[2].TCPHeader.DstPort = PacketInfoRef.TCPHeader.SrcPort;
		PacketInfoPtr[2].TCPHeader.Sequence
			= htonl(ntohl(PacketInfoRef.TCPHeader.Acknowledgemnet) + sizeof(BlockData) - 1);
		PacketInfoPtr[2].TCPHeader.Acknowledgemnet
			= htonl(ntohl(PacketInfoRef.TCPHeader.Sequence) + PacketInfoRef.PayloadLength);
		PacketInfoPtr[2].TCPHeader.Checksum
			= PktUtil::TCPCheckSum(&PacketInfoPtr[2].IPHeader, &PacketInfoPtr[2].TCPHeader);
	}
} *PHIJACK;


using std::chrono::system_clock;

#define STRFTIME_LENGTH 0x00000040
struct ctimepoint
{
	
private:
	time_t RawTime;
	tm TimeInfo;
	errno_t Errno;
	CHAR TimeBuf[STRFTIME_LENGTH];
	system_clock::time_point TimePoint;

public:
	ctimepoint::ctimepoint(void)
	{
		time(&RawTime);
	}

public:
	void now(void)
	{
		Errno = localtime_s(&TimeInfo, &RawTime);
		RawTime = mktime(&TimeInfo);
		TimePoint = system_clock::from_time_t(RawTime);
	}
	LPCSTR ctimepoint::operator()()
	{
		strftime(TimeBuf, sizeof(TimeBuf), "%d-%m-%Y %H-%M-%S", &TimeInfo);

		return TimeBuf;
	}
	operator system_clock::time_point()
	{
		return TimePoint;
	}
};


typedef class TANGU_API _BADURL_LIST
{
	typedef forward_list<string> StringForwardList;
private:
	WINDIVERT_DEVICE WinDivertDev;
	StringForwardList BlackList;
	StringForwardList::iterator BlackListIter;

public:
	_BADURL_LIST::_BADURL_LIST(HANDLE);
	_BADURL_LIST::~_BADURL_LIST(void);

private:
	auto _BADURL_LIST::Match(LPCSTR) -> decltype(true);

public:
	//
	// Block the indexes of list.
	//
	void _BADURL_LIST::Hijack(PACKET_INFO&);

	//
	// List management.
	//
	void _BADURL_LIST::Set(StringForwardList&);
	void _BADURL_LIST::Push(const string&);
}BADURL_LIST, *PBADURL_LIST;

#endif /* _TANGU_BLOCK */