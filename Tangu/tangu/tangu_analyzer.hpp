#pragma once
#ifndef _TANGU_ANALYZER
#define _TANGU_ANALYZER

#include "net_manager.hpp"
#include "packet_field.hpp"

typedef char* HTTPHeader;

enum class PKTBEGIN
{
	LAYER_DATALINK,
	LAYER_NETWORK,
	LAYER_TRANSPORT,
};

__interface PacketAnalyzer
{
	virtual const string& PktParser(const BYTE*, PKTBEGIN) = 0;
};

class PacketInfo : public PacketAnalyzer
{
protected:
	string _DumpContent;
	const string _DumpFiltered;
	CHAR _Format[FORMAT_MESSAGE_ALLOCATE_BUFFER];
	ULONG _No;

	pcap_t*					_Interface;
	struct pcap_pkthdr*	_PacketHeader;
	const LPBYTE			_PacketData;
	
public:
	Packet::ETHERNET_HEADER _MyEthernet;
	Packet::ARP_ARCH _ARPFrame;

	Packet::IP_HEADER _MyIP;
	Packet::ICMP_ARCH _ICMPPacket;

	Packet::TCP_HEADER _MyTCP;

	HTTPHeader _HTTP;

public:
	PacketInfo::PacketInfo(void);

public:
	const string& PacketInfo::DumpData(struct pcap_pkthdr*, const BYTE*, const USHORT Length = 16);

	template <typename _Filter = Common>
	INT PacketInfo::DumpInterface(_Filter* PacketCapturer, std::ostream* Stream)
	{
		PacketAnalyzer*			MyPcapAnalyzer(PacketCapturer);
		__int32					Ret;

		while ((Ret = pcap_next_ex(_Interface, &_PacketHeader, &_PacketData)) >= 0)
		{
			if (Ret == 0)
			{
				continue;
			}
			
			const string& MyHeader(MyPcapAnalyzer->PktParser(_PacketHeader, _PacketData));
			if (MyHeader.length() > 0)
			{
				if (Stream != nullptr)
				{
					system("CLS");
					Stream << MyHeader << endl;
					Stream << PacketCapturer->DumpData(_PacketHeader, _PacketData) << endl;
				}
			}
		}

		return Ret;
	}
};

class Common : public PacketInfo
{
public:
	Common::Common(pcap_t*);

public:
	virtual const string& Common::PktParser(const BYTE*, PKTBEGIN);
};

class ARPAnalyzer : public PacketInfo
{
public:
	ARPAnalyzer::ARPAnalyzer(pcap_t*);

public:
	virtual const string& ARPAnalyzer::PktParser(const BYTE*, PKTBEGIN);
};

class PcapTool
{
protected:
	pcap_t** _Interface;
	pcap_pkthdr* _PacketHeader;
	const byte* _PacketData;

	PacketAnalyzer* _PcapAnalyzer;		/* virtual class : DumpHeader */
	INT _Ret;
	bool _CollectSuccess;

protected:
	PcapTool::PcapTool(void);
};

class NetInfo : protected PcapTool
{
public:
	Packet::ARP _ARPFrame;
	
public:
	NetInfo::NetInfo(pcap_t**);

protected:
	void NetInfo::GenerateARP(Packet::ARP_ARCH::Opcode);
	Packet::ETHERNET_HEADER NetInfo::GetMACAddress(Net::IPInfo&, DOUBLE);
	Net::MACInfo NetInfo::CollectNetworkInfo(Net::IPInfo&, DOUBLE);

public:
	bool NetInfo::IsARPValid(void);
};

#endif /* _ANALYZER */