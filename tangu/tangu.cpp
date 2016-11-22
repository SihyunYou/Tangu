#pragma once
#include <tangu\tangu_analyzer.hpp>

TANGU_API _PCAPTOOL::_PCAPTOOL(void) :
	PacketData(nullptr)
{

}
TANGU_API _PCAPTOOL::_PCAPTOOL(PPCAP PcapInterface) :
	Interface(PcapInterface), PacketData(nullptr)
{

}
TANGU_API PACKET_INFO::PACKET_INFO(void)
{

}
TANGU_API string PACKET_INFO::PktParseString(const LPBYTE PacketData, PKTBEGIN Stage)
{
	string DumpString("");
	UINT Offset(0);

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

	memcpy(EthernetHeader.Destination, PacketData, 6);
	memcpy(EthernetHeader.Source, PacketData + 6, 6);
	EthernetHeader.Type = PktUtil::Trace(PacketData + 12, 2);
	DumpString += "┌────────────────────────────────┐\n";

	PktUtil::CustomPermutate(DumpString, "│   [Source MAC]   %02x:%02x:%02x:%02x:%02x:%02x                             │\n",
		EthernetHeader.Source[0], EthernetHeader.Source[1], EthernetHeader.Source[2], EthernetHeader.Source[3], EthernetHeader.Source[4], EthernetHeader.Source[5]);

	PktUtil::CustomPermutate(DumpString, "│[Destination MAC] %02x:%02x:%02x:%02x:%02x:%02x                             │\n",
		EthernetHeader.Destination[0], EthernetHeader.Destination[1], EthernetHeader.Destination[2], EthernetHeader.Destination[3], EthernetHeader.Destination[4], EthernetHeader.Destination[5]);

	Offset += sizeof(Packet::ETHERNET_HEADER);
	DumpString += "│      [Type]      ";
	switch (static_cast<Packet::ETHERNET_HEADER::EthernetType> (htons(EthernetHeader.Type)))
	{
	case Packet::ETHERNET_HEADER::EthernetType::ARP:
		DumpString += "Address Resolution Protocol (ARP) ";
		ARPFrame.HardwareType = PktUtil::Trace(PacketData, 2);
		ARPFrame.ProtocolType = PktUtil::Trace(PacketData + 2, 2);
		ARPFrame.MACLen = PktUtil::Trace(PacketData + 4, 1);
		ARPFrame.IPLen = PktUtil::Trace(PacketData + 5, 1);
		ARPFrame.Operation = PktUtil::Trace(PacketData + 6, 2);

		memcpy(ARPFrame.SenderMAC, PacketData + 8, SIZ_HARDWARE);
		memcpy(ARPFrame.SenderIP, PacketData + 14, SIZ_PROTOCOL);
		memcpy(ARPFrame.TargetMAC, PacketData + 18, SIZ_HARDWARE);
		memcpy(ARPFrame.TargetIP, PacketData + 24, SIZ_PROTOCOL);

		goto Exit;

	case Packet::ETHERNET_HEADER::EthernetType::IPV4:
		DumpString += "Internet Protocol Version 4 (IPv4)";
		break;

	}
	PktUtil::CustomPermutate(DumpString, " (0x%04x)   │\n", EthernetHeader.Type);
	DumpString += "└────────────────────────────────┘\n";


L3: /* TCP/IP PktBegin 3 : Internet PktBegin { IPv4 }*/

	IPHeader.IHL = PktUtil::Trace(PacketData, 1);
	IPHeader.ServiceType = PktUtil::Trace(PacketData + 1, 1);
	IPHeader.TotalLength = PktUtil::Trace(PacketData + 2, 2);
	IPHeader.ldentification = PktUtil::Trace(PacketData + 4, 2);

	IPHeader.Fragmention = PktUtil::Trace(PacketData + 6, 2);
	IPHeader.TTL = PktUtil::Trace(PacketData + 8, 1);
	IPHeader.Protocol = PktUtil::Trace(PacketData + 9, 1);
	IPHeader.Checksum = PktUtil::Trace(PacketData + 10, 2);
	memcpy(IPHeader.Source, PacketData + 12, SIZ_PROTOCOL);
	memcpy(IPHeader.Destination, PacketData + 16, SIZ_PROTOCOL);

	DumpString += "┌────────────────────────────────┐\n";
	PktUtil::CustomPermutate(DumpString, "│   [Source  IP]   %3i.%3i.%3i.%3i                               │\n",
		IPHeader.Source[0], IPHeader.Source[1], IPHeader.Source[2], IPHeader.Source[3]);
	PktUtil::CustomPermutate(DumpString, "│ [Destination IP] %3i.%3i.%3i.%3i                               │\n",
		IPHeader.Destination[0], IPHeader.Destination[1], IPHeader.Destination[2], IPHeader.Destination[3]);

	DumpString += "│    [Protocol]    ";
	Offset += sizeof(Packet::IP_HEADER);
	switch (static_cast<Packet::IP_HEADER::IPProto>(IPHeader.Protocol))
	{
	case Packet::IP_HEADER::IPProto::ICMP:
		DumpString += "ICMP   ";

		ICMPPacket.Type = PktUtil::Trace(PacketData, 1);
		ICMPPacket.Code = PktUtil::Trace(PacketData + 1, 1);
		ICMPPacket.Checksum = PktUtil::Trace(PacketData + 2, 2);
		ICMPPacket.Identifier = PktUtil::Trace(PacketData + 4, 2);
		ICMPPacket.Sequence = PktUtil::Trace(PacketData + 6, 2);

		memcpy(ICMPPacket.Data, "abcdefghijklmnopqrstuvwabcdfghi", 32);

		goto Exit;

	case Packet::IP_HEADER::IPProto::TCP:
		DumpString += "Transmission Control Protocol (TCP)";
		break;

	case Packet::IP_HEADER::IPProto::USER_DATAGRAM:
		DumpString += "User Datagram Protocol (UDP)";
		goto Exit;

	default:
		DumpString += "UNKNOWN";
		goto Exit;
	}
	PktUtil::CustomPermutate(DumpString, " (0x%02x)                                │\n", IPHeader.Protocol);
	DumpString += "└────────────────────────────────┘\n";


L4: /* TCP/IP PktBegin 4 : Transport PktBegin { TCP }*/

	TCPHeader.SrcPort = PktUtil::Trace(PacketData, 2);
	TCPHeader.DstPort = PktUtil::Trace(PacketData + 2, 2);
	TCPHeader.Sequence = PktUtil::Trace(PacketData + 4, 4);
	TCPHeader.Acknowledgemnet = PktUtil::Trace(PacketData + 8, 4);

	TCPHeader.FHL = PktUtil::Trace(PacketData + 12, 2);
	TCPHeader.WindowSize = PktUtil::Trace(PacketData + 14, 2);
	TCPHeader.Checksum = PktUtil::Trace(PacketData + 16, 2);
	TCPHeader.UrgentPointer = PktUtil::Trace(PacketData + 18, 2);

	DumpString += "┌────────────────────────────────┐\n";
	PktUtil::CustomPermutate(DumpString, "│   [Source  Port]   %5i                                       │\n", TCPHeader.SrcPort);
	PktUtil::CustomPermutate(DumpString, "│ [Destination Port] %5i                                       │\n", TCPHeader.DstPort);
	DumpString += "└────────────────────────────────┘\n";

	//
	// sizeof(Packet::TCP_HEADER) + TCP Options' size 
	//
	Offset += (((TCPHeader.FHL >> 12) & 0x07) * 4);

	switch (static_cast<Packet::TCP_HEADER::Port>(TCPHeader.DstPort))
	{
	case Packet::TCP_HEADER::Port::HTTP:
		break;
	}

	goto Pass;
Exit:
	DumpString += "\n└────────────────────────────────┘\n";
Pass:
	DumpString += "\n\n";
	return DumpString;
}
void PACKET_INFO::PktParseData(const LPBYTE PacketData, PKTBEGIN Stage)
{
	string DumpString("");
	UINT Offset(0);

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

	memcpy(EthernetHeader.Destination, PacketData, 6);
	memcpy(EthernetHeader.Source, PacketData + 6, 6);
	EthernetHeader.Type = PktUtil::Trace(PacketData + 12, 2);

	Offset += sizeof(Packet::ETHERNET_HEADER);
	switch (static_cast<Packet::ETHERNET_HEADER::EthernetType> (htons(EthernetHeader.Type)))
	{
	case Packet::ETHERNET_HEADER::EthernetType::ARP:
		ARPFrame.HardwareType = PktUtil::Trace(PacketData, 2);
		ARPFrame.ProtocolType = PktUtil::Trace(PacketData + 2, 2);
		ARPFrame.MACLen = PktUtil::Trace(PacketData + 4, 1);
		ARPFrame.IPLen = PktUtil::Trace(PacketData + 5, 1);
		ARPFrame.Operation = PktUtil::Trace(PacketData + 6, 2);

		memcpy(ARPFrame.SenderMAC, PacketData + 8, SIZ_HARDWARE);
		memcpy(ARPFrame.SenderIP, PacketData + 14, SIZ_PROTOCOL);
		memcpy(ARPFrame.TargetMAC, PacketData + 18, SIZ_HARDWARE);
		memcpy(ARPFrame.TargetIP, PacketData + 24, SIZ_PROTOCOL);

		goto Exit;

	case Packet::ETHERNET_HEADER::EthernetType::IPV4:
		break;
	}

L3: /* TCP/IP PktBegin 3 : Internet PktBegin { IPv4 }*/

	IPHeader.IHL = PktUtil::Trace(PacketData, 1);
	IPHeader.ServiceType = PktUtil::Trace(PacketData + 1, 1);
	IPHeader.TotalLength = PktUtil::Trace(PacketData + 2, 2);
	IPHeader.ldentification = PktUtil::Trace(PacketData + 4, 2);

	IPHeader.Fragmention = PktUtil::Trace(PacketData + 6, 2);
	IPHeader.TTL = PktUtil::Trace(PacketData + 8, 1);
	IPHeader.Protocol = PktUtil::Trace(PacketData + 9, 1);
	IPHeader.Checksum = PktUtil::Trace(PacketData + 10, 2);
	memcpy(IPHeader.Source, PacketData + 12, SIZ_PROTOCOL);
	memcpy(IPHeader.Destination, PacketData + 16, SIZ_PROTOCOL);

	Offset += sizeof(Packet::IP_HEADER);
	switch (static_cast<Packet::IP_HEADER::IPProto>(IPHeader.Protocol))
	{
	case Packet::IP_HEADER::IPProto::ICMP:
		ICMPPacket.Type = PktUtil::Trace(PacketData, 1);
		ICMPPacket.Code = PktUtil::Trace(PacketData + 1, 1);
		ICMPPacket.Checksum = PktUtil::Trace(PacketData + 2, 2);
		ICMPPacket.Identifier = PktUtil::Trace(PacketData + 4, 2);
		ICMPPacket.Sequence = PktUtil::Trace(PacketData + 6, 2);

		memcpy(ICMPPacket.Data, "abcdefghijklmnopqrstuvwabcdfghi", 32);

		goto Exit;

	case Packet::IP_HEADER::IPProto::TCP:
		break;

	case Packet::IP_HEADER::IPProto::USER_DATAGRAM:
		goto Exit;

	default:
		goto Exit;
	}

L4: /* TCP/IP PktBegin 4 : Transport PktBegin { TCP }*/

	TCPHeader.SrcPort = PktUtil::Trace(PacketData, 2);
	TCPHeader.DstPort = PktUtil::Trace(PacketData + 2, 2);
	TCPHeader.Sequence = PktUtil::Trace(PacketData + 4, 4);
	TCPHeader.Acknowledgemnet = PktUtil::Trace(PacketData + 8, 4);

	TCPHeader.FHL = PktUtil::Trace(PacketData + 12, 2);
	TCPHeader.WindowSize = PktUtil::Trace(PacketData + 14, 2);
	TCPHeader.Checksum = PktUtil::Trace(PacketData + 16, 2);
	TCPHeader.UrgentPointer = PktUtil::Trace(PacketData + 18, 2);

	Offset += (((TCPHeader.FHL >> 12) & 0x07) * 4);

	switch (static_cast<Packet::TCP_HEADER::Port>(TCPHeader.DstPort))
	{
	case Packet::TCP_HEADER::Port::HTTP:
		break;
	}

Exit:
	return;
}


#include <tangu\tangu_spoof.hpp>

TANGU_API ARPSpoof::ARPSpoof(PPCAP* Interface, Net::IPInfo Target)
{
	Net::IPAdapterInfo* AddressInfo = Net::IPAdapterInfo::GetInstance();

	Gateway.second = Net::Utility::GetGatewayIPAddress(AddressInfo);
	Gateway.first = GetMACAddress(Gateway.second, 30.0);
	ARPFrame._Rsrc.ISrc = Net::Utility::GetIPAddress(AddressInfo);
	ARPFrame._Rsrc.MSrc = Net::Utility::GetMACAddress(AddressInfo);
	ARPFrame._Rsrc.IDst = Target;
	ARPFrame._Rsrc.MDst = GetMACAddress(ARPFrame._Rsrc.IDst, 30.0);
}
TANGU_API void ARPSpoof::Reply(void)
{
	ARPFrame._Rsrc.ISrc = Gateway.second;
	GenerateARP(Packet::ARP_ARCH::Opcode::REPLY);
}
TANGU_API void ARPSpoof::Relay()
{
	BYTE Msg[1500];
	PACKET_INFO CommonPacketHole;

	do
	{
		Ret = pcap_next_ex(Interface, &PacketHeader, (const UCHAR**)&PacketData);
		if (0 == Ret)
		{
			continue;
		}

		CommonPacketHole.PktParseData(PacketData, PKTBEGIN::LAYER_DATALINK);
		if (Net::MACInfo{ CommonPacketHole.EthernetHeader.Source } == ARPFrame._Rsrc.MDst)
		{
			if (Net::MACInfo{ CommonPacketHole.EthernetHeader.Destination } == ARPFrame._Rsrc.MSrc)
			{
				memcpy(Msg, PacketData, PacketHeader->len);
				memcpy(Msg, *(Gateway.first), SIZ_HARDWARE);
				memcpy(Msg + 6, *(ARPFrame._Rsrc.MSrc), SIZ_HARDWARE);

				pcap_sendpacket(Interface, Msg, PacketHeader->len);
			}
		}
	} while (Ret >= 0);
}
TANGU_API bool ARPSpoof::IsARPValid()
{
	return SuccessReceived;
}
TANGU_API void ARPSpoof::GenerateARP(Packet::ARP_ARCH::Opcode Operation)
{
	ARPFrame.GetARP(Operation);
	pcap_sendpacket(Interface,
		ARPFrame._Msg,
		sizeof(Packet::ETHERNET_HEADER) + sizeof(Packet::ARP_ARCH));
}



#include <tangu\tangu_blocker.hpp>

TANGU_API _BADURL_LIST::_BADURL_LIST(LPCSTR Txt_MalformedSite) :
	UrlStream(Txt_MalformedSite, ios::in),
	LogStream(LOGGER_PATH, ios::out)
{
	assert(LogStream.is_open());

	string Ban;
	It = BlockedURL.before_begin();
	while (UrlStream.good())
	{
		std::getline(UrlStream, Ban);

		Algorithm::erase_all(Ban, "http://");

#pragma warning(push)
#pragma warning(disable : 4566)
		//
		// Algorithm::erase_all(Ban, L"\u...");
		//
#pragma warning(pop)

		It = BlockedURL.insert_after(It, Ban);
	}
	UrlStream.close();

	// 
	// set timer.
	//
	time(&RawTime);
	localtime_s(&TimeInfo, &RawTime);
}
TANGU_API _BADURL_LIST::~_BADURL_LIST(void)
{
	LogStream.close();
}
TANGU_API void _BADURL_LIST::LogAccess(void)
{
	strftime(TimeBuf, sizeof(TimeBuf), "%d-%m-%Y %H-%M-%S", &TimeInfo);
}
TANGU_API void _BADURL_LIST::Add(string URL)
{
	It = BlockedURL.insert_after(It, URL);
}
TANGU_API bool _BADURL_LIST::Match(LPSTR HTTPPayload)
{
	unordered_map<string, string> HTTPParsedInfo;
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
					LogAccess();
					LogStream << TimeBuf << ' ' << Lock << std::endl << std::flush;

					return false;
				}
			}
		}
	}

	return true;
}



#include <tangu\tangu_ping.hpp>

long long _TIME_POINT::operator()(void)
{
	return duration_cast<milliseconds>(End - Start).count();
}

PacketGrouper::PacketGrouper(PPCAP* Interface, Net::IPInfo Target) :
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
PacketGrouper::STATISTICS& PacketGrouper::GetStats(void)
{
	return Stat;
}



#include <tangu\tangu_interface.hpp>

TANGU_API PCAP_DEVICE::PCAP_DEVICE(bool(*IsMyDevice)(PPCAP_INTERFACE)) :
	DeviceNum(0)
{
	Status = pcap_findalldevs(&FirstDevice, Error);
	if (PCAP_ERROR == Status)
	{
		goto PCAP_DEVICE_FAILED;
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

PCAP_DEVICE_FAILED:
	;
}
TANGU_API PCAP_DEVICE::PCAP_DEVICE(void)
{
	DeviceChar = pcap_lookupdev(Error);
	if (nullptr == DeviceChar)
	{
		goto PCAP_DEVICE_FAILED;
	}

	Status = pcap_lookupnet(DeviceChar, &Net, &Mask, Error);
	if (PCAP_ERROR == Status)
	{
		goto PCAP_DEVICE_FAILED;
	}

	struct in_addr NetAddress;
	struct in_addr MaskAddress;

	NetAddress.s_addr = Net;
	MaskAddress.s_addr = Mask;

	OpenLive(DeviceChar);

PCAP_DEVICE_FAILED:
	;
}
TANGU_API PCAP_DEVICE::~PCAP_DEVICE(void)
{
	if (nullptr != FirstDevice)
	{
		pcap_freealldevs(FirstDevice);
	}
	pcap_close(Interface);
}
TANGU_API void PCAP_DEVICE::OpenLive(LPSTR DeviceName)
{
	Interface = pcap_open_live(DeviceName, 65536, 1, 1000, Error);
}

TANGU_API bool IsMyDeviceWithAddress(PPCAP_INTERFACE Device)
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
TANGU_API bool IsMyDeviceWithDescription(PPCAP_INTERFACE Device)
{
	return string(Device->description) == "Microsoft" ? true : false;
}


TANGU_API WINDIVERT_DEVICE::WINDIVERT_DEVICE(LPCSTR Filter) :
	PacketLen(0)
{
	HDivertDev = WinDivertOpen(Filter,
		WINDIVERT_LAYER::WINDIVERT_LAYER_NETWORK,
		0,
		0);

	DWORD Errno = GetLastError();
	if (INVALID_HANDLE_VALUE == HDivertDev &&
		ERROR_SUCCESS != Errno)
	{
		switch (Errno)
		{
		case ERROR_FILE_NOT_FOUND:
			throw ErrorFileNotFoundException();

		case ERROR_ACCESS_DENIED:
			throw ErrorAccessDeniedException();

		case ERROR_INVALID_PARAMETER:
			throw ErrorInvalidParameterException();

		case ERROR_INVALID_IMAGE_HASH:
			throw ErrorInvalidImageHashException();

		case ERROR_DRIVER_BLOCKED:
			throw ErrorDriverBlockedException();

		default:
			throw Win32Exception::FromLastError();
		}
	}
}
TANGU_API WINDIVERT_DEVICE::~WINDIVERT_DEVICE(void)
{
	if (nullptr != HDivertDev)
	{
		WinDivertClose(HDivertDev);
	}
}
TANGU_API const LPBYTE WINDIVERT_DEVICE::Receive(void)
{
	if (TRUE != WinDivertRecv(HDivertDev,
		Payload,
		sizeof(Payload),
		&PAddr,
		&ReadLen))
	{
		throw ErrorReadFaultException();
	}

	return Payload;
}
TANGU_API const LPBYTE WINDIVERT_DEVICE::Send(void)
{
	if (TRUE != WinDivertSend(HDivertDev,
		Payload,
		ReadLen,
		&PAddr,
		nullptr))
	{
		throw ErrorWriteFaultException();
	}

	return Payload;
}
TANGU_API const LPBYTE WINDIVERT_DEVICE::ReceiveAndSend(void)
{
	this->Receive();
	return this->Send();
}

Win32Exception::Win32Exception(DWORD Errno) :
	ErrorCode(Errno)
{
}
std::exception_ptr Win32Exception::FromLastError(void) noexcept
{
	return FromWinError(::GetLastError());
}
std::exception_ptr Win32Exception::FromWinError(DWORD Errno) noexcept
{
	using std::make_exception_ptr;
	switch (Errno)
	{
	case ERROR_SUCCESS:
		return make_exception_ptr(ErrorSuccessException());

	case ERROR_INVALID_FUNCTION:
		return make_exception_ptr(ErrorInvalidFunctionException());

	case ERROR_FILE_NOT_FOUND:
		return make_exception_ptr(ErrorFileNotFoundException());

	case ERROR_PATH_NOT_FOUND:
		return make_exception_ptr(ErrorPathNotFoundException());

	case ERROR_TOO_MANY_OPEN_FILES:
		return make_exception_ptr(ErrorTooManyOpenFilesException());

	case ERROR_ACCESS_DENIED:
		return make_exception_ptr(ErrorAccessDeniedException());

	case ERROR_INVALID_HANDLE:
		return make_exception_ptr(ErrorInvalidHandleException());

	case ERROR_ALREADY_EXISTS:
		return make_exception_ptr(ErrorAlreadyExistsException());

	case ERROR_INVALID_PARAMETER:
		return make_exception_ptr(ErrorInvalidParameterException());

	case ERROR_MOD_NOT_FOUND:
		return make_exception_ptr(ErrorModuleNotFoundException());

	case ERROR_PROC_NOT_FOUND:
		return make_exception_ptr(ErrorProcedureNotFoundException());

	default:
		return make_exception_ptr(Win32Exception(Errno));
	}
}
void _declspec(noreturn) Win32Exception::Throw(DWORD LastError)
{
	std::rethrow_exception(FromWinError(LastError));
}
void _declspec(noreturn) Win32Exception::ThrowFromLastError(void)
{
	Throw(::GetLastError());
}
DWORD Win32Exception::GetErrorCode(void) const
{
	return ErrorCode;
}
LPCSTR Win32Exception::what(void) const
{
	LPVOID lpMassage = NULL;
	DWORD dwFormat = FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS;
	DWORD dwLanguage = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);

	if (!FormatMessageA(dwFormat, NULL, ErrorCode, dwLanguage,
		(LPSTR)&lpMassage, 0, NULL))
	{
		return nullptr;
	}

	LocalFree(lpMassage);

	return (LPCSTR)lpMassage;
}