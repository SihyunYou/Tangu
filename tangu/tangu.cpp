//
// tangu.cpp
// Copyright © jynis2937, all rights reserved,
// This program is under the GNU Lesser General Public License.
//

#pragma once
#include <tangu\tangu_analyzer.hpp>
#include <tangu\tangu_spoof.hpp>
#include <tangu\tangu_blocker.hpp>
#include <tangu\tangu_ping.hpp>
#include <tangu\tangu_interface.hpp>
#include <tangu\tangu_divert.hpp>
#include <tangu\tangu_exception.hpp>

//
// tangu.cpp : implementation of the PACKET_INFO class.

_PCAPTOOL::_PCAPTOOL(void) :
	PacketData(nullptr)
{
}
_PCAPTOOL::_PCAPTOOL(PPCAP PcapInterface) :
	Interface(PcapInterface), PacketData(nullptr)
{
}
PACKET_INFO::PACKET_INFO(void) :
	PacketData(nullptr)
{
}
PACKET_INFO::PACKET_INFO(LPCBYTE _PacketData) : 
	PacketData(_PacketData)
{
}
void PACKET_INFO::ParseData(PKTBEGIN Stage)
{
	UINT Offset(0);

	switch (Stage)
	{
	case PKTBEGIN::LAYER_DATALINK:
		goto L2;

	case PKTBEGIN::LAYER_NETWORK:
		goto L3;

	case PKTBEGIN::LAYER_TRANSPORT:
		goto L4;

	case PKTBEGIN::LAYER_APPLICATION:
		goto L5;
	}

L2:	/* TCP/IP PktBegin 2 : Data Link PktBegin { Ethernet } */

	EthernetHeader.Destination = PktUtil::Trace(PacketData, SIZ_HARDWARE);
	EthernetHeader.Source = PktUtil::Trace(PacketData + 6, SIZ_HARDWARE);
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
		
		ARPFrame.SenderMAC = PktUtil::Trace(PacketData + 8, SIZ_HARDWARE);
		ARPFrame.SenderIP = PktUtil::Trace(PacketData + 14, SIZ_PROTOCOL);
		ARPFrame.TargetMAC = PktUtil::Trace(PacketData + 18, SIZ_HARDWARE);
		ARPFrame.TargetIP = PktUtil::Trace(PacketData + 24, SIZ_PROTOCOL);

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
	IPHeader.Source = PktUtil::Trace(PacketData + 12, SIZ_PROTOCOL);
	IPHeader.Destination = PktUtil::Trace(PacketData + 16, SIZ_PROTOCOL);

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

L5:
	switch (static_cast<Packet::TCP_HEADER::Port>(TCPHeader.DstPort))
	{
	case Packet::TCP_HEADER::Port::HTTP:
		break;
	}

Exit:
	return;
}



//
// tangu.cpp : implementation of the ARPSpoof class.

ARPSpoof::ARPSpoof(PPCAP* Interface, Net::IPInfo Target)
{
	Net::IPAdapterInfo* AddressInfo = Net::IPAdapterInfo::GetInstance();

	Gateway.second = Net::Utility::GetGatewayIPAddress(AddressInfo);
	Gateway.first = GetMACAddress(Gateway.second, 30.0);
	ARPFrame._Rsrc.ISrc = Net::Utility::GetIPAddress(AddressInfo);
	ARPFrame._Rsrc.MSrc = Net::Utility::GetMACAddress(AddressInfo);
	ARPFrame._Rsrc.IDst = Target;
	ARPFrame._Rsrc.MDst = GetMACAddress(ARPFrame._Rsrc.IDst, 30.0);
}
void ARPSpoof::Reply(void)
{
	ARPFrame._Rsrc.ISrc = Gateway.second;
	GenerateARP(Packet::ARP_ARCH::Opcode::REPLY);
}
void ARPSpoof::Relay()
{
	BYTE Msg[1500];
	PACKET_INFO CommonPacketHole(PacketData);

	do
	{
		Ret = pcap_next_ex(Interface, &PacketHeader, (const UCHAR**)&PacketData);
		if (0 == Ret)
		{
			continue;
		}

		CommonPacketHole.ParseData(PKTBEGIN::LAYER_DATALINK);
		if (Net::MACInfo(CommonPacketHole.EthernetHeader.Source) == ARPFrame._Rsrc.MDst)
		{
			if (Net::MACInfo(CommonPacketHole.EthernetHeader.Destination) == ARPFrame._Rsrc.MSrc)
			{
				memcpy(Msg, PacketData, PacketHeader->len);
				memcpy(Msg, (LPCBYTE) Gateway.first, SIZ_HARDWARE);
				memcpy(Msg + 6, (LPCBYTE) ARPFrame._Rsrc.MSrc, SIZ_HARDWARE);

				pcap_sendpacket(Interface, Msg, PacketHeader->len);
			}
		}
	} while (Ret >= 0);
}
bool ARPSpoof::IsARPValid()
{
	return SuccessReceived;
}
void ARPSpoof::GenerateARP(Packet::ARP_ARCH::Opcode Operation)
{
	ARPFrame.GetARP(Operation);
	pcap_sendpacket(Interface,
		ARPFrame._Msg,
		sizeof(Packet::ETHERNET_HEADER) + sizeof(Packet::ARP_ARCH));
}



//
// tangu.cpp : implementation of the BADURL_LIST class.

_BADURL_LIST::_BADURL_LIST(HANDLE _Device) :
	WinDivertDev(_Device)
{
}
_BADURL_LIST::~_BADURL_LIST(void)
{
}
void _BADURL_LIST::Hijack(PACKET_INFO& _PacketInfoRef)
{
	if (this->Match((LPCSTR)_PacketInfoRef.ApplicationPayload))
	{
		HIJACK Hijack(_PacketInfoRef);
		Hijack.Reset();
		WinDivertDev.Send(_PacketInfoRef.PacketData, _PacketInfoRef.PacketLength);

		Hijack.Block();
		WinDivertDev.Send(_PacketInfoRef.PacketData, _PacketInfoRef.PacketLength);

		Hijack.Finish();
		WinDivertDev.Send(_PacketInfoRef.PacketData, _PacketInfoRef.PacketLength);
	}
}
void _BADURL_LIST::Set(StringForwardList& _List)
{
	BlackList = _List;
	BlackListIter = _List.end();
}
void _BADURL_LIST::Push(const string& _Url)
{
	BlackListIter = BlackList.insert_after(BlackListIter, _Url);
}
auto _BADURL_LIST::Match(LPCSTR HTTPPayload) -> decltype(true)
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
			for (auto& Lock : BlackList)
			{
				if (Key.second.find(Lock) != string::npos)
				{
					return false;
				}
			}
		}
	}

	return true;
}



//
// tangu.cpp : implementation of the PacketGrouper class.

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

		ICMPPacketHole = PacketData;
		ICMPPacketHole.ParseData(PKTBEGIN::LAYER_DATALINK);
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



//
// tangu.cpp : implementation of the PCAP_DEVICE class.

PCAP_DEVICE::PCAP_DEVICE(std::function<bool(PPCAP_INTERFACE)>& IsMyDevice) :
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
PCAP_DEVICE::PCAP_DEVICE(void)
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
PCAP_DEVICE::~PCAP_DEVICE(void)
{
	if (nullptr != FirstDevice)
	{
		pcap_freealldevs(FirstDevice);
	}
	pcap_close(Interface);
}
void PCAP_DEVICE::OpenLive(LPSTR DeviceName)
{
	Interface = pcap_open_live(DeviceName, 65536, 1, 1000, Error);
}



//
// tangu.cpp : implementation of the WINDIVERT_DEVICE class.

WINDIVERT_DEVICE::WINDIVERT_DEVICE(LPCSTR _Filter) :
	ReadPacketLength(0),
	WrittenPacketLength(0)
{
	DivertDevice = WinDivertOpen(_Filter,
		WINDIVERT_LAYER::WINDIVERT_LAYER_NETWORK,
		0,
		0);

	DWORD Errno = GetLastError();
	if (INVALID_HANDLE_VALUE == DivertDevice &&
		ERROR_SUCCESS != Errno)
	{
		ThrowExcpetions(Errno);
	}
}
WINDIVERT_DEVICE::WINDIVERT_DEVICE(HANDLE _Device) :
	DivertDevice(_Device)
{
}
WINDIVERT_DEVICE::~WINDIVERT_DEVICE(void)
{
	if (nullptr != DivertDevice)
	{
		if (FALSE == WinDivertClose(DivertDevice))
		{
			throw Win32Exception::FromLastError();
		}
	}
}
TANGU_API	void WINDIVERT_DEVICE::ThrowExcpetions(DWORD Errno)
{
	// Refered to http://reqrt.org/windivert-faq.html 

	switch (Errno)
	{
		//
		// DivertOpen() fail 
		//

	case ERROR_FILE_NOT_FOUND:
		// Either one of the WinDivert32.sys or WinDivert64.sys files were not found. 
		throw ErrorFileNotFoundException();

	case ERROR_ACCESS_DENIED:
		// The calling application does not have Administrator privileges. 
		throw ErrorAccessDeniedException();

	case ERROR_INVALID_PARAMETER:
		// This indicates an invalid packet filter string, layer, priority, or flags.
		throw ErrorInvalidParameterException();

	case ERROR_OPEN_FAILED:
		// Only older versions (< 1.0.3) of WinDivert return (110) errors. Please upgrade to the latest version. 
		throw ErrorOpenFailedException();

	case ERROR_PROC_NOT_FOUND:
		// The error may occur for Windows Vista users. The solution is to install the following patch from Microsoft: 
		// http://support.microsoft.com/kb/2761494. 
		throw ErrorProcNotFoundException();

	case ERROR_INVALID_IMAGE_HASH:
		// The WinDivert32.sys or WinDivert64.sys driver file does not have a valid digital signature. 
		throw ErrorInvalidImageHashException();

	case ERROR_DRIVER_BLOCKED:
		// This error occurs for various reasons, including: 
		// * attempting to load the 32 - bit WinDivert.sys driver on a 64 - bit system(or vice versa);
		// * the WinDivert.sys driver is blocked by security software; or
		//	* you are using a virtualization environment that does not support drivers.
		throw ErrorDriverBlockedException();

		//
		// DivertSend() fail
		//
	case ERROR_DATA_NOT_ACCEPTED:
		// This error is returned when the user application attempts to inject a malformed packet. 
		// It may also be returned for valid inbound packets, and the Windows TCP/IP stack rejects the packet for some reason. 
		throw ErrorDataNotAcceptedException();

	case ERROR_RETRY:
		// The underlying cause of this error is unknown. However, this error usually occurs when certain kinds of anti-virus/
		// firewall/security software is installed, and the error message usually resolves once the offending program is uninstalled. 
		// This suggests a software compatibility problem. 
		throw ErrorRetryException();

	default:
		throw Win32Exception::FromWinError(Errno);
	}
}
void WINDIVERT_DEVICE::Receive(void)
{
	BOOL RecvSuccess = WinDivertRecv(DivertDevice,
		Payload,
		sizeof(Payload),
		&Address,
		&ReadPacketLength);

	if (TRUE != RecvSuccess)
	{
		throw Win32Exception::FromLastError();
	}
}
void WINDIVERT_DEVICE::Send(void)
{
	BOOL SendSuccess = WinDivertSend(DivertDevice,
		Payload,
		ReadPacketLength,
		&Address,
		&WrittenPacketLength);
	if (ReadPacketLength != WrittenPacketLength)
	{
		SendSuccess = FALSE;
	}

	if (TRUE != SendSuccess)
	{
		throw Win32Exception::FromLastError();
	}
}
void WINDIVERT_DEVICE::Send(LPCBYTE _Payload, UINT _Length)
{
	BOOL SendSuccess = WinDivertSend(DivertDevice,
		(PVOID) _Payload,
		_Length,
		&Address,
		&WrittenPacketLength);

	if (TRUE != SendSuccess)
	{
		throw Win32Exception::FromLastError();
	}
}



//
// tangu.cpp : implementation of the Win32Exception class.

Win32Exception::Win32Exception(DWORD Errno) :
	_ErrorCode(Errno)
{
}
 Win32Exception::~Win32Exception(void)
{
}
std::exception_ptr Win32Exception::FromLastError(void) noexcept
{
	return FromWinError(::GetLastError());
}
std::exception_ptr Win32Exception::FromWinError(DWORD Errno) noexcept
{
	Win32Exception* Exception;
	switch (Errno)
	{
	case ERROR_SUCCESS:
	{
		Exception = new ErrorSuccessException();
	}
	esac

	case ERROR_INVALID_FUNCTION:
	{
		Exception = new ErrorInvalidFunctionException();
	}
	esac

	case ERROR_FILE_NOT_FOUND:
	{
		Exception = new ErrorFileNotFoundException();
	}
	esac

	case ERROR_PATH_NOT_FOUND:
	{
		Exception = new ErrorPathNotFoundException();
	}
	esac

	case ERROR_ACCESS_DENIED:
	{
		Exception = new ErrorAccessDeniedException();
	}
	esac

	case ERROR_INVALID_HANDLE:
	{
		Exception = new ErrorInvalidHandleException();
	}
	esac

	case ERROR_READ_FAULT:
	{
		Exception = new ErrorReadFaultException();
	}
	esac

	case ERROR_WRITE_FAULT:
	{
		Exception = new ErrorWriteFaultException();
	}
	esac

	case ERROR_INVALID_PARAMETER:
	{
		Exception = new ErrorInvalidParameterException();
	}
	esac

	case ERROR_ALREADY_EXISTS:
	{
		Exception = new ErrorAlreadyExistsException();
	}
	esac

	default:
		Exception = new Win32Exception(Errno);
	}

	return std::make_exception_ptr(Exception);
}
void _declspec(noreturn) Win32Exception::Throw(DWORD WinErrno)
{
	std::rethrow_exception(FromWinError(WinErrno));
}
void _declspec(noreturn) Win32Exception::ThrowFromLastError(void)
{
	Throw(::GetLastError());
}
DWORD Win32Exception::get(void) const
{
	return _ErrorCode;
}
LPCSTR Win32Exception::what(void) const
{
	LPVOID lpMassage = NULL;
	DWORD dwFormat = FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS;
	DWORD dwLanguage = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);

	if (!FormatMessageA(dwFormat, NULL, _ErrorCode, dwLanguage,
		(LPSTR)&lpMassage, 0, NULL))
	{
		return nullptr;
	}

	LocalFree(lpMassage);

	return (LPCSTR)lpMassage;
}