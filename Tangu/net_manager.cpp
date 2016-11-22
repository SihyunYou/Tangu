#pragma once
#include <net_manager\net_manager.hpp>

namespace Net /* net_manager.hpp # class IPAdapterInfo */
{

	TANGU_API IPAdapterInfo* IPAdapterInfo::SingleIPAdapterInfo = nullptr;
	TANGU_API IPAdapterInfo* IPAdapterInfo::GetInstance(void)
	{
		if (nullptr == SingleIPAdapterInfo)
		{
			SingleIPAdapterInfo = new IPAdapterInfo;
		}
		return SingleIPAdapterInfo;
	}

	TANGU_API IPAdapterInfo::IPAdapterInfo(void)
		: SizeOfBuf(0), AdapterInfo(new IP_ADAPTER_INFO)
	{
		IsSuccessed = false;

		Status = ::GetAdaptersInfo(AdapterInfo, &SizeOfBuf);
		if (NULL != AdapterInfo)
		{
			if (ERROR_BUFFER_OVERFLOW == Status)
			{
				delete AdapterInfo;
				AdapterInfo = new IP_ADAPTER_INFO[SizeOfBuf];
			}
		}

		if (NULL != AdapterInfo)
		{
			Status = ::GetAdaptersInfo(AdapterInfo, &SizeOfBuf);
			if (NO_ERROR == Status)
			{
				IsSuccessed = true;
			}
		}
	}
	TANGU_API IPAdapterInfo::~IPAdapterInfo(void)
	{
		if (AdapterInfo)
		{
			delete[] AdapterInfo;
		}
	}

	TANGU_API PIP_ADAPTER_INFO IPAdapterInfo::operator()(void)
	{
		return AdapterInfo;
	}
	TANGU_API PIP_ADAPTER_INFO IPAdapterInfo::GetNode(bool(_cdecl *FuncCompare)(PIP_ADAPTER_INFO))
	{
		bool IsValidResourcesOrNot;
		while (AdapterInfo)
		{
			IsValidResourcesOrNot = FuncCompare(AdapterInfo);
			if (false != IsValidResourcesOrNot)
			{
				break;
			}

			AdapterInfo = AdapterInfo->Next;
		}

		return AdapterInfo;
	}

	TANGU_API bool _cdecl CompareSubnetMask(PIP_ADAPTER_INFO IPAdapterInfo)
	{
		Net::IPInfo HostIP(IPAdapterInfo->IpAddressList.IpAddress.String);
		Net::IPInfo GatewayIP(IPAdapterInfo->GatewayList.IpAddress.String);
		Net::SubnetIPInfo HostSubnetMask(IPAdapterInfo->IpAddressList.IpMask.String);

		if (HostIP() == "0.0.0.0")
		{
			return false;
		}

		return HostIP.Mask(HostSubnetMask) == GatewayIP.Mask(HostSubnetMask)
			? true : false;
	}
	TANGU_API bool _cdecl CompareDescription(PIP_ADAPTER_INFO IPAdapterInfo)
	{
		if (nullptr != strstr(IPAdapterInfo->Description, "Wireless"))
		{
			return true;
		}
		return false;
	}

}

namespace Net /* net_manager.hpp # class IPNetTableInfo */
{

	TANGU_API IPNetTableInfo* IPNetTableInfo::SingleIPNetTableInfo = nullptr;
	TANGU_API IPNetTableInfo* IPNetTableInfo::GetInstance(void)
	{
		if (nullptr == SingleIPNetTableInfo)
		{
			SingleIPNetTableInfo = new IPNetTableInfo;
		}
		return SingleIPNetTableInfo;
	}

	TANGU_API IPNetTableInfo::IPNetTableInfo(void) :
		IpNetTable(nullptr), 
		IsRowCorrespond(false),
		Type { "", "", "Dynamic", "Static" }
	{
		while (ERROR_INSUFFICIENT_BUFFER == (Status = GetIpNetTable((MIB_IPNETTABLE*)IpNetTable,
			&SizeOfPointer,
			TRUE)))
		{
			delete[] IpNetTable;
			IpNetTable = new char[SizeOfPointer];
			Status = GetIpNetTable((MIB_IPNETTABLE*)IpNetTable,
				&SizeOfPointer,
				TRUE);
		}
	}
	TANGU_API IPNetTableInfo::~IPNetTableInfo(void)
	{
		if (IpNetTable)
		{
			delete[] IpNetTable;
		}
	}

	TANGU_API PMIB_IPNETTABLE IPNetTableInfo::GetTable(void)
	{
		return (PMIB_IPNETTABLE)IpNetTable;
	}
	TANGU_API PMIB_IPNETROW IPNetTableInfo::GetNode(bool(_cdecl *FuncCompare)(PMIB_IPNETROW))
	{
		Table = (PMIB_IPNETTABLE)IpNetTable;
		if (IsRowCorrespond)
		{
			return Row = &(Table->table[Index]);
		}

		for (INT i = 0; i != Table->dwNumEntries; ++i)
		{
			Row = &(Table->table[i]);

			if (CompareARP(Row))
			{
				IsRowCorrespond = true;
				Index = i;
				return Row;
			}
		}
		return nullptr;
	}

	TANGU_API bool _cdecl CompareARP(PMIB_IPNETROW IPNetRow)
	{
		Net::PIPAdapterInfo GatewayAddressInfo = Net::IPAdapterInfo::GetInstance();
		if (Net::Utility::GetGatewayIPAddress(GatewayAddressInfo)
			== Net::IPInfo(ntohl(IPNetRow->dwAddr)))
		{
			return true;
		}
		return false;
	}

}

namespace Net /* net_manager.hpp # class Utility */
{

	TANGU_API MACInfo Utility::GetMACAddress(PIPAdapterInfo AdaptersInfo)
	{
		PIP_ADAPTER_INFO IpAdapterInfoNode = AdaptersInfo->GetNode(Net::CompareDescription);
		return nullptr != IpAdapterInfoNode ?
			MACInfo(IpAdapterInfoNode->Address) :
			MACInfo();
	}
	TANGU_API MACInfo Utility::GetGatewayMACAddress(PIPNetTableInfo NetTableInfo)
	{
		PMIB_IPNETROW IpNetRowInfo = NetTableInfo->GetNode(Net::CompareARP);
		return nullptr != IpNetRowInfo ?
			MACInfo(IpNetRowInfo->bPhysAddr) :
			MACInfo();
	}
	TANGU_API IPInfo Utility::GetIPAddress(PIPAdapterInfo AdaptersInfo)
	{
		PIP_ADAPTER_INFO IpAdapterInfoNode = AdaptersInfo->GetNode(Net::CompareDescription);
		return nullptr != IpAdapterInfoNode ?
			IPInfo(IpAdapterInfoNode->IpAddressList.IpAddress.String) :
			IPInfo();
	}
	TANGU_API IPInfo Utility::GetGatewayIPAddress(PIPAdapterInfo AdaptersInfo)
	{
		PIP_ADAPTER_INFO IpAdapterInfoNode = AdaptersInfo->GetNode(Net::CompareDescription);
		return nullptr != IpAdapterInfoNode ?
			IPInfo(IpAdapterInfoNode->GatewayList.IpAddress.String) :
			IPInfo();
	}

}

namespace Net /* net_manager_ip.hpp # class IPInfo */
{

	TANGU_API IPInfo::IPInfo(void)
	{
		memset(_bIP, 0x00, 4);
		_sIP = "0.0.0.0";
	}
	TANGU_API IPInfo::IPInfo(const LPBYTE IPByte)
	{
		if (nullptr != IPByte)
		{
			CHAR Address[16];
			memcpy(_bIP, IPByte, 4);
			sprintf_s(Address, "%i.%i.%i.%i", IPByte[0], IPByte[1], IPByte[2], IPByte[3]);
			_sIP = Address;
		}
		else
		{
			memset(_bIP, 0x00, sizeof(_bIP));
			_sIP = "0.0.0.0";
		}
	}
	TANGU_API IPInfo::IPInfo(const string& IPString)
	{
		_sIP = IPString;
		ipstr_to_hex(IPString.c_str(), _bIP);
	}
	TANGU_API IPInfo::IPInfo(const IPInfo& IP)
	{
		memcpy(this->_bIP, IP._bIP, 4);
		_sIP = IP._sIP;
	}
	TANGU_API IPInfo::IPInfo(const DWORD dwIP)
	{
		DWORD FullIntegerIP = dwIP;
		BYTE DividedAddressWithCharType[4];
		DividedAddressWithCharType[0] = (BYTE)((FullIntegerIP & 0xFF000000) >> 24);
		DividedAddressWithCharType[1] = (BYTE)((FullIntegerIP & 0x00FF0000) >> 16);
		DividedAddressWithCharType[2] = (BYTE)((FullIntegerIP & 0x0000FF00) >> 8);
		DividedAddressWithCharType[3] = (BYTE)(FullIntegerIP & 0x000000FF);

		*this = (IPInfo)DividedAddressWithCharType;
	}
	TANGU_API const IPInfo& IPInfo::operator=(const LPBYTE IPByte)
	{
		memcpy(_bIP, IPByte, 4);

		char InternetAddr[16];
		sprintf_s(InternetAddr, "%i.%i.%i.%i", IPByte[0], IPByte[1], IPByte[2], IPByte[3]);
		_sIP = InternetAddr;

		return *this;
	}
	TANGU_API const IPInfo& IPInfo::operator=(const string& IPString)
	{
		_sIP = IPString;
		ipstr_to_hex(IPString.c_str(), _bIP);

		return *this;
	}
	TANGU_API const IPInfo& IPInfo::operator=(const IPInfo& IP)
	{
		memcpy(this->_bIP, IP._bIP, 4);
		_sIP = IP._sIP;

		return *this;
	}
	TANGU_API const IPInfo& IPInfo::operator=(const DWORD dwIP)
	{
		*this = IPInfo(dwIP);
		return *this;
	}

	TANGU_API void IPInfo::ipstr_to_hex(LPCSTR IPString, LPBYTE Buf)
	{
#define STRPOS(str, c) strchr(str, c) - (str) + 1
		
		UINT i{ 0 }, offset{ 0 };
		do
		{
			*(Buf + i++) = atoi(IPString + offset);
			offset += STRPOS(IPString + offset, '.');
		} while (i < 4);

#undef STRPOS
	}

	TANGU_API const LPBYTE IPInfo::operator*(void)
	{
		return _bIP;
	}
	TANGU_API BYTE IPInfo::operator[](SIZE_T Octet)
	{
		return (Octet > 4 || Octet < 1) ? _bIP[Octet] : 0;
	}
	TANGU_API bool IPInfo::operator==(const IPInfo& InternetProtocolInfo)
	{
		return InternetProtocolInfo._sIP == this->_sIP;
	}
	TANGU_API string IPInfo::operator()(void)
	{
		return _sIP;
	}

	TANGU_API bool IPInfo::IsEmpty(void)
	{
		for (INT i = SIZ_PROTOCOL - 1; i != 0; --i)
		{
			if (0 != _bIP[i])
			{
				return false;
			}
		}
		return true;
	}
	TANGU_API IPInfo& IPInfo::Mask(IPInfo& SubnetIPAddress)
	{
		for (INT i = 0; i != SIZ_PROTOCOL; ++i)
		{
			_bIP[i] &= SubnetIPAddress._bIP[i];
		}
		*this = _bIP;

		return *this;
	}

}

namespace Net /* net_manager_link.hpp # class MACInfo */
{

	TANGU_API MACInfo::MACInfo(void)
	{
		memset(_bMAC, 0x00, SIZ_HARDWARE);
		_sMAC = "00-00-00-00-00-00";
	}
	TANGU_API MACInfo::MACInfo(const LPBYTE MediaByte)
	{
		memcpy(_bMAC, MediaByte, SIZ_HARDWARE);

		CHAR MediaAddr[18];
		sprintf_s(MediaAddr, "%02x-%02x-%02x-%02x-%02x-%02x", 
			MediaByte[0], MediaByte[1], MediaByte[2], MediaByte[3], MediaByte[4], MediaByte[5]);
		_sMAC = MediaAddr;
	}
	TANGU_API MACInfo::MACInfo(const string& MediaCode)
	{
		_sMAC = MediaCode;
		this->macstr_to_hex(MediaCode.c_str(), _bMAC);
	}
	TANGU_API MACInfo::MACInfo(const MACInfo& MediaAccessControlInfo)
	{
		memcpy(this->_bMAC, MediaAccessControlInfo._bMAC, SIZ_HARDWARE);
		this->_sMAC = MediaAccessControlInfo._sMAC;
	}
	TANGU_API const MACInfo& MACInfo::operator=(const LPBYTE MediaByte)
	{
		memcpy(_bMAC, MediaByte, SIZ_HARDWARE);

		CHAR MediaAddr[18];
		sprintf_s(MediaAddr, "%02x-%02x-%02x-%02x-%02x-%02x", 
			MediaByte[0], MediaByte[1], MediaByte[2], MediaByte[3], MediaByte[4], MediaByte[5]);
		_sMAC = MediaAddr;

		return *this;
	}
	TANGU_API const MACInfo& MACInfo::operator=(const string& MediaCode)
	{
		this->macstr_to_hex(MediaCode.c_str(), _bMAC);
		this->_sMAC = MediaCode;

		return *this;
	}
	TANGU_API const MACInfo& MACInfo::operator=(const MACInfo& MediaAccessControlInfo)
	{
		memcpy(this->_bMAC, MediaAccessControlInfo._bMAC, SIZ_HARDWARE);
		this->_sMAC = MediaAccessControlInfo._sMAC;

		return *this;
	}

	TANGU_API void MACInfo::macstr_to_hex(LPCSTR MediaCode, LPBYTE Buf)
	{
		UINT Pos{ 0 };
		while (Pos < SIZ_HARDWARE)
		{
			Buf[Pos++] = (BYTE)strtoul(MediaCode, nullptr, 16);
			MediaCode = strchr(MediaCode, '-') + 1;
		}
	}

	TANGU_API const LPBYTE MACInfo::operator*(void)
	{
		return _bMAC;
	}
	TANGU_API BYTE MACInfo::operator[](SIZE_T Octet)
	{
		return (Octet >= SIZ_HARDWARE || Octet < 0) ? _bMAC[Octet] : 0;
	}
	TANGU_API bool MACInfo::operator==(const MACInfo& MediaAccessControlInfo)
	{
		return MediaAccessControlInfo._sMAC == this->_sMAC;
	}
	TANGU_API string MACInfo::operator()(void)
	{
		return _sMAC;
	}

};
