#pragma once
#include "net_manager.hpp"

namespace Net /* _NetManager_H # class Utility*/
{
	BYTE Utility::BufferForAddress[20] = { 0 };

	bool _cdecl CompareSubnetMask(PIP_ADAPTER_INFO IPAdapterInfo)
	{
		Net::IPInfo HostIP(IPAdapterInfo->IpAddressList.IpAddress.String);
		Net::IPInfo GatewayIP(IPAdapterInfo->GatewayList.IpAddress.String);
		Net::SubnetIPInfo HostSubnetMask(IPAdapterInfo->IpAddressList.IpMask.String);

		if (HostIP.uc_bstr() == "0.0.0.0")
		{
			return false;
		}

		return HostIP.Mask(HostSubnetMask) == GatewayIP.Mask(HostSubnetMask)
			? true : false;
	}
	bool _cdecl CompareDescription(PIP_ADAPTER_INFO IPAdapterInfo)
	{
		if (nullptr != strstr(IPAdapterInfo->Description, "Wireless"))
		{
			return true;
		}
		return false;
	}
	bool _cdecl CompareARP(PMIB_IPNETROW IPNetRow)
	{
		Net::PIPAdapterInfo GatewayAddressInfo = Net::IPAdapterInfo::GetInstance();
		if (Net::Utility::GetGatewayIPAddress(GatewayAddressInfo)
			== Net::IPInfo(ntohl(IPNetRow->dwAddr)))
		{
			return true;
		}
		return false;
	}

	IPAdapterInfo* IPAdapterInfo::SingleIPAdapterInfo = nullptr;
	IPAdapterInfo* IPAdapterInfo::GetInstance(void)
	{
		if (nullptr == SingleIPAdapterInfo)
		{
			SingleIPAdapterInfo = new IPAdapterInfo;
		}
		return SingleIPAdapterInfo;
	}

	IPAdapterInfo::IPAdapterInfo(void)
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

	IPAdapterInfo::~IPAdapterInfo(void)
	{

	}

	PIP_ADAPTER_INFO IPAdapterInfo::operator()(void)
	{
		return AdapterInfo;
	}

	PIP_ADAPTER_INFO IPAdapterInfo::GetNode(bool(_cdecl *FuncCompare)(PIP_ADAPTER_INFO))
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

	IPNetTableInfo* IPNetTableInfo::SingleIPNetTableInfo = nullptr;
	IPNetTableInfo* IPNetTableInfo::GetInstance(void)
	{
		if (nullptr == SingleIPNetTableInfo)
		{
			SingleIPNetTableInfo = new IPNetTableInfo;
		}
		return SingleIPNetTableInfo;
	}

	IPNetTableInfo::IPNetTableInfo(void)
		: IpNetTable(nullptr), IsRowCorrespond(false)
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
	IPNetTableInfo::~IPNetTableInfo(void)
	{

	}

	PMIB_IPNETROW IPNetTableInfo::operator()(void)
	{
		return Row;
	}
	PMIB_IPNETROW IPNetTableInfo::GetNode(bool(_cdecl *FuncCompare)(PMIB_IPNETROW))
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


	MACInfo Utility::GetMACAddress(Net::PIPAdapterInfo AdaptersInfo)
	{
		PIP_ADAPTER_INFO IpAdapterInfoNode = AdaptersInfo->GetNode(Net::CompareDescription);
		return nullptr != IpAdapterInfoNode ?
			MACInfo(IpAdapterInfoNode->Address) :
			MACInfo();
	}
	MACInfo Utility::GetGatewayMACAddress(Net::PIPNetTableInfo NetTableInfo)
	{
		PMIB_IPNETROW IpNetRowInfo = NetTableInfo->GetNode(Net::CompareARP);
		return nullptr != IpNetRowInfo ?
			MACInfo(IpNetRowInfo->bPhysAddr) :
			MACInfo();
	}
	IPInfo Utility::GetIPAddress(Net::PIPAdapterInfo AdaptersInfo)
	{
		PIP_ADAPTER_INFO IpAdapterInfoNode = AdaptersInfo->GetNode(Net::CompareDescription);
		return nullptr != IpAdapterInfoNode ?
			IPInfo(IpAdapterInfoNode->IpAddressList.IpAddress.String) :
			IPInfo();
	}
	IPInfo Utility::GetGatewayIPAddress(Net::PIPAdapterInfo AdaptersInfo)
	{
		PIP_ADAPTER_INFO IpAdapterInfoNode = AdaptersInfo->GetNode(Net::CompareDescription);
		return nullptr != IpAdapterInfoNode ?
			IPInfo(IpAdapterInfoNode->GatewayList.IpAddress.String) :
			IPInfo();
	}

	bool Utility::RecoveryPeriod(UINT Period)
	{
		Sleep(Period);
		return 1;
	}
}

namespace Net /* _NetManager_IP # class IPInfo */
{
	void IPInfo::IPStringToHex(const CHAR* IPString, BYTE* Buf)
	{
		unsigned Pos{ 0 };
		while (Pos < 4)
		{
			Buf[Pos++] = atoi(IPString);
			IPString = strchr(IPString, '.') + 1;
		}
	}

	IPInfo::IPInfo(void)
	{
		memset(_bIP, 0x00, 4);
		_sIP = "0.0.0.0";
	}
	IPInfo::IPInfo(const BYTE* IPByte)
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
	IPInfo::IPInfo(const string& IPString)
	{
		_sIP = IPString;
		IPStringToHex(IPString.c_str(), _bIP);
	}
	IPInfo::IPInfo(const IPInfo& IP)
	{
		memcpy(this->_bIP, IP._bIP, 4);
		_sIP = IP._sIP;
	}
	IPInfo::IPInfo(const DWORD dwIP)
	{
		DWORD FullIntegerIP = dwIP;
		BYTE DividedAddressWithCharType[4];
		DividedAddressWithCharType[0] = (BYTE)((FullIntegerIP & 0xFF000000) >> 24);
		DividedAddressWithCharType[1] = (BYTE)((FullIntegerIP & 0x00FF0000) >> 16);
		DividedAddressWithCharType[2] = (BYTE)((FullIntegerIP & 0x0000FF00) >> 8);
		DividedAddressWithCharType[3] = (BYTE)(FullIntegerIP & 0x000000FF);

		*this = (IPInfo)DividedAddressWithCharType;
	}
	const IPInfo& IPInfo::operator=(const BYTE* IPByte)
	{
		memcpy(_bIP, IPByte, 4);

		char InternetAddr[16];
		sprintf_s(InternetAddr, "%i.%i.%i.%i", IPByte[0], IPByte[1], IPByte[2], IPByte[3]);
		_sIP = InternetAddr;

		return *this;
	}
	const IPInfo& IPInfo::operator=(const string& IPString)
	{
		_sIP = IPString;
		IPStringToHex(IPString.c_str(), _bIP);

		return *this;
	}
	const IPInfo& IPInfo::operator=(const IPInfo& IP)
	{
		memcpy(this->_bIP, IP._bIP, 4);
		_sIP = IP._sIP;

		return *this;
	}
	const IPInfo& IPInfo::operator=(const DWORD dwIP)
	{
		*this = IPInfo(dwIP);
		return *this;
	}

	byte* IPInfo::operator*(void)
	{
		return _bIP;
	}

	byte IPInfo::operator[](SIZE_T Octet)
	{
		return (Octet > 4 || Octet < 1) ? _bIP[Octet] : 0;
	}

	bool IPInfo::operator==(IPInfo& IPAddress)
	{
		return IPAddress.uc_bstr() != _sIP ? false : true;
	}

	string IPInfo::uc_bstr(void)
	{
		return _sIP;
	}

	IPInfo& IPInfo::Mask(IPInfo& SubnetIPAddress)
	{
		for (INT i = 0; i != SIZ_PROTOCOL; ++i)
		{
			_bIP[i] &= SubnetIPAddress._bIP[i];
		}
		*this = _bIP;

		return *this;
	}
}

namespace Net /* _NetManager_Link # class MACInfo */
{
	void MACInfo::MACStringToInt(const CHAR* MACString, BYTE* Buf)
	{
		UINT Pos{ 0 };
		while (Pos < 6)
		{
			Buf[Pos++] = (BYTE)strtoul(MACString, nullptr, 16);
			MACString = strchr(MACString, '-') + 1;
		}
	}

	MACInfo::MACInfo(void)
	{
		memset(_bMAC, 0x00, 6);
		_sMAC = "00-00-00-00-00-00";
	}
	MACInfo::MACInfo(const BYTE* MACByte)
	{
		memcpy(_bMAC, MACByte, 6);

		char MediaAddr[18];
		sprintf_s(MediaAddr, "%02x-%02x-%02x-%02x-%02x-%02x", MACByte[0], MACByte[1], MACByte[2], MACByte[3], MACByte[4], MACByte[5]);
		_sMAC = MediaAddr;
	}
	MACInfo::MACInfo(const string& MACString)
	{
		_sMAC = MACString;
		MACStringToInt(MACString.c_str(), _bMAC);
	}
	MACInfo::MACInfo(const MACInfo& MAC)
	{
		memcpy(this->_bMAC, MAC._bMAC, 6);
		this->_sMAC = MAC._sMAC;
	}
	const MACInfo& MACInfo::operator=(const BYTE* MACByte)
	{
		memcpy(_bMAC, MACByte, 6);

		char MediaAddr[18];
		sprintf_s(MediaAddr, "%02x-%02x-%02x-%02x-%02x-%02x", MACByte[0], MACByte[1], MACByte[2], MACByte[3], MACByte[4], MACByte[5]);
		_sMAC = MediaAddr;

		return *this;
	}
	const MACInfo& MACInfo::operator=(const string& MACString)
	{
		MACStringToInt(MACString.c_str(), _bMAC);
		this->_sMAC = MACString;

		return *this;
	}
	const MACInfo& MACInfo::operator=(const MACInfo& MAC)
	{
		memcpy(this->_bMAC, MAC._bMAC, 6);
		this->_sMAC = MAC._sMAC;

		return *this;
	}

	bool MACInfo::operator==(const MACInfo& MAC)
	{
		return MAC._sMAC == this->_sMAC;
	}
	byte* MACInfo::operator*(void)
	{
		return _bMAC;
	}
	string MACInfo::uc_bstr(void)
	{
		return _sMAC;
	}
	byte MACInfo::operator[](size_t Octet)
	{
		return (Octet > 4 || Octet < 1) ? _bMAC[Octet] : 0;
	}
};
