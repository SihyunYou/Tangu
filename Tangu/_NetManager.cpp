#pragma once
#include "_NetManager"

namespace Net /* _NetManager_H # class Utility*/
{
	byte Utility::AddrBuf[20];

	IP_ADAPTER_INFO* Utility::GetNetworkAdaptersInfo()
	{
		unsigned long BufLen = 0;
		unsigned long Status = GetAdaptersInfo(nullptr, &BufLen);
		IP_ADAPTER_INFO* AdapterInfo = (IP_ADAPTER_INFO*)malloc(BufLen);

		Status = GetAdaptersInfo(AdapterInfo, &BufLen);

		if (Status != ERROR_SUCCESS)
		{
			free(AdapterInfo);
			return nullptr;
		}

		return AdapterInfo;
	}

	void Utility::GetMACAddress(Net::MACInfo& MACAddress)
	{
		MACAddress = MACInfo(Utility::GetNetworkAdaptersInfo()->Address);
	}
	void Utility::GetIPAddress(Net::IPInfo& IPAddress)
	{
		IPAddress.IPStringToHex(Utility::GetNetworkAdaptersInfo()->IpAddressList.IpAddress.String, AddrBuf);
		IPAddress = AddrBuf;
	}
	void Utility::GetGatewayIPAddress(Net::IPInfo& GatewayAddress)
	{
		GatewayAddress.IPStringToHex(Utility::GetNetworkAdaptersInfo()->GatewayList.IpAddress.String, AddrBuf);
		GatewayAddress = AddrBuf;
	}

	bool Utility::RecoveryPeriod(unsigned __int32 Period)
	{
		Sleep(Period);
		return 1;
	}
}

namespace Net /* _NetManager_IP # class IPInfo */
{
	void IPInfo::IPStringToHex(const char* IPString, byte* Buf)
	{
		unsigned Pos{ 0 };
		while (Pos < 4)
		{
			Buf[Pos++] = atoi(IPString);
			IPString = strchr(IPString, '.') + 1;
		}
	}

	IPInfo::IPInfo()
	{
		memset(_bIP, 0x00, 4);
		_sIP = "0.0.0.0";
	}
	IPInfo::IPInfo(const byte* IPByte)
	{
		memcpy(_bIP, IPByte, 4);

		char InternetAddr[16];
		sprintf_s(InternetAddr, "%3i.%3i.%3i.%3i", IPByte[0], IPByte[1], IPByte[2], IPByte[3]);
		_sIP = InternetAddr;
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
	const IPInfo& IPInfo::operator=(const byte* IPByte)
	{
		memcpy(_bIP, IPByte, 4);

		char InternetAddr[16];
		sprintf_s(InternetAddr, "%3i.%3i.%3i.%3i", IPByte[0], IPByte[1], IPByte[2], IPByte[3]);
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

	byte* IPInfo::operator*(void)
	{
		return _bIP;
	}
	string IPInfo::uc_bstr(void)
	{
		return _sIP;
	}
	byte IPInfo::operator[](size_t Octet)
	{
		return (Octet > 4 || Octet < 1) ? _bIP[Octet] : 0;
	}
}

namespace Net /* _NetManager_Link # class MACInfo */
{
	void MACInfo::MACStringToInt(const char* MACString, byte* Buf)
	{
		unsigned Pos{ 0 };
		while (Pos < 6)
		{
			Buf[Pos++] = strtoul(MACString, nullptr, 16);
			MACString = strchr(MACString, '-') + 1;
		}
	}

	MACInfo::MACInfo()
	{
		memset(_bMAC, 0x00, 6);
		_sMAC = "00-00-00-00-00-00";
	}
	MACInfo::MACInfo(const byte* MACByte)
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
	const MACInfo& MACInfo::operator=(const byte* MACByte)
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
