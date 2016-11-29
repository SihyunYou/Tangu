//
// net_manager.cpp
// Copyright © jynis2937, all rights reserved,
// This program is under the GNU Lesser General Public License.
//

#pragma once
#include <net_manager\net_manager.hpp>

namespace Net /* net_manager_exception.hpp # class NetException */
{
	NetException::NetException(NET_ERROR Errno) :
		_ErrorCode(Errno)
	{
	}
	NetException::~NetException(void)
	{
	}

	exception_ptr NetException::FromNetError(NET_ERROR Errno) noexcept
	{
		static NetException* Exception;
		switch (Errno)
		{
		case NET_ERROR::ERROR_INTEGER_OVERFLOW:
			Exception = new ErrorIntegerOverflowException();
			break;

		case NET_ERROR::ERROR_INVALID_SUBNET_MASK:
			Exception = new ErrorInvalidSubnetMaskException();
			break;

		default:
			Exception = new NetException(Errno);
		}

		return make_exception_ptr(Exception);
	}
	void _declspec(noreturn) NetException::Throw(NET_ERROR NetErrno)
	{
		std::rethrow_exception(NetException::FromNetError(NetErrno));
	}

	DWORD NetException::get(void) const
	{
		return static_cast<DWORD>(_ErrorCode);
	}
	LPCSTR NetException::what(void) const
	{
		switch (_ErrorCode)
		{
		case NET_ERROR::ERROR_PASS:
			return "";

		case NET_ERROR::ERROR_INTEGER_OVERFLOW:
			return "";

		case NET_ERROR::ERROR_INVALID_SUBNET_MASK:
			return "";

		default:
			return "";
			;
		}
	}

}

namespace Net /* net_manager.hpp # class IPAdapterInfo */
{

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
		if (AdapterInfo)
		{
			delete[] AdapterInfo;
		}
	}

	PIP_ADAPTER_INFO IPAdapterInfo::operator()(void)
	{
		return AdapterInfo;
	}
	PIP_ADAPTER_INFO IPAdapterInfo::GetNode(std::function<bool(PIP_ADAPTER_INFO)> CompareSpecifies)
	{
		bool IsValidResourcesOrNot;
		while (AdapterInfo)
		{
			IsValidResourcesOrNot = CompareSpecifies(AdapterInfo);
			if (false != IsValidResourcesOrNot)
			{
				break;
			}

			AdapterInfo = AdapterInfo->Next;
		}

		return AdapterInfo;
	}

}

namespace Net /* net_manager.hpp # class IPNetTableInfo */
{

	IPNetTableInfo* IPNetTableInfo::SingleIPNetTableInfo = nullptr;
	IPNetTableInfo* IPNetTableInfo::GetInstance(void)
	{
		if (nullptr == SingleIPNetTableInfo)
		{
			SingleIPNetTableInfo = new IPNetTableInfo;
		}
		return SingleIPNetTableInfo;
	}

	IPNetTableInfo::IPNetTableInfo(void) :
		IpNetTable(nullptr), 
		IsRowCorrespond(false),
		Type { "", "", "Dynamic", "Static" }
	{
		while (ERROR_INSUFFICIENT_BUFFER == (Status = GetIpNetTable((PMIB_IPNETTABLE)IpNetTable,
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
		if (IpNetTable)
		{
			delete[] IpNetTable;
		}
	}

	PMIB_IPNETTABLE IPNetTableInfo::GetTable(void)
	{
		return (PMIB_IPNETTABLE)IpNetTable;
	}
	PMIB_IPNETROW IPNetTableInfo::GetNode(std::function<bool(PMIB_IPNETROW)> CompareARP) 
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

}

namespace Net /* net_manager.hpp # class Utility */
{

	MACInfo Utility::GetMACAddress(PIPAdapterInfo AdaptersInfo)
	{
		PIP_ADAPTER_INFO IpAdapterInfoNode = AdaptersInfo->GetNode(
			[](PIP_ADAPTER_INFO IpAdapterInfo) -> bool
		{
			Net::IPInfo HostIP(IpAdapterInfo->IpAddressList.IpAddress.String);
			Net::IPInfo GatewayIP(IpAdapterInfo->GatewayList.IpAddress.String);
			Net::IPInfo HostSubnetMask(IpAdapterInfo->IpAddressList.IpMask.String);

			if (HostIP.IsEmpty())
			{
				return false;
			}

			return HostIP.Mask(HostSubnetMask) == GatewayIP.Mask(HostSubnetMask)
				? true : false;
		});

		return nullptr != IpAdapterInfoNode ?
			MACInfo(IpAdapterInfoNode->Address) :
			MACInfo();
	}
	MACInfo Utility::GetGatewayMACAddress(PIPNetTableInfo NetTableInfo)
	{
		PMIB_IPNETROW IpNetRowInfo = NetTableInfo->GetNode(
			[](PMIB_IPNETROW IpNetRow) -> bool
		{
			Net::PIPAdapterInfo GatewayAddressInfo = Net::IPAdapterInfo::GetInstance();
			if (Net::Utility::GetGatewayIPAddress(GatewayAddressInfo)
				== Net::IPInfo(ntohl(IpNetRow->dwAddr)))
			{
				return true;
			}
			return false;
		});

		return nullptr != IpNetRowInfo ?
			MACInfo(IpNetRowInfo->bPhysAddr) :
			MACInfo();
	}
	IPInfo Utility::GetIPAddress(PIPAdapterInfo AdaptersInfo)
	{
		PIP_ADAPTER_INFO IpAdapterInfoNode = AdaptersInfo->GetNode(
			[](PIP_ADAPTER_INFO IpAdapterInfo) -> bool
		{
			if (nullptr != strstr(IpAdapterInfo->Description, "Wireless"))
			{
				return true;
			}
			return false;
		});
		return nullptr != IpAdapterInfoNode ?
			IPInfo(IpAdapterInfoNode->IpAddressList.IpAddress.String) :
			IPInfo();
	}
	IPInfo Utility::GetGatewayIPAddress(PIPAdapterInfo AdaptersInfo)
	{
		PIP_ADAPTER_INFO IpAdapterInfoNode = AdaptersInfo->GetNode(
			[](PIP_ADAPTER_INFO IpAdapterInfo) -> bool
		{
			if (nullptr != strstr(IpAdapterInfo->Description, "Wireless"))
			{
				return true;
			}
			return false;
		});
		return nullptr != IpAdapterInfoNode ?
			IPInfo(IpAdapterInfoNode->GatewayList.IpAddress.String) :
			IPInfo();
	}

}

namespace Net /* net_manager_ip.hpp # class IPInfo */
{

	IPInfo::IPInfo(void)
	{
		IPInfoZeroInit();
	}
	IPInfo::IPInfo(LPCBYTE byteIP)
	{
		if (nullptr != byteIP)
		{
			memcpy(this->_bAddr, byteIP, SIZ_PROTOCOL);
			ipbyte_to_str(byteIP, this->_sAddr);
			this->_iAddr = ipbyte_to_dw(byteIP);
		}
		else
		{
			throw ErrorAccessViolationException();
		}
	}
	IPInfo::IPInfo(const string& stringIP)
	{
		this->_sAddr = stringIP;
		ipstr_to_byte(stringIP.c_str(), this->_bAddr);
		this->_iAddr = ipbyte_to_dw(this->_bAddr);
	}
	IPInfo::IPInfo(const IPInfo& infoIP)
	{
		memcpy(this->_bAddr, infoIP._bAddr, SIZ_PROTOCOL);
		this->_sAddr = infoIP._sAddr;
		this->_iAddr = infoIP._iAddr;
	}
	IPInfo::IPInfo(UINT dwIP)
	{
		this->_iAddr = dwIP;
		this->ipdw_to_byte(dwIP, this->_bAddr);
		this->ipbyte_to_str(this->_bAddr, this->_sAddr);
	}

	const IPInfo& IPInfo::operator=(const LPBYTE byteIP)
	{
		memcpy(this->_bAddr, byteIP, SIZ_PROTOCOL);
		this->ipbyte_to_str(this->_bAddr, this->_sAddr);
		this->_iAddr = this->ipbyte_to_dw(this->_bAddr);

		return *this;
	}
	const IPInfo& IPInfo::operator=(const string& stringIP)
	{
		this->_sAddr = stringIP;
		this->ipstr_to_byte(stringIP.c_str(), this->_bAddr);
		this->_iAddr = this->ipbyte_to_dw(this->_bAddr);

		return *this;
	}
	const IPInfo& IPInfo::operator=(const IPInfo& infoIP)
	{
		memcpy(this->_bAddr, infoIP._bAddr, SIZ_PROTOCOL);
		this->_sAddr = infoIP._sAddr;
		this->_iAddr = infoIP._iAddr;

		return *this;
	}
	const IPInfo& IPInfo::operator=(UINT dwIP)
	{
		this->_iAddr = dwIP;
		this->ipdw_to_byte(dwIP, this->_bAddr);
		this->ipbyte_to_str(this->_bAddr, this->_sAddr);

		return *this;
	}

	__forceinline void IPInfo::IPInfoZeroInit(void)
	{
		memset(this->_bAddr, 0x00, 4);
		this->_sAddr = "0.0.0.0";
		this->_iAddr = 0;
	}
	void IPInfo::ipstr_to_byte(LPCSTR stringIP, LPBYTE byteIP)
	{
#define STRPOS(str, c) strchr(str, c) - (str) + 1

		UINT i(0);
		SSIZE_T offset(0);
		INT temp;
		do
		{
			temp = atoi(stringIP + offset);
			if (IP_ADDRESS::RESERVED0 > temp ||
				temp > IP_ADDRESS::BROADCAST)
			{
				throw ErrorIntegerOverflowException();
			}
			*(byteIP + i++) = temp;
			offset += STRPOS(stringIP + offset, '.');
		} while (i < SIZ_PROTOCOL);

#undef STRPOS
	}
	void IPInfo::ipdw_to_byte(const UINT dwIP, const LPBYTE byteIP)
	{
		for (auto i = 0; i != SIZ_PROTOCOL; ++i)
		{
			byteIP[i] = static_cast<BYTE>(
				((dwIP & (0x000000FF << (i * CHAR_BIT)) >> CHAR_BIT * (SIZ_PROTOCOL - i - 1)))
			);
		}
	}
	UINT IPInfo::ipbyte_to_dw(LPCBYTE byteIP)
	{
		UINT dwIP(0);
		for (auto i = SIZ_PROTOCOL - 1; i >= 0; --i)
		{
			dwIP |= ((byteIP[i] << (i * CHAR_BIT)) & (0xFF000000 >> (SIZ_PROTOCOL - i - 1)));
		}
		return dwIP;
	}
	void IPInfo::ipbyte_to_str(LPCBYTE byteIP, string& stringIP)
	{
		CHAR Address[4 * SIZ_PROTOCOL];
		sprintf_s(Address, "%i.%i.%i.%i", byteIP[0], byteIP[1], byteIP[2], byteIP[3]);
		stringIP = Address;
	}

	BYTE& IPInfo::operator[](SIZE_T Octet)
	{
		if (Octet > SIZ_PROTOCOL || Octet < 1)
		{
			return this->_bAddr[Octet];
		}
		throw ErrorOutOfIndexException();
	}
	bool IPInfo::operator==(const IPInfo& InfoIP)
	{
		return InfoIP._sAddr == this->_sAddr;
	}

	IP_ADDRESS IPInfo::Class(void)
	{
		if (IP_ADDRESS::RESERVED0 == this->_bAddr[0] ||
			IP_ADDRESS::RESERVED126 == this->_bAddr[0])
		{
			return static_cast<IP_ADDRESS>(this->_bAddr[0]);
		}
		else if (0xFF >= this->_bAddr[0])
		{
			return IP_ADDRESS::N;
		}
		array<IP_ADDRESS, 5> ClassUnit = {
			IP_ADDRESS::A,
			IP_ADDRESS::B,
			IP_ADDRESS::C,
			IP_ADDRESS::D,
			IP_ADDRESS::E
		};

		for (IP_ADDRESS Area : ClassUnit)
		{
			if (Area < this->_bAddr[0])
			{
				return Area;
			}
		}

		return IP_ADDRESS::N;
	}
	bool IPInfo::IsEmpty(void)
	{
		for (auto i = SIZ_PROTOCOL - 1; i != 0; --i)
		{
			if (0x00 != this->_bAddr[i])
			{
				return false;
			}
		}
		return true;
	}
	bool IPInfo::IsValidSubnetMask(IPInfo& SubnetIPAddress)
	{
		if (SubnetIPAddress._bAddr[SIZ_PROTOCOL - 1] == 0xFF)
		{
			return false;
		}

		bool BitOn = false;
		for (auto j = SIZ_PROTOCOL; j >= 0; ++j)
		{
			for (auto i = 0; i != CHAR_BIT; ++i)
			{
				if (BitOn)
				{
					if (!((0x01 << i) | this->_bAddr[j]))
					{
						return false;
					}
				}
				else
				{
					if ((0x01 << i) | this->_bAddr[j])
					{
						BitOn = true;
					}
				}
			}
		}

		return true;
	}
	IPInfo& IPInfo::Mask(IPInfo& SubnetClassless)
	{
		if (IsValidSubnetAddress(SubnetClassless))
		{
			throw ErrorInvalidSubnetMaskException();
		}

		for (auto i = 0; i != SIZ_PROTOCOL; ++i)
		{
			this->_bAddr[i] &= SubnetClassless._bAddr[i];
		}
		*this = IPInfo(this->_bAddr);

		return *this;
	}
	IPInfo& IPInfo::Mask(IP_CLASS SubnetClassfull)
	{
		auto octet(static_cast<unsigned>(SubnetClassfull));
		for (auto i = octet - 1; i != SIZ_PROTOCOL; ++i)
		{
			this->_bAddr[i] &= 0x00;
		}
		*this = IPInfo(this->_bAddr);

		return *this;
	}
}

namespace Net /* net_manager_link.hpp # class MACInfo */
{

	MACInfo::MACInfo(void)
	{
		this->MACInfoZeroInit();
	}
	MACInfo::MACInfo(const LPBYTE byteMAC)
	{
		memcpy(this->_bAddr, byteMAC, SIZ_HARDWARE);
		this->macbyte_to_str(this->_bAddr, this->_sAddr);
		this->_iAddr = macbyte_to_qw(this->_bAddr);
	}
	MACInfo::MACInfo(const string& stringMAC)
	{
		this->_sAddr = stringMAC;
		this->macstr_to_byte(stringMAC.c_str(), this->_bAddr);
		this->_iAddr = this->macbyte_to_qw(this->_bAddr);
	}
	MACInfo::MACInfo(const MACInfo& infoMAC)
	{
		memcpy(this->_bAddr, infoMAC._bAddr, SIZ_HARDWARE);
		this->_sAddr = infoMAC._sAddr;
		this->_iAddr = infoMAC._iAddr;
	}
	MACInfo::MACInfo(UINT64 qwMAC)
	{
		this->_iAddr = qwMAC;
		this->macqw_to_byte(qwMAC, this->_bAddr);
		this->macbyte_to_str(this->_bAddr, this->_sAddr);
	}

	const MACInfo& MACInfo::operator=(const LPBYTE byteMAC)
	{
		memcpy(this->_bAddr, byteMAC, SIZ_HARDWARE);
		this->macbyte_to_str(this->_bAddr, this->_sAddr);
		this->_iAddr = this->macbyte_to_qw(this->_bAddr);

		return *this;
	}
	const MACInfo& MACInfo::operator=(const string& stringMAC)
	{
		this->macstr_to_byte(stringMAC.c_str(), _bAddr);
		this->_sAddr = stringMAC;
		this->_iAddr = this->macbyte_to_qw(this->_bAddr);

		return *this;
	}
	const MACInfo& MACInfo::operator=(const MACInfo& infoMAC)
	{
		memcpy(this->_bAddr, infoMAC._bAddr, SIZ_HARDWARE);
		this->_sAddr = infoMAC._sAddr;
		this->_iAddr = infoMAC._iAddr;

		return *this;
	}
	const MACInfo& MACInfo::operator=(UINT64 qwMAC)
	{
		this->_iAddr = qwMAC;
		this->macqw_to_byte(qwMAC, this->_bAddr);
		this->macbyte_to_str(this->_bAddr, this->_sAddr);

		return *this;
	}

	void MACInfo::MACInfoZeroInit(void)
	{
		memset(this->_bAddr, 0x00, SIZ_HARDWARE);
		this->_sAddr = "00-00-00-00-00-00";
		this->_iAddr = 0;
	}
	void MACInfo::macstr_to_byte(LPCSTR stringMAC, LPBYTE byteMAC)
	{
		auto Pos(0);
		while (Pos < SIZ_HARDWARE)
		{
			byteMAC[Pos++] = (BYTE)strtoul(stringMAC, nullptr, 16);
			stringMAC = strchr(stringMAC, '-') + 1;
		}
	}
		void MACInfo::macqw_to_byte(UINT64& qwMAC, LPBYTE byteMAC)
	{
		for (auto i = 0; i != SIZ_HARDWARE; ++i)
		{
			byteMAC[i] = static_cast<BYTE>(
				((qwMAC & (0x0000000000FF << (i * CHAR_BIT)) >> CHAR_BIT * (SIZ_HARDWARE - i - 1)))
				);
		}
	}
	UINT MACInfo::macbyte_to_qw(LPCBYTE byteMAC)
	{
		UINT64 qwIP(0);
		for (auto i = SIZ_HARDWARE - 1; i >= 0; --i)
		{
			qwIP |= ((byteMAC[i] << (i * CHAR_BIT)) & (0xFF0000000000 >> (SIZ_HARDWARE - i - 1)));
		}
		return qwIP;
	}
	void MACInfo::macbyte_to_str(LPCBYTE byteMAC, string& stringMAC)
	{
		CHAR Address[4 * SIZ_HARDWARE];
		sprintf_s(Address, "%02x-%02x-%02x-%02x-%02x-%02x",
			byteMAC[0], byteMAC[1], byteMAC[2], byteMAC[3], byteMAC[4], byteMAC[5]);
		this->_sAddr = Address;
	}

	BYTE& MACInfo::operator[](SIZE_T Octet)
	{
		if (Octet >= SIZ_HARDWARE || Octet < 0)
		{
			return _bAddr[Octet];
		}
		throw ErrorOutOfIndexException();
	}
	bool MACInfo::operator==(const MACInfo& InfoMAC)
	{
		return InfoMAC._sAddr == this->_sAddr;
	}

};
