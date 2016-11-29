//
// net_manager_ip.hpp
// Copyright © jynis2937, all rights reserved,
// This program is under the GNU Lesser General Public License.
//

#pragma once
#ifndef _NETMANAGE_IP
#define _NETMANAGE_IP

#include <tangu\tangu_build.hpp>
#include <net_manager\net_manager_exception.hpp>

NAMESPACE_BEGIN(Net)

enum IP_ADDRESS : unsigned
{
	RESERVED0 = 0,
	A = 1,
	RESERVED126 = 127,
	B = 128,
	C = 192,
	D = 224,
	E = 240,
	BROADCAST = 255,
	N // Not a valid ip address
};
enum class IP_CLASS : unsigned
{
	A = 1,
	B,
	C,
	D,
	E,
	N // Not a valid ip class
};

typedef class TANGU_API IPInfo
{
private:
	//
	// Address expressed byte, string or uint types
	//
	BYTE _bAddr[SIZ_PROTOCOL];
	string _sAddr;
	UINT _iAddr;

public:
	IPInfo::IPInfo(void);
	IPInfo::IPInfo(const LPBYTE);
	IPInfo::IPInfo(const string&);
	IPInfo::IPInfo(const IPInfo&);
	IPInfo::IPInfo(UINT);
	const IPInfo& IPInfo::operator=(const LPBYTE);
	const IPInfo& IPInfo::operator=(const string&);
	const IPInfo& IPInfo::operator=(const IPInfo&);
	const IPInfo& IPInfo::operator=(UINT);
	
private:
	__forceinline void IPInfo::IPInfoZeroInit(void);

	void IPInfo::ipstr_to_byte(LPCSTR, LPBYTE);
	void IPInfo::ipdw_to_byte(UINT, LPBYTE);
	UINT IPInfo::ipbyte_to_dw(LPCBYTE);
	void IPInfo::ipbyte_to_str(LPCBYTE, string&);
	
public:
	operator IPInfo::LPCBYTE() const
	{
		return (LPCBYTE) this->_bAddr;
	}
	operator IPInfo::LPCSTR() const
	{
		return (LPCSTR) this->_sAddr.c_str();
	}
	operator IPInfo::UINT() const
	{
		return this->_iAddr;
	}

public:
	BYTE IPInfo::operator[](SIZE_T);
	bool IPInfo::operator==(const IPInfo&);

	IP_ADDRESS IPInfo::Class(void);
	bool IPInfo::IsEmpty(void);
	bool IPInfo::IsValidSubnetAddress(IPInfo&);
	IPInfo& IPInfo::Mask(IPInfo&);
	IPInfo& IPInfo::Mask(IP_CLASS);
} *PIPInfo;

NAMESPACE_END

#endif /* _NETMANAGE_IP */