#pragma once
#ifndef _NETMANAGE_IP
#define _NETMANAGE_IP

#include <tangu\tangu_build.hpp>

NAMESPACE_BEGIN(Net)

typedef class TANGU_API IPInfo
{
private:
	BYTE _bIP[SIZ_PROTOCOL];
	string _sIP;

public:
	IPInfo::IPInfo(void);
	IPInfo::IPInfo(const LPBYTE);
	IPInfo::IPInfo(const string&);
	IPInfo::IPInfo(const IPInfo&);
	IPInfo::IPInfo(const DWORD);
	const IPInfo& IPInfo::operator=(const LPBYTE);
	const IPInfo& IPInfo::operator=(const string&);
	const IPInfo& IPInfo::operator=(const IPInfo&);
	const IPInfo& IPInfo::operator=(const DWORD);

private:
	void IPInfo::ipstr_to_hex(LPCSTR, LPBYTE);

public:
	const LPBYTE IPInfo::operator*(void);
	BYTE IPInfo::operator[](SIZE_T);
	bool IPInfo::operator==(const IPInfo&);
	string IPInfo::operator()(void);

	bool IPInfo::IsEmpty(void);
	IPInfo& IPInfo::Mask(IPInfo&);
} *PIPInfo;

typedef IPInfo SubnetIPInfo;

NAMESPACE_END

#endif /* _NETMANAGE_IP */