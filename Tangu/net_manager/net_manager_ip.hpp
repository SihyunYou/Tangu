#pragma once
#ifndef _NETMANAGE_IP
#define _NETMANAGE_IP

#include "tangu_build.hpp"

namespace Net
{
	typedef class IPInfo
	{
	private:
		BYTE		_bIP[4];
		string		_sIP;

	private:
		void IPInfo::IPStringToHex(const CHAR* IPString, BYTE* Buf);
		
	public:
		IPInfo::IPInfo();
		IPInfo::IPInfo(const BYTE* IPByte);
		IPInfo::IPInfo(const string& IPString);
		IPInfo::IPInfo(const IPInfo& IP);
		IPInfo::IPInfo(const DWORD dwIP);
		const IPInfo& IPInfo::operator=(const BYTE* IPByte);
		const IPInfo& IPInfo::operator=(const string& IPString);
		const IPInfo& IPInfo::operator=(const IPInfo& IP);
		const IPInfo& IPInfo::operator=(const DWORD dwIP);

	public:
		BYTE* IPInfo::operator*(void);
		BYTE IPInfo::operator[](SIZE_T Octet);
		bool IPInfo::operator==(IPInfo&);

		string IPInfo::uc_bstr(void);
		IPInfo& IPInfo::Mask(IPInfo&);
	} *PIPInfo;
	typedef IPInfo SubnetIPInfo;
}

#endif /* _NETMANAGE_IP */