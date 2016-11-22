#pragma once
#ifndef _NETMANAGER_LINK
#define _NETMANAGER_LINK

#include <tangu\tangu_build.hpp>

NAMESPACE_BEGIN(Net)

typedef class TANGU_API MACInfo
{
private:
	BYTE _bMAC[SIZ_HARDWARE];
	string _sMAC;

public:
	MACInfo::MACInfo(void);
	MACInfo::MACInfo(const LPBYTE);
	MACInfo::MACInfo(const string&);
	MACInfo::MACInfo(const MACInfo&);
	const MACInfo& MACInfo::operator=(const LPBYTE);
	const MACInfo& MACInfo::operator=(const string&);
	const MACInfo& MACInfo::operator=(const MACInfo&);

private:
	void MACInfo::macstr_to_hex(LPCSTR, LPBYTE);

public:
	const LPBYTE MACInfo::operator*(void);
	BYTE MACInfo::operator[](SIZE_T);
	bool MACInfo::operator==(const MACInfo&);
	string MACInfo::operator()(void);
} *PMACInfo;

NAMESPACE_END

#endif /* _NETMANAGER_LINK */