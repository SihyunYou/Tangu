#pragma once
#ifndef _NETMANAGER_LINK
#define _NETMANAGER_LINK

#include "tangu_build.hpp"

namespace Net
{
	typedef class MACInfo
	{
	private:
		BYTE		_bMAC[6];
		string		_sMAC;

	public:
		void MACInfo::MACStringToInt(const CHAR* MACString, BYTE* Buf);

	public:
		MACInfo::MACInfo(void);
		MACInfo::MACInfo(const BYTE* MACByte);
		MACInfo::MACInfo(const string& MACString);
		MACInfo(const MACInfo& MAC);
		const MACInfo& MACInfo::operator=(const BYTE* MACByte);
		const MACInfo& MACInfo::operator=(const string& MACString);
		const MACInfo& MACInfo::operator=(const MACInfo& MAC);

	public:
		bool MACInfo::operator==(const MACInfo& MAC);
		BYTE* MACInfo::operator*(void);
		string MACInfo::uc_bstr(void);
		BYTE MACInfo::operator[](size_t Octet);
	} *PMACInfo;
}
#endif /* _NETMANAGER_LINK */