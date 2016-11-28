#pragma once
#ifndef _NETMANAGER_LINK
#define _NETMANAGER_LINK

#include <tangu\tangu_build.hpp>

NAMESPACE_BEGIN(Net)

typedef class TANGU_API MACInfo
{
private:
	//
	// Physical address expressed byte, string or uint64 types
	//
	BYTE _bAddr[SIZ_HARDWARE];
	string _sAddr;
	UINT64 _iAddr;

public:
	MACInfo::MACInfo(void);
	MACInfo::MACInfo(const LPBYTE);
	MACInfo::MACInfo(const string&);
	MACInfo::MACInfo(const MACInfo&);
	MACInfo::MACInfo(UINT64);
	const MACInfo& MACInfo::operator=(const LPBYTE);
	const MACInfo& MACInfo::operator=(const string&);
	const MACInfo& MACInfo::operator=(const MACInfo&);
	const MACInfo& MACInfo::operator=(UINT64);

private:
	__forceinline void MACInfo::MACInfoZeroInit(void);
	void MACInfo::macstr_to_byte(LPCSTR, LPBYTE);
	void MACInfo::macqw_to_byte(UINT64&, LPBYTE);
	UINT MACInfo::macbyte_to_qw(LPCBYTE);
	void MACInfo::macbyte_to_str(LPCBYTE, string&);

public:
	operator MACInfo::LPCBYTE() const
	{
		return (LPCBYTE) this->_bAddr;
	}
	operator MACInfo::LPCSTR() const
	{
		return (LPCSTR) this->_sAddr.c_str();
	}
	operator MACInfo::UINT64() const
	{
		return this->_iAddr;
	}
	

public:
	BYTE MACInfo::operator[](SIZE_T);
	bool MACInfo::operator==(const MACInfo&);
} *PMACInfo;

NAMESPACE_END

#endif /* _NETMANAGER_LINK */