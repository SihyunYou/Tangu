//
// net_manager_link.hpp
// Copyright © jynis2937, all rights reserved,
// This program is under the GNU Lesser General Public License.
//

#pragma once
#ifndef _NETMANAGER_LINK
#define _NETMANAGER_LINK

#include <tangu\tangu_build.hpp>

NAMESPACE_BEGIN(Net)

/*
* @brief    net_manager section that supports physical address.
*/
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
	/*
	* @brief    Constructor
	*           Zero initialized address.
	*/
	MACInfo::MACInfo(void);
	/*
	* @brief    Constructor
	*           Initialized with byte typed address.
	* @param    Byte (unsigned char) typed physical address.
	*/
	MACInfo::MACInfo(const LPBYTE);
	/*
	* @brief    Constructor
	*           Initialized with string typed address.
	* @param    String (char* or STL string) typed physical address.
	*/
	MACInfo::MACInfo(const string&);
	/*
	* @brief    Constructor
	*           Initialized with uint typed address.
	* @param    Integer (unsigned long long) typed physical address. Physical address
	*           uses low-48bit. High-16bit is ignored.
	*/
	MACInfo::MACInfo(UINT64);
	/*
	* @brief    Constructor
	*           Initialized with other MACInfo reference.
	* @param    MACInfo reference instance.
	*/
	MACInfo::MACInfo(const MACInfo&);

	/*
	* @param    Byte (unsigned char) typed physical address.
	* @return   this
	*/
	const MACInfo& MACInfo::operator=(const LPBYTE);
	/*
	* @param    String (char* or STL string) typed physical address.
	* @return   this
	*/
	const MACInfo& MACInfo::operator=(const string&);
	/*
	* @param    Integer (unsigned long long) typed physical address.
	* @return   this
	*/
	const MACInfo& MACInfo::operator=(UINT64);
	/*
	* @param    MACInfo reference instance.
	* @return   this
	*/
	const MACInfo& MACInfo::operator=(const MACInfo&);
	
private:
	/*
	* @brief    Initialize addresses with zero.
	*/
	__forceinline void MACInfo::MACInfoZeroInit(void);

	/*
	* @brief    Convert physical address string to physical address byte array.
	* @param    Physical address string.
	* @param    Physical address byte array.
	*/
	void MACInfo::macstr_to_byte(LPCSTR, LPBYTE);
	/*
	* @brief    Convert physical address integer to physical address byte array.
	* @param    Physical address integer.
	* @param    Physical address byte array.
	*/
	void MACInfo::macqw_to_byte(UINT64&, LPBYTE);
	/*
	* @brief    Convert physical address byte array to physical address integer.
	* @param    Physical address byte array.
	* @return   Physical address integer.
	*/
	UINT MACInfo::macbyte_to_qw(LPCBYTE);
	/*
	* @brief    Convert physical address byte array to physical address string.
	* @param    Physical address byte array.
	* @param    Physical address string reference.
	*/
	void MACInfo::macbyte_to_str(LPCBYTE, string&);

public:
	/*
	* @brief    Type cast operator overloading.
	* @return   Physical address byte array.
	*/
	operator MACInfo::LPCBYTE() const
	{
		return (LPCBYTE) this->_bAddr;
	}
	/*
	* @brief    Type cast operator overloading.
	* @return   Physical address string.
	*/
	operator MACInfo::LPCSTR() const
	{
		return (LPCSTR) this->_sAddr.c_str();
	}
	/*
	* @brief    Type cast operator overloading.
	* @return   Physical address integer.
	*/
	operator MACInfo::UINT64() const
	{
		return this->_iAddr;
	}

public:
	/*
	* @brief    Subscript operator overloading.
	* @param     An index of array.
	* @return   Physical address byte array index reference.
	*/
	BYTE& MACInfo::operator[](SIZE_T);
	/*
	* @brief    Relational operator overloading.
	* @param     The MACInfo instance reference.
	* @return   MACInfo instance being equal, true. Or not, false.
	*/
	bool MACInfo::operator==(const MACInfo&);
} *PMACInfo;

NAMESPACE_END

#endif /* _NETMANAGER_LINK */