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

/*
* @brief    A range modifier judged from the first octet of IPv4 address.
*/
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


/*
* @brief    net_manager section that supports IPv4 address. 
*/
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
	/*
	* @brief    Constructor
	*           Zero initialized address.
	*/
	IPInfo::IPInfo(void);
	/*
	* @brief    Constructor
	*           Initialized with byte typed address.
	* @param    Byte (unsigned char) typed IPv4 address.
	*/
	IPInfo::IPInfo(LPCBYTE);
	/*
	* @brief    Constructor
	*           Initialized with string typed address.
	* @param    String (char* or STL string) typed IPv4 address.
	*/
	IPInfo::IPInfo(const string&);
	/*
	* @brief    Constructor
	*           Initialized with uint typed address.
	* @param    Integer (unsigned int) typed IPv4 address.
	*/
	IPInfo::IPInfo(UINT);
	/*
	* @brief    Constructor
	*           Initialized with other IPInfo reference.
	* @param    IPInfo reference instance.
	*/
	IPInfo::IPInfo(const IPInfo&);
	
	/*       
	* @param    Byte (unsigned char) typed IPv4 address.
	* @return   this
	*/
	const IPInfo& IPInfo::operator=(const LPBYTE);
	/*
	* @param    String (char* or STL string) typed IPv4 address.
	* @return   this
	*/
	const IPInfo& IPInfo::operator=(const string&);
	/*
	* @param    Integer (unsigned int) typed IPv4 address.
	* @return   this
	*/
	const IPInfo& IPInfo::operator=(UINT);
	/*
	* @param    IPInfo reference instance.
	* @return   this
	*/
	const IPInfo& IPInfo::operator=(const IPInfo&);

private:
	/*
	* @brief    Initialize addresses with zero.
	*/
	__forceinline void IPInfo::IPInfoZeroInit(void);

	/*
	* @brief    Convert IPv4 address string to IPv4 address byte array. 
	* @param    IPv4 address string.
	* @param    IPv4 address byte array.
	*/
	void IPInfo::ipstr_to_byte(LPCSTR, LPBYTE);
	/*
	* @brief    Convert IPv4 address integer to IPv4 address byte array.
	* @param    IPv4 address integer.
	* @param    IPv4 address byte array.
	*/
	void IPInfo::ipdw_to_byte(UINT, LPBYTE);
	/*
	* @brief    Convert IPv4 address byte array to IPv4 address integer.
	* @param    IPv4 address byte array.
	* @return   IPv4 address integer.
	*/
	UINT IPInfo::ipbyte_to_dw(LPCBYTE);
	/*
	* @brief    Convert IPv4 address byte array to IPv4 address string.
	* @param    IPv4 address byte array.
	* @param    IPv4 address string reference.
	*/
	void IPInfo::ipbyte_to_str(LPCBYTE, string&);
	
public:
	/*
	* @return   IPv4 address byte array.
	*/
	operator IPInfo::LPCBYTE() const
	{
		return (LPCBYTE) this->_bAddr;
	}
	/*
	* @return   IPv4 address string.
	*/
	operator IPInfo::LPCSTR() const
	{
		return (LPCSTR) this->_sAddr.c_str();
	}
	/*
	* @return   IPv4 address integer.
	*/
	operator IPInfo::UINT() const
	{
		return this->_iAddr;
	}

public:
	/*
	* @param     An index of array.
	* @return   IPv4 address byte array index reference.
	*/
	BYTE& IPInfo::operator[](SIZE_T);
	/*
	* @param     The IPInfo instance reference.
	* @return   IPInfo instance being equal, true. Or not, false.
	*/
	bool IPInfo::operator==(const IPInfo&);

public:
	/*
	* @brief    IPv4 class for classfull network.
	*/
	enum class IP_CLASS : short
	{
		A, B, C, D, E
	};

	/*
	* @brief    Get IPv4 class checking the first octet.
	* @return   IPv4 class.
	*/
	IP_ADDRESS IPInfo::Class(void);
	/*
	* @brief    Check info class' address is equal to zero or null stream. 
	* @return   Zero being equal, true. Or not, false.
	*/
	bool IPInfo::IsEmpty(void);
	/*
	* @brief    Subnet mask should be divied into network area and host area.
	*           Check bit array of subnet mask is sequential stream.  
	* @param     The IPInfo instance reference.
	* @return   IPInfo instance being equal, true. Or not, false.
	*/
	bool IPInfo::IsValidSubnetMask(IPInfo&);
	/*
	* @brief    Operate masking of IPv4 address.
	* @param     The IPInfo instance reference. Unless It must be for subnet mask,
	*           it throws an exception.
	* @return   this
	*/
	IPInfo& IPInfo::Mask(IPInfo&);
	/*
	* @brief    Operate masking of IPv4 address.
	* @param     The IPv4 class, scoped enumerated.
	* @return   this
	*/
	IPInfo& IPInfo::Mask(IP_CLASS);
} *PIPInfo;

NAMESPACE_END

#endif /* _NETMANAGE_IP */