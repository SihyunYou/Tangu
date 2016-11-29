//
// net_manager.hpp
// Copyright © jynis2937, all rights reserved,
// This program is under the GNU Lesser General Public License.
//

#pragma once
#ifndef _NETMANAGE_H
#define _NETMANAGE_H

#include <net_manager\net_manager_exception.hpp>
#include <net_manager\net_manager_ip.hpp>
#include <net_manager\net_manager_link.hpp>

NAMESPACE_BEGIN(Net)

/*
* @brief    Layer identifiers for source, destination.
* @todo     The New PortInfo class should be adopted.
* @deprecated    The unsigned integer typed port information.
*/
typedef struct DATALINK_IDENTIFIER
{
	MACInfo MDst;
	MACInfo MSrc;
} L2ID, *PL2ID;
typedef struct NETWORK_IDENTIFIER
{
	MACInfo MDst;
	MACInfo MSrc;
	IPInfo ISrc;
	IPInfo IDst;
}L3ID, *PL3ID;
typedef struct TRANSPORT_IDENTIFIER
{
	MACInfo MDst;
	MACInfo MSrc;
	IPInfo ISrc;
	IPInfo IDst;
	UINT PSrc;
	UINT PDst;
}L4ID, *PL4ID;


/*
* @brief    A singleton wrapper for struct _IP_ADAPTER_INFO
*/
typedef class TANGU_API IPAdapterInfo
{
private:
	DWORD SizeOfBuf;
	DWORD Status;
	PIP_ADAPTER_INFO AdapterInfo;
	bool IsSuccessed;

private:
	static IPAdapterInfo* SingleIPAdapterInfo;

public:
	/*
	* @return   A static IPAdapterInfo instance
	*/
	static IPAdapterInfo* IPAdapterInfo::GetInstance(void);

public:
	/*
	* @brief    Constructor
	*           Allocate an IP_ADAPTER_INFO typed linked list and get adapters' information.
	* @see      ::GetAdaptersInfo()
	*/
	IPAdapterInfo::IPAdapterInfo(void);
	/*
	* @brief    Destructor
	*           Free the linked list.
	*/
	IPAdapterInfo::~IPAdapterInfo(void);

public:
	/*
	* @brief    Get the first list node.
	* @return   An address of the first IP_ADAPTER_INFO typed list node.
	*/
	PIP_ADAPTER_INFO operator()(void);
	/*
	* @brief    Get the next list node until param lambda function returns true.
	* @param    ([](PIP_ADAPTER_INFO) -> bool) typed lambda function. 
	* @return   An address of the specified IP_ADAPTER_INFO typed list node.
	*/
	PIP_ADAPTER_INFO GetNode(std::function<bool(PIP_ADAPTER_INFO)>);
} *PIPAdapterInfo;


/*
* @brief    A singleton wrapper for struct _MIB_IPNETTABLE
*/
typedef class TANGU_API IPNetTableInfo
{
private:
	DWORD Status;
	PCHAR IpNetTable;
	DWORD SizeOfPointer;
	PMIB_IPNETROW Row;
	PMIB_IPNETTABLE Table;
	INT Index;
	bool IsRowCorrespond;

private:
	static IPNetTableInfo* SingleIPNetTableInfo;

public:
	array<string, 4> Type;

public:
	/*
	* @return   A static IPAdapterInfo instance
	*/
	static IPNetTableInfo* IPNetTableInfo::GetInstance(void);

public:
	/*
	* @brief    Constructor
	*           Allocate an MIB_IPNETTABLE array and get IP net table.
	* @see      ::GetIpNetTable()
	*/
	IPNetTableInfo::IPNetTableInfo(void);
	/*
	* @brief    Destructor
	*           Free the array.
	*/		
	IPNetTableInfo::~IPNetTableInfo(void);

public:
	/*
	* @brief    Get an array of IP net table.
	* @return   An address of MIB_IPNETTABLE typed array consisting of MIB_IPNETROW typed elements.
	*/
	PMIB_IPNETTABLE IPNetTableInfo::GetTable(void);
	/*
	* @brief    Get the specified element of IP net table.
	* @param	    ([](PMIB_IPNETROW) -> bool) typed lambda function. 
	* @return   An address of MIB_IPNETROW typed array.
	*/
	PMIB_IPNETROW IPNetTableInfo::GetNode(std::function<bool(PMIB_IPNETROW)>);
}*PIPNetTableInfo;


/*
* @brief    The utility APIs for a net identifier on each layer. 
*/
class TANGU_API Utility
{
public:
	/*
	* @brief    Get the specified physical address of this computer. 
	* @param	    User-defined IP adapters' information configuration.
	* @return   MAC address of the specified adapter.
	*/
	MACInfo static Utility::GetMACAddress(PIPAdapterInfo);
	/*
	* @brief    Get the specified physical address of this computer. 
	* @param	    User-defined net table information configuration.
	* @return   A gateway MAC address of the specified net table.
	*/
	MACInfo static Utility::GetGatewayMACAddress(PIPNetTableInfo);
	/*
	* @brief    Get the specified IPv4 address of this computer. 
	* @param	    User-defined IP adapters' information configuration.
	* @return   IPv4 address of the specified adapter.
	*/
	IPInfo static Utility::GetIPAddress(PIPAdapterInfo);
	/*
	* @brief    Get the specified IPv4 address of this computer. 
	* @param	    User-defined IP adapters' information configuration.
	* @return   IPv4 address of the specified adapter.
	*/
	IPInfo static Utility::GetGatewayIPAddress(PIPAdapterInfo);
};

NAMESPACE_END

typedef Net::Utility NetUtil;

#endif /* _NETMANAGE_H */