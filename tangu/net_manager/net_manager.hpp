#pragma once
#ifndef _NETMANAGE_H
#define _NETMANAGE_H

#include <net_manager\net_manager_exception.hpp>
#include <net_manager\net_manager_ip.hpp>
#include <net_manager\net_manager_link.hpp>

NAMESPACE_BEGIN(Net)

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
	static IPAdapterInfo* IPAdapterInfo::GetInstance(void);

public:
	IPAdapterInfo::IPAdapterInfo(void);
	IPAdapterInfo::~IPAdapterInfo(void);

public:
	PIP_ADAPTER_INFO operator()(void);
	PIP_ADAPTER_INFO GetNode(std::function<bool(PIP_ADAPTER_INFO)>);
} *PIPAdapterInfo;

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
	static IPNetTableInfo* IPNetTableInfo::GetInstance(void);

public:
	IPNetTableInfo::IPNetTableInfo(void);
	IPNetTableInfo::~IPNetTableInfo(void);

public:
	PMIB_IPNETTABLE IPNetTableInfo::GetTable(void);
	PMIB_IPNETROW IPNetTableInfo::GetNode(std::function<bool(PMIB_IPNETROW)>);
}*PIPNetTableInfo;

class TANGU_API Utility
{
public:
	static MACInfo Utility::GetMACAddress(PIPAdapterInfo);
	static MACInfo Utility::GetGatewayMACAddress(PIPNetTableInfo);
	static IPInfo Utility::GetIPAddress(PIPAdapterInfo);
	static IPInfo Utility::GetGatewayIPAddress(PIPAdapterInfo);
};

NAMESPACE_END

typedef Net::Utility NetUtil;

#endif /* _NETMANAGE_H */