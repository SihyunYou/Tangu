#pragma once
#ifndef _NETMANAGE_H
#define _NETMANAGE_H

#include "net_manager_ip.hpp" 
#include "net_manager_link.hpp"

namespace Net
{
	typedef struct DATALINK_LAYER
	{
		MACInfo		MDst;
		MACInfo		MSrc;
	} L2, *PL2;
	typedef struct NETWORK_LAYER
	{
		MACInfo		MDst;
		MACInfo		MSrc;
		IPInfo			ISrc;
		IPInfo			IDst;
	}L3, *PL3;
	typedef struct TRANSPORT_LAYER
	{
		MACInfo		MDst;
		MACInfo		MSrc;
		IPInfo			ISrc;
		IPInfo			IDst;
	}L4, *PL4;


	bool _cdecl CompareSubnetMask(PIP_ADAPTER_INFO);
	bool _cdecl CompareDescription(PIP_ADAPTER_INFO);
	bool _cdecl CompareARP(PMIB_IPNETROW);
	typedef class IPAdapterInfo
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
		PIP_ADAPTER_INFO GetNode(bool(_cdecl *FuncCompare)(PIP_ADAPTER_INFO));
	} *PIPAdapterInfo;
	typedef class IPNetTableInfo
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
		static IPNetTableInfo* IPNetTableInfo::GetInstance(void);

	public:
		IPNetTableInfo::IPNetTableInfo(void);
		IPNetTableInfo::~IPNetTableInfo(void);

	public:
		PMIB_IPNETROW IPNetTableInfo::operator()(void);
		PMIB_IPNETROW IPNetTableInfo::GetNode(bool(_cdecl *FuncCompare)(PMIB_IPNETROW));
	}*PIPNetTableInfo;
	
	class Utility
	{
	public:
		static BYTE BufferForAddress[20];

	public:
		static MACInfo Utility::GetMACAddress(Net::PIPAdapterInfo);
		static MACInfo Utility::GetGatewayMACAddress(Net::PIPNetTableInfo);
		static IPInfo Utility::GetIPAddress(Net::PIPAdapterInfo);
		static IPInfo Utility::GetGatewayIPAddress(Net::PIPAdapterInfo);
		
		static bool Utility::RecoveryPeriod(UINT);
	};
}

#endif /* _NETMANAGE_H */