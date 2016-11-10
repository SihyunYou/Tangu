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

	class Utility
	{
	public:
		static BYTE BufferForAddress[20];

	public:
		static MACInfo Utility::GetMACAddress(Net::IPAdapterInfo*);
		static IPInfo Utility::GetIPAddress(Net::IPAdapterInfo*);
		static IPInfo Utility::GetGatewayIPAddress(Net::IPAdapterInfo*);

		static bool Utility::RecoveryPeriod(UINT);
	};
}

#endif /* _NETMANAGE_H */