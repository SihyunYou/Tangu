//
// tangu_blocker.hpp
// Copyright © jynis2937, all rights reserved,
// This program is under the GNU Lesser General Public License.
//

#pragma once
#ifndef _TANGU_BLOCK
#define _TANGU_BLOCK

#include <net_manager\net_manager.hpp>
#include <packet_field\packet_field.hpp>
#include <boost\algorithm\string.hpp>
#include <tangu\tangu_analyzer.hpp>
#include <tangu\tangu_interface.hpp>
#include <tangu\tangu_divert.hpp>

namespace Algorithm = boost::algorithm;
using namespace Packet;

/*
* @brief Transmission control protocol hijack 
*/
typedef class TANGU_API HIJACK
{
private:
	LPCSTR static BlockData;

	shared_ptr<PACKET_INFO> HijackPtr;
	PPACKET_INFO PacketInfoPtr;
	PACKET_INFO& PacketInfoRef;

public:
	/*
	* @brief    Constructor
	*           Initialize tcp packets to reset, to redirect to block page, to finish 
	*           a session.
	* @param    Tangu-defined detailed packet information instance reference
	*/
	HIJACK::HIJACK(PACKET_INFO&);

public:
	/*
	* @brief     Send a TCP RST to the server; immediately closing the connection
	*           at the server's end.
	*/
	void HIJACK::Reset(void);
	/*
	* @brief    Send the blockpage to the browser.
	*/
	void HIJACK::Block(void);
	/*
	* @brief    Send a TCP FIN to the browser; closing the connection at the 
	*           browser's end.
	*/
	void HIJACK::Finish(void);
} *PHIJACK;


typedef class TANGU_API _BADURL_LIST
{
	typedef forward_list<string> StringForwardList;
private:
	WINDIVERT_DEVICE WinDivertDev;
	StringForwardList BlackList;
	StringForwardList::iterator BlackListIter;
	bool IsValidHost;

public:
	/*
	* @brief    Constructor
	*           Initializes handle.
	* @param    handle for windivert API
	*/
	_BADURL_LIST::_BADURL_LIST(HANDLE);
	/*
	* @brief    Destructor
	*/
	_BADURL_LIST::~_BADURL_LIST(void);

private:
	/*
	* @brief    Match whether the value of a key is equal to the first @param.
	* @param    HTTP host header section value (hostname[:port])
	* @return   Being matched, true. Or not, false.
	*/
	auto _BADURL_LIST::Match(LPCSTR) -> decltype(_BADURL_LIST::IsValidHost);

public:
	/*
	* @brief    Block the indexes of black list by hijacking TCP sessions.
	* @param    Tangu-defined detailed packet information instance reference
	*/
	void _BADURL_LIST::Hijack(PACKET_INFO&);

	/*
	* @brief    Manage lists. Register a forward list. (reinitialization)
	* @param    Bad host name forward list
	*/
	void _BADURL_LIST::Set(StringForwardList&);
	/*
	* @brief    Insert a new value after the end of list.
	* @param    A bad host name string
	*/
	void _BADURL_LIST::Push(const string&);
}BADURL_LIST, *PBADURL_LIST;

#endif /* _TANGU_BLOCK */