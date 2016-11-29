//
// tangu_build.hpp
// Copyright © jynis2937, all rights reserved,
// This program is under the GNU Lesser General Public License.
//

#pragma once
#ifndef _TANGU
#define _TANGU

//
// 'identifier' : class 'type' needs to have dll-interface to be used by clients of class 'type2'
//
#pragma warning (disable : 4251)

#ifdef TANGU_EXPORTS
#define TANGU_API __declspec(dllexport)
#else
#define TANGU_API __declspec(dllimport)
#endif

/************************************************* C++ Library *************************************************/
#include <Algorithm>
using _STD pair;
using _STD make_pair;

using _STD exception_ptr;

//
// Standard template libraries for tangu packet structures.
//
#include <Iterator>
#include <Array>
#include <Vector>
#include <Forward_List>
#include <Unordered_Map>
using _STD array;
using _STD vector;
using _STD forward_list;
using _STD unordered_map;

//
// Smart pointers.
//
#include <Memory>
using _STD shared_ptr;
using _STD unique_ptr;

//
// Lambda functions.
//
#include <Functional>
using _STD function;

#include <String>
using _STD string;
using _STD wstring;
using _STD to_string;
using _STD to_wstring;

//
// File stream header. TANGU_BLOCKER needs a list for malware site.
//
#include <FStream>
#include <SStream>
using _STD ios;
using _STD ifstream;
using _STD ofstream;
using _STD istringstream;

//
// Time library
//
// chrono is the name of a header, but also of a sub - namespace : All the 
// elements in this header(except for the common_type specializations) are not 
// defined directly under the std namespace (like most of the standard library) 
// but under the std::chrono namespace.
//
// The elements in this header deal with time. This is done mainly by means of 
// three concepts :
// •Durations : They measure time spans. In this library, they are represented with 
// objects of the duration class template, that couples a count representation and 
// a period precision(e.g., ten milliseconds has ten as count representation and 
// milliseconds as period precision).
// •Time points : A reference to a specific point in time. In this library, objects of 
// the time_point class template express this by using a duration relative to an 
// epoch (which is a fixed point in time common to all time_point objects using 
// the same clock).
// •Clocks : A framework that relates a time point to real physical time.
// The library provides at least three clocks that provide means to express the 
// current time as a time_point : system_clock, steady_clock and 
// high_resolution_clock.
//
#include <CTime>
#include <Chrono>
using namespace _STD chrono;

//
// Random number generation facilities.
//
// This library allows to produce random numbers using combinations of 
// generators and distributions:
// •Generators : Objects that generate uniformly distributed numbers.
// •Distributions : Objects that transform sequences of numbers generated
// by a generator into sequences of numbers that follow a specific random 
// variable distribution, such as uniform, Normal or Binomial.
//
#include <Random>
using _STD random_device;
using _STD mt19937;
using _STD uniform_int_distribution;

/******************************************************************************************************************/

/**************************************** Windows System Library *******************************************/

//
// The windows.h header file is required for applications that use Windows API 
// (for both Unicode and ANSI versions of the API). Tangu's net_manager and packet_field 
// use data types typedefed by Windows Headers, API getting system resources.
//

// Macro notices that you'll build an application without MFC sources.
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>

typedef const unsigned char* LPCBYTE;

//
// Prevent redefinition of WinSock2.h header, Windows.h header.
//
#define _WINSOCKAPI_ 
#include <WinSock2.h>
#pragma comment(lib, "Ws2_32.lib")

//
// The Iphlpapi.h header file is required for applications that use the IP Helper functions. 
// When the Winsock2.h header file is required, the #include line for this file should be 
// placed before the #include line for the Iphlpapi.h header file. 
//
#include <IpHlpAPI.h>
#pragma comment(lib, "IpHlpAPI.lib")

/******************************************************************************************************************/

/************************************ Pcap (Packet Capture) Library ****************************************/

//
// pcap (pcaet capture) consists of the API for capturing network traffic. Windows uses a port of
// libpcap known as WinPcap. Tangu uses WinPcap to capture packets travelling over a network
// and, to transmit packets on a network "at the link layer", as well as to get a list of network
// interfaces. (may be not listed)
// 

// 
// If your program uses the remote capture capabilities of WinPcap, add HAVE_REMOTE among 
// the preprocessor definitions. Do not include remote-ext.h directly in your source files.
//
#define HAVE_REMOTE

#include <pcap\pcap.h>

//
// VC include
//
#include <wpcapi.h>
#pragma comment(lib, "wpcap.lib")

/******************************************************************************************************************/

/******************************************* WinDivert Library ************************************************/

//
// Windows Packet Divert (WinDivert) is a user-mode packet capture-and-divert package to 
// capture / sniff / filter / drop / (re)inject / modify network packets.
// WinDivert can be used to implement user-mode packet filters, packet sniffers, firewalls, NAT, 
// VPNs, tunneling applications, etc. 
//
#pragma managed(push, off)
#include <windivert\windivert.h>
#pragma managed(pop)

/******************************************************************************************************************/

#define In
#define Out

//
// Address length on link layer (physical, internet)
//

#define SIZ_HARDWARE 6
#define SIZ_PROTOCOL 4
//
// Casting preprocessors 
// You can declare 8-, 16, 32-, or 64-bit integer variables by ising __int[n] type specifier,
// sized integer types supported by Microsoft C/C++ features.
//
#define SCast(data_type_size)	static_cast<signed __int##data_type_size> 
#define UCast(data_type_size)	static_cast<unsigned __int##data_type_size> 
#define bitsizeof(data_type)		sizeof(data_type) * CHAR_BIT

//
// The top header uses flexible syntaxs that specifie where the statements begin and end,
// for instance, switch, a control statement; namespace, a logical management area.
//
#define esac break;

#define NAMESPACE_BEGIN(var) namespace var##{
#define NAMESPACE_END }

//
// Thread utils.
//
__forceinline bool sleep_for(DWORD milliseconds, unsigned time = 1)
{
	Sleep(milliseconds * time);
	return true;
}

#pragma pack(push)
#pragma warning(disable : 4005)
#define sleep_for(x) ::sleep_for(x)
#define sleep_for(x, t) ::sleep_for(x, t) 

#pragma pack(pop)
#endif /* _TANGU */