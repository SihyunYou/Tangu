#pragma once
#ifndef _TANGU
#define _TANGU

#pragma warning(disable:4091)

#ifndef _SCL_SECURE_NO_WARNINGS
#define _SCL_SECURE_NO_WARNINGS
#endif /* _SCL_SECURE_NO_WARNINGS */
#include <Algorithm>
using _STD copy;
using _STD transform;

using _STD pair;
using _STD make_pair;

#include <Iterator>
#include <Array>
#include <Vector>
#include <Forward_list>
#include <Unordered_map>
using _STD array;
using _STD vector;
using _STD forward_list;
using _STD unordered_map;

#include <String>
#include <Fstream>
#include <Sstream>
using _STD string;
using _STD wstring;
using _STD to_string;
using _STD to_wstring;

using _STD ios;
using _STD ifstream;
using _STD ofstream;
using _STD istringstream;

#include <Thread>
using _STD thread;

#include <Ctime>
#include <Chrono>
using namespace _STD chrono;

#endif /* _TANGU */

#define SCast(x) static_cast<signed __int##x> 
#define UCast(x) static_cast<unsigned __int##x> 

#define SIZ_ARP	42
#define SIZ_ICMP	74

/* Convenient Lexical Preprocessor */
#define esac break;
#define NAMESPACE_BEGIN(var) namespace var{
#define NAMESPACE_END }

/* Header : _NetManager */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")

#include <IPhlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")

/* Header : _PacketField */
/*
Creating an application that uses wpcap.dll

To create an application that uses wpcap.dll with Microsoft Visual C++, follow these steps:
	•Include the file pcap.h at the beginning of every source file that uses the functions exported by library.
	•If your program uses Win32 specific functions of WinPcap, remember to include WPCAP among the preprocessor definitions.
	•If your program uses the remote capture capabilities of WinPcap, add  HAVE_REMOTE among the preprocessor definitions. Do not include remote-ext.h directly in your source files.
	•Set the options of the linker to include the wpcap.lib library file. wpcap.lib can be found in the WinPcap developer's pack.
	•Set the options of the linker to include the winsock library file ws2_32.lib. This file is distributed with the C compiler and contains the socket functions for Windows. It is needed by some functions used by the samples in the tutorial.
*/

#define HAVE_REMOTE
#include <pcap\pcap.h>
// VC include
#include <wpcapi.h>
#pragma comment(lib, "wpcap.lib")

#define DUMP_LENGTH 0x00000800

#define SIZ_HARDWARE 6
#define SIZ_PROTOCOL 4


#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_ // Prevent redefinition of <WinSock2.h>, <Windows.h>

#pragma managed(push, off)
#include <windivert\windivert.h>
#pragma managed(pop)

#include <CTime>
#include <Assert.h>