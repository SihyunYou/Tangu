#pragma once
#ifndef _WINDIVERT
#define _WINDIVERT

#include "tangu_analyzer.hpp"

#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_ // Prevent redefinition of <WinSock2.h>, <Windows.h>

#pragma managed(push, off)
#include <windivert.h>
#pragma managed(pop)

#include <CTime>
#include <Assert.h>

#endif /* _WINDIVERT */