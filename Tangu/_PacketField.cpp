#pragma once
#include "_PacketField"

namespace Packet /* _PacketField_H # class Utility */
{
	char Utility::_Buf[0x20] = { 0 };
	unsigned Utility::_Dec = 0;

	unsigned __int32 Utility::Trace(const byte* Data, unsigned __int32 Length)
	{
		if (Length > sizeof(long))
		{
			return -1;
		}
		else
		{
			_Dec = 0;
			for (int Byte = Length - 1; Byte >= 0; --Byte)
			{
				sprintf_s(_Buf, "%i", Data[Length - Byte - 1]);
				_Dec += (atoi(_Buf) << (Byte * 8));
			}

			return _Dec;
		}
	}

	void Utility::CustomPermutate(string& Content, const char* Format, ...)
	{
		char			FormatBuf[FORMAT_MESSAGE_ALLOCATE_BUFFER];
		va_list		Marker;

		va_start(Marker, Format);
		vsprintf_s(FormatBuf, Format, Marker);

		Content += FormatBuf;
	}
}

namespace Packet /* _PacketField_ARP # class __ARP */
{

}