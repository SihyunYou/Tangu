#pragma once

#include <IOStream>
#include <net_manager\net_manager.hpp>

#pragma comment(lib, "tangu.lib")

INT main(INT argc, LPSTR argv[])
{
	using namespace Net;

	PIPNetTableInfo IpNetRow = IPNetTableInfo::GetInstance();
	PMIB_IPNETTABLE Table = IpNetRow->GetTable();
	PMIB_IPNETROW Row;

	std::cout << "Internet Address\tPhysical Address\t Type\n";
	for (INT i = 0; i != Table->dwNumEntries; ++i)
	{
		Row = &(Table->table[i]);
		std::cout << IPInfo{ ntohl(Row->dwAddr) }() << "\t\t" <<
			MACInfo{ Row->bPhysAddr }() << "\t" <<
			IpNetRow->Type[Row->dwType - 1] << std::endl;
	}
}
