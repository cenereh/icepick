#include "../log.h"
#include "build.h"

int wmain(int argc, wchar_t** argv)
{
	LOG_INIT();

	if (argc < 4)
	{
		clog(L"sei coglione");
		return 0;
	}

	return build::BuildExe(argv[1], argv[2], argv[3]);
}