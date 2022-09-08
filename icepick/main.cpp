#include "../log.h"
#include "winapi/winapi.h"

int main()
{
	LOG_INIT();
	WINAPI_INIT();

	if (!Init)
		return 0;
}