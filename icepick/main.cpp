#include "../log.h"
#include "winapi/winapi.h"

#include "unpack.h"

int main()
{
	LOG_INIT();
	WINAPI_INIT();

	if (!Init)
		return 0;

	uint32_t Size;
	uint8_t* ExecutableToMap = unpack::UnpackPayload(Size);

	return 1;
}