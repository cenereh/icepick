#pragma once
#include <cstdint>

static class mapper
{
public:

	static enum ProcessToInject : int
	{
		PROCESS_SELF = 0,
		PROCESS_NOTEPAD
	};

	static bool UnmanagedManualMap(uint8_t* Image);
	static bool UnmanagedProcessInjection(ProcessToInject proc, uint8_t* Image);
	static bool UnmanagedX86ProcessInjection(ProcessToInject proc, uint8_t* Image);

	// todo: managed process injection with embedded CLR stub.
	static bool ManagedProcessInjection(uint8_t* Image);
	static bool ManagedX86ProcessInjection(uint8_t* Image);
	
};

