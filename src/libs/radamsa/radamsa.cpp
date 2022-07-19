#include <windows.h>
#include <stdio.h>
#include "radamsa.h"

#ifdef __cplusplus
bool cygwinInit = false;
bool radamsaInit = false;
#else
BOOL cygwinInit = FALSE;
BOOL radamsaInit = FALSE;
#endif
Radamsa _radamsa;

void cygwindll_init()
{
	const char* cygwin_libname = "cygwin1.dll";
	HMODULE hLib = LoadLibraryA(cygwin_libname);

	if (!cygwinInit)
	{
		if (hLib == NULL)
		{
			printf("Unable to load %s, GetLastError = 0x%x", cygwin_libname, GetLastError());
			exit(1);
		}
		
		cgywin_dll_init cygwin_init = (cgywin_dll_init)GetProcAddress(hLib, "cygwin_dll_init");

		cygwin_init();

		printf("%s loaded successfully\n", cygwin_libname);

#ifdef __cplusplus
		cygwinInit = true;
#else
		cygwinInit = TRUE;
#endif
	}

}


// radamsa_init()
// libradamsa is loaded dynamically
void init_radamsa()
{
	const char* radamsa_libname = "libradamsa.dll";

	HMODULE hLib = LoadLibraryA(radamsa_libname);

	if (hLib == NULL)
	{
		printf("Unable to load %s, GetLastError = 0x%x", radamsa_libname, GetLastError());
		exit(1);
	}

	Radamsa_init radamsa_init = (Radamsa_init)GetProcAddress(hLib, "radamsa_init");

	radamsa_init();

	_radamsa = (Radamsa)GetProcAddress(hLib, "radamsa");

	printf("%s loaded successfully\n", radamsa_libname);

#ifdef __cplusplus
	radamsaInit = true;
#else
	radamsaInit = TRUE;
#endif
}

// We have to call radamsa_init() through threading on Windows Cygwin
// Used when libradamsa loaded statically
DWORD WINAPI thread_radamsa_init(void* params)
{
	//radamsa_init();
#ifdef __cplusplus
	radamsaInit = true;
#else
	radamsaInit = TRUE;
#endif
	return 1;
}

// We have to call radamsa() mutation function through threading on Windows Cygwin
DWORD WINAPI thread_radamsa(radamsa_thread_params* params)
{
	OutputDebugStringA("thread_radamsa()\n");
	/*size_t out_len = 0;
	uint8_t* out_buff = (uint8_t*)malloc(params->max_size);
	memset(out_buff, 0, params->max_size);
	OutputDebugStringA("calling radamsa()\n");
	out_len = radamsa((uint8_t*)params->data, params->size, out_buff, params->max_size, params->seed);
	OutputDebugStringA("called radamsa()\n");
	if (out_len > 0)
	{
		free(params->data);
		params->data = out_buff;
		params->size = out_len;
	}
	else
	{
		free(out_buff);
	}*/
	OutputDebugStringA("exit radamsa()\n");
	return 1;
}

// Main radamsa() mutation routine
uint8_t* RadamsaMutator::Mutate(uint8_t *data, size_t data_len, size_t max_len) {
	
	RadamsaMutator::OutputBuff_ = nullptr;
	RadamsaMutator::OutputBuffLen_ = 0;

	if (!radamsaInit)
	{
		printf("Must call radamsa_init() first\n");
		return nullptr;
	}

	size_t out_len = 0;
	uint8_t* out_buff = (uint8_t*)malloc(max_len);
	memset(out_buff, 0, max_len);
	RadamsaMutex.Lock();
	out_len = _radamsa((uint8_t*)data, data_len, out_buff, max_len, Prng.Rand());
	RadamsaMutex.Unlock();
	
	if (out_len <= 0) {
		free(out_buff);
		out_buff = nullptr;
    } 
	else {
		RadamsaMutator::OutputBuff_ = out_buff;
		RadamsaMutator::OutputBuffLen_ = out_len;
	}
	
	return out_buff;
}