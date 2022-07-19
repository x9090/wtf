#include <inttypes.h>
#include <stddef.h>
#include "FuzzerMutate.h"
#include "mutex.h" // Mutex class

// Define Cygwin function prototypes
#if defined(_WIN64)
typedef __int64(WINAPI* cgywin_dll_init)();
typedef void(*Radamsa_init)();
typedef size_t(*Radamsa)(const uint8_t* ptr, size_t len, uint8_t* target, size_t max, unsigned int seed);
typedef size_t(*Radamsa_inplace)(uint8_t* ptr, size_t len, size_t max, unsigned int seed);
#else
typedef void(WINAPI* cgywin_dll_init)();
#endif

#ifdef __cplusplus
extern bool cygwinInit;
extern bool radamsaInit;
extern "C" {
#else
extern BOOL cygwinInit;
extern BOOL radamsaInit;
#endif

// Needs statically link libradamsa.lib
size_t radamsa(uint8_t* ptr, size_t len,
	uint8_t* target, size_t max,
	unsigned int seed);

// Needs statically link libradamsa.lib
size_t radamsa_inplace(uint8_t* ptr,
	size_t len,
	size_t max,
	unsigned int seed);

// WinAFL specific parameters
typedef struct _winafl_radamsa_params {
	uint32_t perf_score;
	char** argv;
}winafl_radamsa_params;

// WinAFL radamsa's thread parameters
typedef struct _radamsa_thread_params {
	uint8_t* data;
	size_t size;
	size_t max_size;
	uint32_t seed;
}radamsa_thread_params;

// Mutator base class
class RadamsaMutator{
public:
	RadamsaMutator(std::mt19937_64 &Rng, size_t MaxLen) : Prng(Rng()), MaxTestcaseLength(MaxLen) { printf("RadamsaMutator()\n"); };
	uint8_t* Mutate(uint8_t* data, size_t data_size, size_t max_len);
    uint8_t *GetOutputBuffer() { return OutputBuff_; };
    size_t GetOutputBufferLength() { return OutputBuffLen_; };

	Mutex RadamsaMutex;
    size_t MaxTestcaseLength;
    fuzzer::Random Prng;

private:
    uint8_t *OutputBuff_;
	size_t OutputBuffLen_;
};

// Required Cygwin to run radamsa on Windows
void cygwindll_init();
void init_radamsa();

DWORD WINAPI thread_radamsa_init(void* params);
DWORD WINAPI thread_radamsa(radamsa_thread_params* params);

extern Radamsa _radamsa;

#ifdef __cplusplus
}
#endif