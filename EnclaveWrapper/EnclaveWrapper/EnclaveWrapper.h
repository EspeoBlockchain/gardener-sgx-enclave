#pragma once

#ifdef SGX_ENCLAVE_EXPORTS
#define SGX_ENCLAVE_EXPORTS_API __declspec(dllexport)
#else
#define SGX_ENCLAVE_EXPORTS_API __declspec(dllimport)
#endif

extern "C" SGX_ENCLAVE_EXPORTS_API int generateRandom(int min, int max, int *result);