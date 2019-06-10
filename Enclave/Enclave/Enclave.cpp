#include "sgx_trts.h"
#include <string.h>
#include "ErrorCode.h"
#include "Enclave_t.h"

using namespace std;

unsigned int e_generate_random(unsigned char *result)
{
	unsigned char *randBuf = new unsigned char[1];
	if (sgx_read_rand(randBuf, 1) != SGX_SUCCESS) return FC_ERR_RAND;

	memcpy(result, randBuf, 1);

	return FC_OK;
}