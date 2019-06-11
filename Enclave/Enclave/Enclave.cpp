#include "sgx_trts.h"
#include <string.h>
#include "ErrorCode.h"
#include "Enclave_t.h"

unsigned int e_generate_random_long(unsigned long *result) {
	unsigned long longRand;
	if (sgx_read_rand((unsigned char *)&longRand, 4) != SGX_SUCCESS) return FC_ERR_RAND;
	
	memcpy(result, &longRand, sizeof(unsigned long));

	return FC_OK;
}