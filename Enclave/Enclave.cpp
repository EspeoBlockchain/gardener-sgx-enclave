#include <string.h>

#include "sgx_trts.h"
#include "sgx_report.h"
#include "sgx_utils.h"

#include "ErrorCode.h"
#include "Enclave_t.h"

unsigned int e_generate_random_long(unsigned long *result) {
	unsigned long longRand;
	if (sgx_read_rand((unsigned char *)&longRand, sizeof(unsigned long)) != SGX_SUCCESS) return FC_ERR_RAND;
	
	memcpy(result, &longRand, sizeof(unsigned long));

	return FC_OK;
}
//
//sgx_status_t enclave_ra_init(sgx_ec256_public_t key, sgx_ra_context_t *ctx) {
//	sgx_status_t ra_status;
//
//	ra_status= sgx_ra_init(&key, 0, ctx);
//
//	return ra_status;
//}

unsigned int e_create_report(sgx_target_info_t *quote_enc_info, sgx_report_t *report) {
  sgx_report_data_t data; // user defined data
  unsigned int ret = 0;
  memset(&data.d, 0x90, sizeof data.d); // put in some data
  ret = sgx_create_report(quote_enc_info, &data, report);

//  hexdump("measurement: ", report->body.mr_enclave.m, SGX_HASH_SIZE);
  return ret;
}
