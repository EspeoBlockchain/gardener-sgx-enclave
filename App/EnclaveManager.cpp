#include "EnclaveManager.h"
#include "Attestator.h"
#include "SgxException.h"
#include "Enclave_u.h"
#include "ErrorCode.h"

#include <sgx_report.h>
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <sgx_utils.h>
#include <time.h>
#include <string>
#include <cstdint>
#include <vector>
#include <iostream>
#include <stdio.h>
#include <sys/stat.h>

using std::vector;
using std::string;
using std::to_string;
using std::invalid_argument;

#define ENCLAVE_NAME "libs/Enclave.signed.so"

EnclaveManager::EnclaveManager() {
	sgx_enclave_id_t eid;
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;

	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG,
		&token, &updated,
		&eid, NULL);

	if (ret != SGX_SUCCESS) throw SgxException(ret);
	this->eid = eid;
}

EnclaveManager::~EnclaveManager() {
	sgx_status_t ret = SGX_SUCCESS;
	ret = sgx_destroy_enclave(eid);

	if (ret != SGX_SUCCESS) throw SgxException(ret);
}

unsigned long EnclaveManager::generateRandom() {
	unsigned int ret = FC_OK;
	unsigned long result;
	enclave_generate_random_long(eid, &ret, &result);
	if (ret != FC_OK) throw SgxException(SGX_ERROR_UNEXPECTED);

	return result;
}

unsigned int EnclaveManager::initRemoteAttestation() {
    config_t config;
	sgx_launch_token_t token= { 0 };
	sgx_status_t status;
	sgx_enclave_id_t eid= 0;
	int updated= 0;
	int sgx_support;
	uint32_t i;
	EVP_PKEY *service_public_key= NULL;
	char have_spid= 0;
	char flag_stdio= 0;

	const time_t timeT = time(NULL);
	struct tm lt, *ltp;

	ltp = localtime(&timeT);
	if ( ltp == NULL ) {
		perror("localtime");
		return 1;
	}
	lt= *ltp;

    loadConfig(&config);

	/* Launch the enclave */

	status = sgx_create_enclave_search(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &updated, &eid, 0);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_create_enclave: %s: %08x\n", ENCLAVE_NAME, status);
		if ( status == SGX_ERROR_ENCLAVE_FILE_ACCESS ) {
			fprintf(stderr, "Did you forget to set LD_LIBRARY_PATH??\n");
		}

		return 1;
	}

    do_attestation(eid, &config);

	return 0;
}
