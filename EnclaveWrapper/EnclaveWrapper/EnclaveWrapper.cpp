#include "stdafx.h"
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "EnclaveWrapper.h"
#include "ErrorCode.h"
#include "SgxException.h"

#define ENCLAVE_FILE _T("Enclave.signed.dll")
#define MAX_BUF_LEN 100

sgx_status_t createEnclave(sgx_enclave_id_t *eid) {
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;

	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG,
		&token, &updated,
		eid, NULL);

	if (ret != SGX_SUCCESS) throw SgxException(ret);

	return ret;
}

sgx_status_t destroyEnclave(sgx_enclave_id_t eid) {
	sgx_status_t ret = SGX_SUCCESS;
	ret = sgx_destroy_enclave(eid);

	if (ret != SGX_SUCCESS) throw SgxException(ret);

	return ret;
}

unsigned int generateRandomChar(sgx_enclave_id_t eid, unsigned char *buf) {
	unsigned int ret = FC_OK;
	e_generate_random(eid, &ret, buf);
	if (ret != FC_OK) throw SgxException(SGX_ERROR_UNEXPECTED);

	return ret;
}

int affineTransformation(int x, int targetRangeMin, int targetRangeMax, int sourceRangeMin, int sourceRangeMax) {
	return (x - sourceRangeMin)*(targetRangeMax - targetRangeMin) / (sourceRangeMax - sourceRangeMin) + targetRangeMin;
}

int generateRandom(int min, int max, int *result) {
	sgx_enclave_id_t eid;
	int mappedRandomValue;

	try {
		createEnclave(&eid);

		unsigned char *buf = new unsigned char[1];
		generateRandomChar(eid, buf);

		mappedRandomValue = affineTransformation((int)buf[0], min, max, 0, 255);
		printf("Transforming [0, 255] to [%d, %d]: %d -> %d \n", min, max, buf[0], mappedRandomValue);

		destroyEnclave(eid);
	} catch (SgxException& e) {
		printf("%s\n", e.what());
		return -1;
	}

	memcpy(result, &mappedRandomValue, sizeof(int));
	return 0;
}
