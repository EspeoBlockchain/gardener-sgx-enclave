#include <stdio.h>
#include <climits>
#include <math.h>

#include "App.h"
#include "SgxException.h"
#include "EnclaveManager.h"

long affineTransformation(unsigned long x, long targetRangeMin, long targetRangeMax, unsigned long sourceRangeMin, unsigned long sourceRangeMax) {
	return floor((double)(x - sourceRangeMin)*(targetRangeMax - targetRangeMin) / (sourceRangeMax - sourceRangeMin) + targetRangeMin);
}

int generateRandom(long min, long max, long *result) {
	try {
		EnclaveManager enclave;
		unsigned long generated = enclave.generateRandom();

		*result = affineTransformation(generated, min, max, 0, ULONG_MAX);
		printf("Transforming random value from SGX [0, %lu] to [%ld, %ld]: %lu -> %ld \n", ULONG_MAX, min, max, generated, *result);
	} catch (SgxException& e) {
		printf("%s\n", e.what());
		return -1;
	}

	return 0;
}

int remoteAttestation() {
    try {
		EnclaveManager enclave;
		int status = enclave.remoteAttestation();

		printf("Tried to initialise remote attestation. Status was %d\n", status);

		return status;
	} catch (SgxException& e) {
		printf("%s\n", e.what());
		return -1;
	}

	return 0;
}

int main() {
    long longStatus;
    generateRandom(0L, 100L, &longStatus);
    remoteAttestation();

	return 0;
}
