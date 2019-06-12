#include "stdafx.h"
#include "EnclaveWrapper.h"
#include "SgxException.h"
#include "EnclaveManager.h"

long affineTransformation(unsigned long x, long targetRangeMin, long targetRangeMax, unsigned long sourceRangeMin, unsigned long sourceRangeMax) {
	return ((double)x - (double)sourceRangeMin)*((double)targetRangeMax - (double)targetRangeMin) / ((double)sourceRangeMax - (double)sourceRangeMin) + (double)targetRangeMin;
}

int generateRandom(long min, long max, long *result) {
	long mappedRandomValue;

	try {
		EnclaveManager enclave;
		unsigned long generated;
		enclave.generateRandom(&generated);

		mappedRandomValue = affineTransformation(generated, min, max, 0, ULONG_MAX);
		printf("Transforming [0, %lu] to [%ld, %ld]: %lu -> %ld \n", ULONG_MAX, min, max, generated, mappedRandomValue);
	} catch (SgxException& e) {
		printf("%s\n", e.what());
		return -1;
	}

	memcpy(result, &mappedRandomValue, sizeof(long));
	return 0;
}
