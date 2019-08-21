#include <stdio.h>
#include "App/App.h"

void testRandom() {
	long result;
	generateRandom(0L, 10L, &result);

	printf("result: %ld\n", result);
}

void testRemoteAttestation() {
    initRemoteAttestation();
}

int main() {
    testRemoteAttestation();

	return 0;
}
