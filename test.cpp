#include <stdio.h>
#include "App/App.h"

int main() {
	long result;
	generateRandom(0L, 10L, &result);
	
	printf("result: %ld\n", result);

	return 0;
}
