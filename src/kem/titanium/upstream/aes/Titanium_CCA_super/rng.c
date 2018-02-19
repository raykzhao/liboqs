#include "rng.h"
#include <stddef.h>
#include <stdint.h>

extern void OQS_randombytes(uint8_t *random_array, size_t bytes_to_read);

int randombytes(unsigned char *x, unsigned long long xlen)
{
	OQS_randombytes(x, xlen);
	return 0;
}
