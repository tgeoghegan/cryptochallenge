#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "pkcs7_padding.h"

char *pkcs7_pad_buffer(const char *buffer, size_t buffer_len, size_t block_size, size_t *out_padded_len)
{
	size_t pad_len = block_size - (buffer_len % block_size);

	char *padded = calloc(1, buffer_len + pad_len);
	if (padded == NULL) {
		return NULL;
	}

	memcpy(padded, buffer, buffer_len);

	for (size_t i = 0; i < pad_len; i++) {
		padded[buffer_len + i] = pad_len;
	}

	if (out_padded_len) {
		*out_padded_len = pad_len + buffer_len;
	}

	return padded;
}

#if PKCS7_PADDING_TEST

int main(int argc, char **argv)
{
	char *buffer = malloc(3);
	memset(buffer, 17, 3);

	size_t padded_len;
	char *padded = pkcs7_pad_buffer(buffer, 3, 4, &padded_len);
	if (!padded) {
		fprintf(stderr, "PKCS#7 padding: failed to pad\n");
		exit(-1);
	}
	if (padded_len != 4) {
		fprintf(stderr, "PKCS#7 padding: bad pad length %zu\n", padded_len);
		exit(-1);
	}

	if (strncmp(buffer, padded, 3) != 0) {
		fprintf(stderr, "PKCS#7 padding: initial buffer missing\n");
	}

	if (padded[3] != 1) {
		fprintf(stderr, "PKCS#7 padding: wrong pad byte %hhd\n", padded[3]);
		exit(-1);
	}

	free(buffer);
	free(padded);
	buffer = NULL;
	padded = NULL;

	buffer = malloc(5);
	memset(buffer, 17, 5);

	padded = pkcs7_pad_buffer(buffer, 5, 4, &padded_len);
	if (!padded) {
		fprintf(stderr, "PKCS#7 padding: failed to pad\n");
		exit(-1);
	}
	if (padded_len != 8) {
		fprintf(stderr, "PKCS#7 padding: bad pad length %zu\n", padded_len);
		exit(-1);
	}

	if (strncmp(buffer, padded, 5) != 0) {
		fprintf(stderr, "PKCS#7 padding: initial buffer missing\n");
	}

	if (padded[5] != 3 || padded[6] != 3 || padded[7] != 3) {
		fprintf(stderr, "PKCS#7 padding: wrong pad bytes %hhd%hhd%hhd\n", padded[5], padded[6], padded[7]);
		exit(-1);
	}

	free(buffer);
	free(padded);
	buffer = NULL;
	padded = NULL;

	buffer = malloc(4);
	memset(buffer, 17, 4);

	padded = pkcs7_pad_buffer(buffer, 4, 4, &padded_len);
	if (!padded) {
		fprintf(stderr, "PKCS#7 padding: failed to pad\n");
		exit(-1);
	}
	if (padded_len != 8) {
		fprintf(stderr, "PKCS#7 padding: bad pad length %zu\n", padded_len);
		exit(-1);
	}

	if (strncmp(buffer, padded, 4) != 0) {
		fprintf(stderr, "PKCS#7 padding: initial buffer missing\n");
	}

	if (padded[4] != 4 || padded[5] != 4 || padded[6] != 4 || padded[7] != 4) {
		fprintf(stderr, "PKCS#7 padding: wrong pad bytes %hhd%hhd%hhd%hhd\n", padded[4], padded[5], padded[6], padded[7]);
		exit(-1);
	}

	free(buffer);
	free(padded);

	printf("PKCS#7 padding OK\n");
	return 0;
}

#endif // PKCS_PADDING_TEST
