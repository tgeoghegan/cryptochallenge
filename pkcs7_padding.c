#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include "pkcs7_padding.h"
#include "utility.h"

bool pkcs7_pad_buffer(const char *buffer, size_t buffer_len, size_t block_size, char **out_padded, size_t *out_padded_len)
{
	size_t pad_len = block_size - (buffer_len % block_size);

	char *padded = calloc(1, buffer_len + pad_len);
	if (padded == NULL) {
		return false;
	}

	memcpy(padded, buffer, buffer_len);

	for (size_t i = 0; i < pad_len; i++) {
		padded[buffer_len + i] = pad_len;
	}

	if (out_padded != NULL) {
		*out_padded = padded;
	}

	if (out_padded_len) {
		*out_padded_len = pad_len + buffer_len;
	}

	return true;
}

bool pkcs7_unpad_buffer(const char *buffer, size_t buffer_len, size_t *out_unpadded_len)
{
	char last_byte = buffer[buffer_len - 1];
	
	// Check padding correctness
	if (last_byte > buffer_len) {
		return false;
	}

	if (last_byte == 0x0) {
		return false;
	}

	for (size_t i = buffer_len - last_byte; i < buffer_len; i++) {
		if (buffer[i] != last_byte) {
			return false;
		}
	}

	if (out_unpadded_len != NULL) {
		*out_unpadded_len = buffer_len - last_byte;
	}

	return true;
}

#if PKCS7_PADDING_TEST

int main(int argc, char **argv)
{
	char *buffer = malloc(3);
	memset(buffer, 17, 3);

	size_t padded_len;
	char *padded = NULL;
	if (!pkcs7_pad_buffer(buffer, 3, 4, &padded, &padded_len)) {
		print_fail("PKCS#7 padding: failed to pad");
		exit(-1);
	}
	if (padded_len != 4) {
		print_fail("PKCS#7 padding: bad pad length %zu", padded_len);
		exit(-1);
	}

	if (strncmp(buffer, padded, 3) != 0) {
		print_fail("PKCS#7 padding: initial buffer missing");
		exit(-1);
	}

	if (padded[3] != 1) {
		print_fail("PKCS#7 padding: wrong pad byte %hhd", padded[3]);
		exit(-1);
	}

	size_t unpadded;
	if (!pkcs7_unpad_buffer(padded, padded_len, &unpadded)) {
		print_fail("PKCS#7 padding: failed to unpad");
		exit(-1);
	}
	if (unpadded != 3) {
		print_fail("PKCS#7 padding: wrong unpadded length %zu", unpadded);
		exit(-1);
	}

	free(buffer);
	free(padded);
	buffer = NULL;
	padded = NULL;

	buffer = malloc(5);
	memset(buffer, 17, 5);

	if (!pkcs7_pad_buffer(buffer, 5, 4, &padded, &padded_len)) {
		print_fail("PKCS#7 padding: failed to pad");
		exit(-1);
	}
	if (padded_len != 8) {
		print_fail("PKCS#7 padding: bad pad length %zu", padded_len);
		exit(-1);
	}

	if (strncmp(buffer, padded, 5) != 0) {
		print_fail("PKCS#7 padding: initial buffer missing");
		exit(-1);
	}

	if (padded[5] != 3 || padded[6] != 3 || padded[7] != 3) {
		print_fail("PKCS#7 padding: wrong pad bytes %hhd%hhd%hhd", padded[5], padded[6], padded[7]);
		exit(-1);
	}

	if (!pkcs7_unpad_buffer(padded, padded_len, &unpadded)) {
		print_fail("PKCS#7 padding: failed to unpad");
		exit(-1);
	}
	if (unpadded != 5) {
		print_fail("PKCS#7 padding: wrong unpadded length %zu", unpadded);
		exit(-1);
	}

	free(buffer);
	free(padded);
	buffer = NULL;
	padded = NULL;

	buffer = malloc(4);
	memset(buffer, 17, 4);

	if (!pkcs7_pad_buffer(buffer, 4, 4, &padded, &padded_len)) {
		print_fail("PKCS#7 padding: failed to pad");
		exit(-1);
	}
	if (padded_len != 8) {
		print_fail("PKCS#7 padding: bad pad length %zu", padded_len);
		exit(-1);
	}

	if (strncmp(buffer, padded, 4) != 0) {
		print_fail("PKCS#7 padding: initial buffer missing");
		exit(-1);
	}

	if (padded[4] != 4 || padded[5] != 4 || padded[6] != 4 || padded[7] != 4) {
		print_fail("PKCS#7 padding: wrong pad bytes %hhd%hhd%hhd%hhd", padded[4], padded[5], padded[6], padded[7]);
        exit(-1);
    }

	if (!pkcs7_unpad_buffer(padded, padded_len, &unpadded)) {
		print_fail("PKCS#7 padding: failed to unpad");
		exit(-1);
	}

	if (unpadded != 4) {
		print_fail("PKCS#7 padding: wrong unpadded length %zu", unpadded);
		exit(-1);
	}

	free(buffer);
	free(padded);

	char *ok_pad = "ICE ICE BABY\x04\x04\x04\x04";
	if (!pkcs7_unpad_buffer(ok_pad, strlen(ok_pad), &unpadded)) {
		print_fail("PKCS#7 padding: failed to unpad");
		exit(-1);
	}
	if (unpadded != 12) {
		print_fail("PKCS#7 padding: wrong unpadded length %zu", unpadded);
		exit(-1);
	}

	char *bad_pad = "ICE ICE BABY\x05\x05\x05\x05";
	if (pkcs7_unpad_buffer(bad_pad, strlen(bad_pad), &unpadded)) {
		print_fail("PKCS#7 padding: unpadded invalid padding");
		exit(-1);
	}

	bad_pad = "ICE ICE BABY\x01\x02\x03\x04";
	if (pkcs7_unpad_buffer(bad_pad, strlen(bad_pad), &unpadded)) {
		print_fail("PKCS#7 padding: unpadded invalid padding");
		exit(-1);
	}

	ok_pad = "four\x4\x4\x4\x4";
	if (!pkcs7_unpad_buffer(ok_pad, strlen(ok_pad), &unpadded)) {
		print_fail("PKCS#7 padding: failed to unpad");
		exit(-1);
	}

	ok_pad = "\x4\x4\x4\x4";
	if (!pkcs7_unpad_buffer(ok_pad, strlen(ok_pad), &unpadded)) {
		print_fail("PKCS#7 padding: failed to unpad");
		exit(-1);
	}

	print_success("PKCS#7 padding OK");
	return 0;
}

#endif // PKCS_PADDING_TEST
