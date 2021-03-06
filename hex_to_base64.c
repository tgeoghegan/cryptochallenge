#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <stdbool.h>

#include "hex_to_base64.h"
#include "utility.h"

static const char *base64_map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

long long_at_index(const char *hex_string, size_t index)
{
	char hex_octet[] = { hex_string[index], hex_string[index + 1], '\0' };
	return strtol(hex_octet, NULL, 16);
}

char *hex_to_raw(const char *hex, size_t length, size_t *out_raw_len)
{
	if (length % 2 != 0) {
		return NULL;
	}
	char *raw = calloc(1, length / 2);
	for (size_t i = 0; i < length; i += 2) {
		//printf("drop byte %lx\n", long_at_index(hex, i));
		raw[i / 2] = long_at_index(hex, i);
	}

	if (out_raw_len) {
		*out_raw_len = length / 2;
	}

	return raw;
}

bool is_base64_encoded(const char *candidate, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		if (strchr(base64_map, candidate[i]) == NULL && candidate[i] != '=') {
			return false;
		}
	}

	return true;
}

char encode_base64_char(unsigned char input)
{
	if (input > strlen(base64_map)) {
		return -1;
	}

	return base64_map[input];
}

char decode_base64_char(char input)
{
	char *position = strchr(base64_map, input);
	if (position == NULL) {
		return -1;
	}

	return position - base64_map;
}

bool hex_to_base64(const char *hex, size_t length, char **out_base64, size_t *out_base64_len)
{
	if (length % 2 != 0) {
		return false;
	}

	size_t base64_len = length / 6 * 4 + (length % 6 != 0);
	char *base64 = calloc(1, base64_len);
	if (base64 == NULL) {
		return false;
	}

	// Six bits is one base64 character. LCM of 6 and 8 (== one byte) is 24, so
	// work three input bytes at a time, producing four output bytes for each
	// block.
	for (int i = 0; i < length; i += 6) {
		// Extract upper six bits of byte 1
		int first_sextet = (long_at_index(hex, i) & 0xFC) >> 2;
		base64[i / 6 * 4] = encode_base64_char(first_sextet);

		// Extract lower two bits of byte 1, upper four bits of byte 2
		int second_sextet = ((long_at_index(hex, i) & 0x3) << 4) + ((i + 2) >= length ? 0 : ((long_at_index(hex, i + 2) & 0xF0) >> 4));
		base64[i / 6 * 4 + 1] = encode_base64_char(second_sextet);

		// Extract lower four bits of byte 2, upper two bits of byte 3
		int third_sextet = ((i + 2) >= length ? 0 : ((long_at_index(hex, i + 2) & 0xF) << 2)) + ((i + 4) >= length ? 0 : ((long_at_index(hex, i + 4) & 0xC0) >> 6));
		if ((i + 2) >= length) {
			base64[i / 6 * 4 + 2] = '=';
		} else {
			base64[i / 6 * 4 + 2] = encode_base64_char(third_sextet);
		}

		// Extract lower six bits of byte 3
		int fourth_sextet = (i + 4) >= length ? 0 : (long_at_index(hex, i + 4) & 0x3F);
		if ((i + 4) >= length) {
			base64[i / 6 * 4 + 3] = '=';
		} else {
			base64[i / 6 * 4 + 3] = encode_base64_char(fourth_sextet);
		}
	}

	if (out_base64 != NULL) {
		*out_base64 = base64;
	} else {
		free(base64);
	}
	if (out_base64_len != NULL) {
		*out_base64_len = base64_len;
	}

	return true;
}

bool base64_to_raw(const char *base64, size_t length, char **out_raw, size_t *out_raw_len)
{
	bool success = false;
	char *raw_decoded = NULL;
	char *no_newlines = calloc(1, length);
	if (no_newlines == NULL) {
		goto done;
	}

	size_t no_newlines_len = 0;
	for (size_t i = 0; i < length; i++) {
		if (base64[i] == '\n') {
			continue;
		}
		if (strchr(base64_map, base64[i]) == NULL && base64[i] != '=') {
			goto done;
		}

		no_newlines[no_newlines_len] = base64[i];
		no_newlines_len++;
	}

	if (no_newlines_len % 4 != 0) {
		goto done;
	}

	size_t raw_len = no_newlines_len * 3 / 4;
	raw_decoded = calloc(1, raw_len);
	if (raw_decoded == NULL) {
		goto done;
	}

	// Construct three ASCII bites from four Base64 characters
	size_t raw_index = 0;
	for (size_t i = 0; i < no_newlines_len; i += 4) {
		// ASCII char 1 is Base64 char 1 << 2 + bits 2-3 of Base64 char 2 >> 4

		int first_octet = (decode_base64_char(no_newlines[i]) << 2) + ((decode_base64_char(no_newlines[i + 1]) & 0x30) >> 4);
		raw_decoded[raw_index] = first_octet;

		// ASCII char 2 is Lower 4 bytes of Base64 char 2 << 4 and bits 2-5 of Base64 char 3 >> 2
		int second_octet = (decode_base64_char(no_newlines[i + 1]) & 0xF) << 4;
		if (no_newlines[i + 2] != '=') {
			second_octet += (decode_base64_char(no_newlines[i + 2]) & 0x3C) >> 2;
		}
		raw_decoded[raw_index + 1] = second_octet;

		// ASCII char 3 is lower 2 bytes of Base64 char 3 << 6 and Base64 char 4
		int third_octet = 0;
		if (no_newlines[i + 2] != '=') {
			third_octet += (decode_base64_char(no_newlines[i + 2]) & 0x3) << 6;
		}
		if (no_newlines[i + 3] != '=') {
			third_octet += decode_base64_char(no_newlines[i + 3]);
		}
		raw_decoded[raw_index + 2] = third_octet;

		raw_index += 3;
	}

	if (out_raw_len != NULL) {
		if (no_newlines[no_newlines_len - 1] == '=') {
			raw_len--;
		}
		if (no_newlines[no_newlines_len - 2] == '=') {
			raw_len--;
		}
		*out_raw_len = raw_len;
	}

	if (out_raw != NULL) {
		*out_raw = raw_decoded;
	} else {
		free(raw_decoded);
	}

	success = true;
done:
	free(no_newlines);

	return success;
}

char *hex_print_string(const char *string, size_t len)
{
	char *hex = calloc(1, len * 2 + 1);
	if (hex == NULL) {
		return NULL;
	}

	for (size_t i = 0; i < len; i++) {
		char hex_char[3];
		snprintf(hex_char, sizeof(hex_char), "%02x", string[i]);
		hex[i * 2] = hex_char[0];
		hex[i * 2 + 1] = hex_char[1];
	}

	return hex;
}

#ifdef BASE64_TEST

int main(void)
{
	const char *input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	const char *input2 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f";
	const char *input3 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f";

	size_t len = strlen(input);
	char *output = NULL;
	if (!hex_to_base64(input, len, &output, NULL)
		|| !output
		|| strcmp(output, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t") != 0) {
		print_fail("base64 conversion failed: %s -> %s", input, output);
		exit(-1);
	}

	char *original = NULL;
	if (!base64_to_raw(output, strlen(output), &original, NULL)) {
		print_fail("conversion to raw failed");
	}
	char *original_hex = NULL;
	if (original) {
		original_hex = hex_print_string(original, strlen(original));
		if (!original_hex || strcmp(original_hex, input) != 0) {
			print_fail("conversion to hex failed: %s -> %s -> %s", input, output, original_hex);
			exit(-1);
		}

		free(original_hex);
		original_hex = NULL;
		free(original);
		original = NULL;
	}

	free(output);
	output = NULL;

	if (!hex_to_base64(input2, strlen(input2), &output, NULL)
		|| !output
		|| strcmp(output, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb28=") != 0) {
		print_fail("base64 conversion failed: %s -> %s", input2, output);
		exit(-1);
	}

	if (!base64_to_raw(output, strlen(output), &original, NULL)) {
		print_fail("base64 conversion failed: %s -> %s", output, original);
	}
	if (original) {
		original_hex = hex_print_string(original, strlen(original));
		if (!original_hex || strcmp(original_hex, input2) != 0) {
			print_fail("conversion to hex failed: %s -> %s -> %s", input2, output, original_hex);
			exit(-1);
		}

		free(original_hex);
		original_hex = NULL;
		free(original);
		original = NULL;
	}

	free(output);
	output = NULL;

	if (!hex_to_base64(input3, strlen(input3), &output, NULL)
		|| !output
		|| strcmp(output, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hybw==") != 0) {
		print_fail("Base64 conversion failed: %s -> %s", input3, output);
		exit(-1);
	}

	if (!base64_to_raw(output, strlen(output), &original, NULL)) {
		print_fail("base64 conversion failed");
	}
	if (original) {
		original_hex = hex_print_string(original, strlen(original));
		if (!original_hex || strcmp(original_hex, input3) != 0) {
			print_fail("conversion to hex failed: %s -> %s -> %s", input3, output, original_hex);
			exit(-1);
		}

		free(original_hex);
		original_hex = NULL;
		free(original);
		original = NULL;
	}

	free(output);
	output = NULL;

	print_success("base64 OK");
	return 0;
}

#endif // BASE64_TEST
