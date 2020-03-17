#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <errno.h>
#include <math.h>
#include <float.h>

#include "decrypt_single_char_xor.h"
#include "hex_to_base64.h"
#include "utility.h"
#include "compute_englishness.h"

static void pretty_print(const char *string, size_t len);

static char *xor_string_with_char(const char *string, size_t len, char key)
{
	char *decrypted = calloc(1, len / 2 + 1);
	if (decrypted == NULL) {
		return NULL;
	}

	for (size_t i = 0; i < len; i += 2) {
		char curr_char = (char)long_at_index(string, i);
		decrypted[i / 2] = curr_char ^ key;
	}

	return decrypted;
}

static char *xor_raw_bytes_with_char(const char *raw_bytes, size_t len, char key)
{
	char *decrypted = calloc(1, len + 1);
	if (decrypted == NULL) {
		return NULL;
	}

	for (size_t i = 0; i < len; i++) {
		decrypted[i] = raw_bytes[i] ^ key;
	}

	return decrypted;
}

static void pretty_print(const char *string, size_t len)
{
	if (string == NULL) {
		printf("NULL\n");
		return;
	}
	for (size_t i = 0; i < len; i++) {
		if (isprint(string[i])) {
			printf("%c", string[i]);
		}

	}
	printf("\n");
}

float best_string_from_encrypted(bool raw_bytes, const char *encrypted, size_t length, char **out_best_string, char *out_best_key)
{
	char *best_string = NULL;
	float best_score = FLT_MAX;
	char best_key = -1;

	for (int key = 0; key < 256; key++) {
		char *decrypted = raw_bytes ? xor_raw_bytes_with_char(encrypted, length, (char)key) : xor_string_with_char(encrypted, length, (char)key);
		if (decrypted) {
			float score = compute_englishness(decrypted, length / 2, ENGLISHNESS_CHECK_MONOGRAMS);
			if (score < best_score) {
				best_score = score;
				best_key = key;
				free(best_string);
				best_string = decrypted;
			} else {
				free(decrypted);
			}
		}
	}

	bool verbose = false;
	if (verbose && best_score != FLT_MAX) {
		printf("Input string: %s\nScore: %f\tkey: %d\nBest string: ", encrypted, best_score, best_key);
		pretty_print(best_string, length / 2);
		printf("\n");
	}

	if (out_best_string) {
		*out_best_string = best_string;
	} else {
		free(best_string);
	}

	if (out_best_key) {
		*out_best_key = best_key;
	}

	return best_score;
}

#if DECRYPT_SINGLE_CHAR_XOR_TEST

int main(int argc, char **argv)
{
	if (argc == 2) {
		FILE *input = fopen(argv[1], "r");
		if (input == NULL) {
			print_fail("failed to open input '%s': %s", argv[1], strerror(errno));
			exit(-1);
		}

		char *line = NULL;
		size_t linecap = 0;
		ssize_t linelen = 0;
		char *best_string = NULL;
		float best_score = FLT_MAX;
		while ((linelen = getline(&line, &linecap, input)) > 0) {
			float score;
			char *curr_string = NULL;
			if (line[linelen - 1] == '\n') {
				score = best_string_from_encrypted(false, line, linelen - 1, &curr_string, NULL);
			} else {
				score = best_string_from_encrypted(false, line, linelen, &curr_string, NULL);
			}
			if (score < best_score) {
				best_score = score;
				free(best_string);
				best_string = curr_string;
			} else {
				free(curr_string);
			}
		}
		free(line);
		fclose(input);

		if (!best_string || strcmp(best_string, "Now that the party is jumping\n") != 0) {
			print_fail("wrong best string %s", best_string);
			exit(-1);
		} else {
			print_success("single char xor test OK");
		}

		free(best_string);
	} else {
		const char *encrypted = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
		char *best = NULL;
		best_string_from_encrypted(false, encrypted, strlen(encrypted), &best, NULL);
		if (!best || strcmp(best, "Cooking MC's like a pound of bacon") != 0) {
			print_fail("wrong best string %s", best);
			exit(-1);
		} else {
			print_success("simple single char xor test OK");
		}
	}

	return 0;
}

#endif // DECRYPT_SINGLE_CHAR_XOR_TEST
