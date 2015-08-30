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

static bool isprint_or_whitespace(char c)
{
	return isprint(c) || c == '\r' || c == '\n' || c == '\t';
}

float compute_englishness(const char *string, size_t len)
{
	int space_count = 0;
	int other_count = 0;
	int occurrences[26];
	bzero(occurrences, sizeof(occurrences));
	struct {
		char letter;
		float proportion;
	} OCCURENCE_EXPECTATION[] = {
		{ 'e', 0.1202f },
		{ 't', 0.0910f },
		{ 'a', 0.0812f },
		{ 'o', 0.0768f },
		{ 'i', 0.0731f },
		{ 'n', 0.0695f },
		{ 's', 0.0628f },
		{ 'r', 0.0602f },
		{ 'h', 0.0592f },
		{ 'd', 0.0432f },
		{ 'l', 0.0398f },
		{ 'u', 0.0288f },
		{ 'c', 0.0271f },
		{ 'm', 0.0261f },
		{ 'f', 0.0230f },
		{ 'y', 0.0211f },
		{ 'w', 0.0209f },
		{ 'g', 0.0203f },
		{ 'p', 0.0182f },
		{ 'b', 0.0149f },
		{ 'v', 0.0111f },
		{ 'k', 0.0069f },
		{ 'x', 0.0017f },
		{ 'q', 0.0011f },
		{ 'j', 0.0010f },
		{ 'z', 0.0007f },
	};

	/*
	 * Wolfram says the average English word is five letters, meaning there
	 * should be a space about that often. That's pretty soft, but fuck it.
	 */
	float space_occurrence_expectation = (float)len / 6;
	/* Rough guess that we expect one punctuation, paren, etc. per string */
	float other_occurrence_expectation = 1.0f;

	for (size_t i = 0; i < len; i++) {
		if (isupper(string[i])) {
			occurrences[string[i] - 'A']++;
		} else if (islower(string[i])) {
			occurrences[string[i] - 'a']++;
		} else if (string[i] == ' ') {
			space_count++;
		} else {
			other_count++;
		}
	}

	bool verbose = false;

	float delta_sum = 0;
	for (size_t i = 0; i < sizeof(OCCURENCE_EXPECTATION) / sizeof(OCCURENCE_EXPECTATION[0]); i++) {
		char c = OCCURENCE_EXPECTATION[i].letter;
		float expectation = OCCURENCE_EXPECTATION[i].proportion * len;
		float occurred = (float)occurrences[c - 'a'];
		float delta = (occurred - expectation) * (occurred - expectation) / expectation;
		if (verbose)
			printf("expect %f saw %f contribution %f for %c\n", expectation, occurred, delta, c);
		delta_sum += delta;
	}
	float space_contrib = (space_count - space_occurrence_expectation) * (space_count - space_occurrence_expectation) / space_occurrence_expectation;
	delta_sum += space_contrib;
	float other_contrib = (other_count - other_occurrence_expectation) * (other_count - other_occurrence_expectation) / other_occurrence_expectation;
	delta_sum += other_contrib;
	if (verbose) {
		printf("expect %f saw %d contribution %f for space\n", space_occurrence_expectation, space_count, space_contrib);
		printf("expect %f saw %d contribution %f for other\n", other_occurrence_expectation, other_count, other_contrib);
	}

	if (verbose) {
		printf("string:\n");
		pretty_print(string, len);
		printf("score %f\n", delta_sum);
	}

	return delta_sum;
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
			float score = compute_englishness(decrypted, length / 2);
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
