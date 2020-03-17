#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <float.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdbool.h>

#include "decrypt_single_char_xor.h"
#include "hex_to_base64.h"
#include "utility.h"
#include "compute_englishness.h"

char *repeating_key_xor(const char *plaintext, size_t len, const char *key, size_t key_len)
{
	char *ciphertext = calloc(1, len + 1);
	if (ciphertext == NULL) {
		return NULL;
	}

	for (size_t i = 0; i < len; i++) {
		ciphertext[i] = plaintext[i] ^ key[i % key_len];
	}
	return ciphertext;
}

int set_bits_in_byte(char byte)
{
	int count = 0;
	for (int i = 0; i < 8; i++) {
		if (byte >> i & 1) {
			count++;
		}
	}

	return count;
}

int bitwise_hamming_distance(const char *lhs, size_t lhs_len, const char *rhs, size_t rhs_len)
{
	int distance = 0;
	for (size_t i = 0; i < lhs_len; i++) {
		distance += set_bits_in_byte(lhs[i] ^ rhs[i]);
	}
	return distance;
}

int *guess_key_lengths(const char *ciphertext, size_t ciphertext_len, int key_len_count)
{
	struct key_candidate {
		int key_len;
		float hamming_score;
	};
	struct key_candidate key_candidates[39];
	bzero(key_candidates, sizeof(key_candidates));

	for (int key_len = 2; key_len <= 40; key_len++) {
		float total_hamming = 0.0f;
		size_t block_count = ciphertext_len / key_len;

		for (size_t i = 0; i < block_count - 1; i++) {
			float hamming = bitwise_hamming_distance(ciphertext + (key_len * i), key_len, ciphertext + (key_len * (i + 1)), key_len);
			total_hamming += hamming;
		}

		total_hamming /= block_count * key_len;

		key_candidates[key_len - 2].key_len = key_len;
		key_candidates[key_len - 2].hamming_score = total_hamming;
	}

	qsort_b(key_candidates, sizeof(key_candidates) / sizeof(key_candidates[0]), sizeof(key_candidates[0]), ^(const void *lhs, const void *rhs) {
		struct key_candidate *lhs_key = (struct key_candidate *)lhs;
		struct key_candidate *rhs_key = (struct key_candidate *)rhs;

		if (lhs_key->hamming_score < rhs_key->hamming_score) {
			return -1;
		} else if (lhs_key->hamming_score == rhs_key->hamming_score) {
			return 0;
		} else if (lhs_key->hamming_score > rhs_key->hamming_score) {
			return 1;
		}

		return 0;
	});

	int *best_key_lengths = calloc(sizeof(int), key_len_count);
	for (int i = 0; i < key_len_count; i++) {
		struct key_candidate key_candidate = key_candidates[i];
		best_key_lengths[i] = key_candidate.key_len;
	}

	return best_key_lengths;
}

int guess_key(const char *ciphertext, size_t ciphertext_len, size_t key_len, char **out_key)
{
	char key[key_len];
	bzero(key, sizeof(key));

	// transpose: make key_len blocks of size ciphertext_len / key_len and for each, determine single byte xor key
	for (int i = 0; i < key_len; i++) {
		size_t transpose_block_len = ciphertext_len / key_len;

		char *transpose_block = calloc(1, transpose_block_len);
		if (transpose_block == NULL) {
			print_fail("failed to allocate buffer");
			return -1;
		}

		for (size_t j = 0; j < ciphertext_len / key_len; j++) {
			transpose_block[j] = ciphertext[(j * key_len) + i];
		}

		char *out_best_string = NULL;
		char out_best_key;
		(void)best_string_from_encrypted(true, transpose_block, transpose_block_len * 2, &out_best_string, &out_best_key);

		key[i] = out_best_key;
	}

	if (out_key) {
		*out_key = calloc(1, key_len + 1);
		if (*out_key == NULL) {
			print_fail("failed to allocate key buffer");
			return -1;
		}
		memcpy(*out_key, key, sizeof(key));
	}

	return 0;
}

#if TEST_REPEATING_KEY_XOR

int main(int argc, char **argv)
{
	char *plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
	char *expected_ciphertext = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
	char *key = "ICE";

	char *ciphertext = repeating_key_xor(plaintext, strlen(plaintext), key, strlen(key));
	char *pretty_ciphertext = hex_print_string(ciphertext, strlen(ciphertext));

	if (strncmp(expected_ciphertext, pretty_ciphertext, strlen(expected_ciphertext)) == 0) {
		print_success("repeating XOR encrypt OK");
	} else {
		print_fail("repeating XOR encrypt wrong");
		exit(-1);
	}

	char *reverse_encrypt = repeating_key_xor(ciphertext, strlen(ciphertext), key, strlen(key));
	if (!reverse_encrypt || strcmp(reverse_encrypt, plaintext) != 0) {
		print_fail("reverse repeating XOR encryption wrong: %s", reverse_encrypt);
		exit(-1);
	} else {
		print_success("reverse repeating XOR encryption OK");
	}
	free(reverse_encrypt);
	free(ciphertext);
	free(pretty_ciphertext);

	const char *lhs = "this is a test";
	const char *rhs = "wokka wokka!!!";
	int distance = bitwise_hamming_distance(lhs, strlen(lhs), rhs, strlen(rhs));
	if (distance == 37) {
		print_success("hamming OK");
	} else {
		print_fail("hamming wrong: %d", distance);
		exit(-1);
	}

	if (argc != 3) {
		return 0;
	}

	size_t size;
	char *buf = load_buffer_from_file(argv[1], &size);
	if (buf == NULL) {
		print_fail("failed to load file");
		exit(-1);
	}

	size_t raw_len;
	char *raw_bytes = NULL;
	if (!base64_to_raw(buf, size, &raw_bytes, &raw_len)) {
		print_fail("failed to decode Base64 input");
		exit(-1);
	}

	int key_len_count = 5;
	int *key_lens = guess_key_lengths(raw_bytes, raw_len, key_len_count);
	if (!key_lens) {
		print_fail("failed to guess repeating xor key lengths");
		exit(-1);
	}

	float best_englishness = FLT_MAX;
	char *best_key = NULL;
	char *best_decrypted = NULL;
	for (int i = 0; i < key_len_count; i++) {
		char *likely_key = NULL;

		if (guess_key(raw_bytes, raw_len, key_lens[i], &likely_key) != 0) {
			print_fail("failed to guess repeating xor key");
			exit(-1);
		}

		char *decrypted = repeating_key_xor(raw_bytes, raw_len, likely_key, key_lens[i]);
		if (decrypted == NULL) {
			print_fail("failed to decrypt repeating xor");
			exit(-1);
		}

		float englishness = compute_englishness(decrypted, raw_len, ENGLISHNESS_CHECK_MONOGRAMS);
		if (englishness < best_englishness) {
			best_englishness = englishness;
			free(best_key);
			best_key = strdup(likely_key);
			free(best_decrypted);
			best_decrypted = strdup(decrypted);
		}

		free(decrypted);
		free(likely_key);
	}

	if (best_englishness == FLT_MAX) {
		print_fail("repeating xor: failed to find any English plaintext");
		exit(-1);
	}

	if (best_key == NULL || strcmp(best_key, "Terminator X: Bring the noise") != 0) {
		print_fail("repeating xor: guessed wrong key: %s", best_key);
		exit(-1);
	}

	size_t decrypted_size;
	char *decrypted_verify = load_buffer_from_file(argv[2], &decrypted_size);
	if (decrypted_verify == NULL) {
		print_fail("failed to open verify file %s", argv[2]);
		exit(-1);
	}

	if (strncmp(best_decrypted, decrypted_verify, decrypted_size) != 0) {
		print_fail("decryption for repeating xor failed: %s", best_decrypted);
		exit(-1);
	}

	print_success("decrypt repeating key xor OK");

	free(decrypted_verify);
	free(best_key);
	free(best_decrypted);
	free(key_lens);
	free(buf);
	free(raw_bytes);
	
	return 0;
}

#endif // TEST_REPEATING_KEY_XOR
