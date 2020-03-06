#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>

#include "aes_128_ecb.h"
#include "hex_to_base64.h"
#include "utility.h"
#include "xor_buffers.h"

static const size_t BLOCKSIZE = 16;

bool aes_ctr(const char *text, size_t text_len, const char *key, const char *nonce, char **out_transformed, size_t *out_transformed_len)
{
	bool success = false;

	/*
	 * For each block of plaintext, we must generate the corresponding keystream block and then XOR
	 * with that to get ciphertext--no padding needed! The key stream is created by AES encrypting a
	 * nonce block with the provided key.
	 * It appears there are several parameters in CTR informing how the nonce block is constructed,
	 * but here, as specified by the exercise, we will use 64 bits of unsigned LE nonce followed by
	 * 64 bits of LE block count.
	 */
	size_t block_count = text_len / BLOCKSIZE;
	if (text_len % BLOCKSIZE != 0) {
		block_count++;
	}

	uint64_t counter = 0;
	char counter_block[BLOCKSIZE];
	char *keystream = NULL;
	size_t keystream_len;
	char *transformed = calloc(1, text_len);
	if (transformed == NULL) {
		goto done;
	}

	for (size_t index = 0; index < block_count; index++) {
		memset(counter_block, 0, sizeof(counter_block));

		// Construct counter block. First, copy in nonce, little endian.
		for (size_t idx = 0; idx < BLOCKSIZE / 2; idx++) {
			counter_block[idx] = nonce[BLOCKSIZE / 2 - idx - 1];
		}

		// Copy in current counter value, little endian
		for (size_t idx = BLOCKSIZE / 2; idx < BLOCKSIZE; idx++) {
			counter_block[idx] = counter & (0xFFull << ((idx - BLOCKSIZE / 2) * 8));
		}

		// Encrypt counter block with key to get current block of keystream
		if (aes_128_ecb_encrypt(counter_block, sizeof(counter_block), key, BLOCKSIZE, &keystream, &keystream_len) != 0) {
			print_fail("failed to encrypt keystream");
			goto done;
		}

		if (keystream_len != BLOCKSIZE) {
			print_fail("unexpected keystream length %zu", keystream_len);
			goto done;
		}

		// XOR current keystream block with current text block
		size_t current_byte_index = index * BLOCKSIZE;
		// Truncate keystream if this is the last block and it is not aligned
		size_t block_len = current_byte_index + BLOCKSIZE <= text_len ? BLOCKSIZE : text_len - current_byte_index;
		xor_buffers(keystream, text + current_byte_index, transformed + current_byte_index, block_len);

		free(keystream);
		keystream = NULL;
		counter++;
	}

	if (out_transformed != NULL) {
		*out_transformed = transformed;
		transformed = NULL;
	}
	if (out_transformed_len != NULL) {
		*out_transformed_len = text_len;
	}

	success = true;
done:
	free(keystream);
	free(transformed);

	return success;
}

#if AES_CTR_TEST

int main()
{
	// Parameters provided by challenge 18. Note in particular all-zero nonce.
	const char *b64_ciphertext = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
	const char *key = "YELLOW SUBMARINE";
	const char nonce[BLOCKSIZE / 2] = {0};
	char *raw_ciphertext = NULL;
	size_t raw_ciphertext_len;

	if (!base64_to_raw(b64_ciphertext, strlen(b64_ciphertext), &raw_ciphertext, &raw_ciphertext_len)) {
		print_fail("AES CTR: failed to decode ciphertext from base64");
		exit(-1);
	}

	char *plaintext = NULL;
	size_t plaintext_len;
	if (!aes_ctr(raw_ciphertext, raw_ciphertext_len, key, nonce, &plaintext, &plaintext_len)) {
		print_fail("AES CTR: failed to decrypt ciphertext");
		exit(-1);
	}

	const char *real_plaintext = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ";
	if (strncmp(real_plaintext, plaintext, plaintext_len) != 0) {
		print_fail("AES CTR: decrypted text is wrong");
		dump_hex_label(stderr, "plaintext bytes", plaintext, plaintext_len);
		exit(-1);
	}

	// Roundtrip a few other messages with random nonces and keys
	for (int i = 0; i < 10; i++) {
		size_t message_len = arc4random_uniform(100) + 20;
		char curr_key[BLOCKSIZE];
		char curr_nonce[BLOCKSIZE / 2];
		char message[120]; // biggest possible message given arc4random_uniform params

		arc4random_buf(curr_key, sizeof(curr_key));
		arc4random_buf(curr_nonce, sizeof(curr_nonce));
		bzero(message, sizeof(message));
		arc4random_buf(message, message_len);

		char *ciphertext = NULL;
		size_t ciphertext_len;
		if (!aes_ctr(message, message_len, curr_key, curr_nonce, &ciphertext, &ciphertext_len)) {
			print_fail("AES CTR: failed to encrypt message");
			exit(-1);
		}

		if (ciphertext_len != message_len) {
			print_fail("AES CTR: unexpected ciphertext length %zu", ciphertext_len);
			exit(-1);
		}

		char *curr_plaintext = NULL;
		size_t curr_plaintext_len;
		if (!aes_ctr(ciphertext, ciphertext_len, curr_key, curr_nonce, &curr_plaintext, &curr_plaintext_len)) {
			print_fail("AES CTR: failed to decrypt message");
			exit(-1);
		}

		if (curr_plaintext_len != ciphertext_len) {
			print_fail("AES CTR: unexpected plaintext length %zu", curr_plaintext_len);
			exit(-1);
		}

		if (memcmp(curr_plaintext, message, curr_plaintext_len) != 0) {
			print_fail("AES CTR: unexpected plaintext");
			exit(-1);
		}
		free(curr_plaintext);
		free(ciphertext);
	}

	print_success("AES CTR OK");

	free(raw_ciphertext);
	free(plaintext);

	return 0;
}

#endif // AES_CTR_TEST
