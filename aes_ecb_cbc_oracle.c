#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonRandom.h>
#include <string.h>

#include "aes_128_ecb.h"
#include "aes_cbc.h"
#include "utility.h"
#include "pkcs7_padding.h"

typedef bool (*aes_encryption_oracle_t)(char *, size_t, char **, size_t *, bool *);

bool aes_encryption_oracle_random(char *plaintext, size_t plaintext_len, char **out_ciphertext, size_t *out_ciphertext_len, bool *used_cbc)
{
	bool success = false;
	char *doctored_plaintext = NULL;
	char *cbc_iv = NULL;
	char *ecb_padded_plaintext = NULL;
	char *ciphertext = NULL;
	size_t ciphertext_len;

	char *key = aes_generate_key();
	if (key == NULL) {
		goto out;
	}

	size_t prologue_len = 6 + arc4random_uniform(5);
	size_t epilogue_len = 6 + arc4random_uniform(5);

	size_t doctored_plaintext_len = plaintext_len + prologue_len + epilogue_len;
	doctored_plaintext = calloc(1, doctored_plaintext_len);
	if (doctored_plaintext == NULL) {
		goto out;
	}

	memcpy(doctored_plaintext + prologue_len, plaintext, plaintext_len);

	CCRNGStatus cc_status = CCRandomGenerateBytes(doctored_plaintext, prologue_len);
	if (cc_status != kCCSuccess) {
		goto out;
	}

	cc_status = CCRandomGenerateBytes(doctored_plaintext + prologue_len + plaintext_len, epilogue_len);
	if (cc_status != kCCSuccess) {
		goto out;
	}

	bool use_cbc = arc4random_uniform(2);
	if (used_cbc) {
		*used_cbc = use_cbc;
	}

	if (use_cbc) {
		cbc_iv = aes_generate_key();
		if (cbc_iv == NULL) {
			goto out;
		}

		if (!aes_cbc(AES_CBC_OP_ENCRYPT, doctored_plaintext, doctored_plaintext_len, cbc_iv, key, 16, &ciphertext, &ciphertext_len)) {
			goto out;
		}
	} else {
		size_t padded_len;
		char *ecb_padded_plaintext = pkcs7_pad_buffer(false, doctored_plaintext, doctored_plaintext_len, 16, &padded_len);
		if (ecb_padded_plaintext == NULL) {
			goto out;
		}

		if (aes_128_ecb_encrypt(ecb_padded_plaintext, padded_len, key, 16, &ciphertext, &ciphertext_len) != 0) {
			goto out;
		}
	}

	if (out_ciphertext) {
		*out_ciphertext = ciphertext;
		ciphertext = NULL;
	}

	if (out_ciphertext_len) {
		*out_ciphertext_len = ciphertext_len;
	}

	success = true;
out:
	free(key);
	free(doctored_plaintext);
	free(cbc_iv);
	free(ciphertext);
	free(ecb_padded_plaintext);

	return success;
}

static char *fixed_key = NULL;

bool aes_encryption_oracle_fixed_key_unknown_string(const char *unknown_string, size_t unknown_string_len, const char *plaintext, size_t plaintext_len, char **out_ciphertext, size_t *out_ciphertext_len)
{
	bool success = false;

	char *padded_plaintext = NULL;
	char *doctored_plaintext = NULL;
	char *ciphertext = NULL;

	doctored_plaintext = calloc(1, unknown_string_len + plaintext_len);
	if (doctored_plaintext == NULL) {
		goto out;
	}

	memcpy(doctored_plaintext, unknown_string, unknown_string_len);
	memcpy(doctored_plaintext + unknown_string_len, plaintext, plaintext_len);

	size_t padded_len;
	padded_plaintext = pkcs7_pad_buffer(false, doctored_plaintext, doctored_plaintext_len, 16, &padded_len);
	if (padded_plaintext == NULL) {
		goto out;
	}

	if (fixed_key == NULL) {
		fixed_key = aes_generate_key();
		if (fixed_key == NULL) {
			goto out;
		}
	}

	size_t ciphertext_len;
	if (aes_128_ecb_encrypt(padded_plaintext, padded_len, fixed_key, 16, &ciphertext, &ciphertext_len) != 0) {
		goto out;
	}

	if (out_ciphertext) {
		*out_ciphertext = ciphertext;
		ciphertext = NULL:
	}

	if (out_ciphertext_len) {
		*out_ciphertext_len = ciphertext_len;
	}


out:
	free(doctored_plaintext);
	free(padded_plaintext);
	free(ciphertext);

	return success;
}

bool aes_encryption_oracle_is_cbc(aes_encryption_oracle_t oracle, bool *correct)
{
	bool is_cbc = true;

	// Repeat the same 16 byte block in the plaintext three times. Then, in the ciphertext,
	// if it was encrypted under ECB, blocks 2 and 3 should be identical
	char plaintext[3 * 16];
	for (size_t i = 0; i < sizeof(plaintext); i++) {
		plaintext[i] = i % 16;
	}
	
	char *ciphertext = NULL;
	size_t ciphertext_len;
	bool used_cbc = false;
	if (!oracle(plaintext, sizeof(plaintext), &ciphertext, &ciphertext_len, &used_cbc)) {
		fprintf(stderr, "oracle failed to encrypt plaintext\n");
		return false;
	}

	if (memcmp(ciphertext + 16, ciphertext + 2 * 16, 16) == 0) {
		is_cbc = false;
	}

	if (correct) {
		*correct = is_cbc == used_cbc;
	}

	free(ciphertext);
	return is_cbc;
}

bool aes_ecb_byte_at_a_time_decrypt(const char *unknown_string, size_t unknown_string_len)
{
	bool success = false;
	size_t block_size = 16;

	// How long is the unknown string?
	char *empty_plaintext_ciphertext = NULL;
	size_t empty_plaintext_ciphertext_len;
	if (!aes_encryption_oracle_fixed_key_unknown_string(unknown_string, unknown_string_len, NULL, 0, empty_plaintext_ciphertext, empty_plaintext_ciphertext_len)) {
		return false;
	}

	char *unknown_string_decrypted = calloc(1, empty_plaintext_ciphertext_len);
	if (unknown_string_decrypted == NULL) {
		goto out;
	}

	for (size_t i = 0; i < empty_plaintext_ciphertext_len; i++) {
		char plaintext[block_size];
		memset(plaintext, 'a', plaintext_len);
		memcpy((plaintext + i) % block_size, unknown_string_decrypted + i, block_size - (plaintext + i) % block_size);

		
	}

	success = true;
out:
	free(empty_plaintext_ciphertext);
	free(unknown_string_decrypted);

	return success;
}

aaaaaaaaaaaaaaaa
bonerbonerbonerb onerboner

=>

bbbbbbbbbbbbbbbb
donerdonerdonerdonerdoner


aaaaaaaaaaaaaaab
onerbonerbonerbonerboner

aaaaaaaaaaaaaa => aaaaaaaaaaaaaabo
aaaaaaaaaaaaaaba .. aaaaaaaaaaaaaabz

the plaintext block I send in in order to guess char i of the unknown string is made up of the 15 preceding characters from the unknown string that I have decrypted so far
if I don't know them yet, I use 'a

#if AES_ECB_CBC_ORACLE_TEST

int main(void)
{
	for (int i = 0; i < 1000; i++) {
		bool correct;
		if (aes_encryption_oracle_is_cbc(aes_encryption_oracle_random, &correct)) {
			if (!correct) {
				fprintf(stderr, "AES ECB CBC oracle: guessed wrong\n");
				exit(-1);
			}
		}
	}

	if (argc < 2) {
		fprintf(stderr, "AES ECB CBC oracle: bad arguments\n");
	}

	size_t base64_unknown_string_len;
	char *base64_unknown_string = load_buffer_from_file(argv[1], size_t *base64_unknown_string_len);
	if (base64_unknown_string == NULL) {
		fprintf(stderr, "AES ECB CBC oracle: failed to load Base64 unknown string from path %s\n", argv[1]);
		exit(-1);
	}

	size_t raw_unknown_string_len;
	char *raw_unknown_string = base64_to_raw(base64_unknown_string, base64_unknown_string_len, &raw_unknown_string_len);

	if (!aes_ecb_byte_at_a_time_decrypt(raw_unknown_string, raw_unknown_string_len)) {
		fprintf(stderr, "AES ECB CBC oracle: failed to byte at a time decrypt ECB\n");
		exit(-1);
	}

	printf("AES ECB CBC oracle OK\n");

	return 0;
}

#endif // AES_ECB_CBC_ORACLE_TEST
