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

#if AES_ECB_CBC_ORACLE_TEST

int main(void)
{
	for (int i = 0; i < 1000; i++) {
		bool correct;
		if (aes_encryption_oracle_is_cbc(aes_encryption_oracle_random, &correct)) {
			if (!correct) {
				fprintf(stderr, "AES ECB CBC oracle: guessed wrong\n");
			}
		}
	}

	printf("AES ECB CBC oracle OK\n");

	return 0;
}

#endif // AES_ECB_CBC_ORACLE_TEST
