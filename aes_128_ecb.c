#include <CommonCrypto/CommonCrypto.h>
#include <stdio.h>
#include <stdbool.h>

#include "aes_128_ecb.h"
#include "utility.h"
#include "hex_to_base64.h"

int aes_128_ecb_encrypt(const char *plaintext, size_t plaintext_len, const char *key, size_t key_len, char **out_ciphertext, size_t *out_ciphertext_len)
{
	// Ciphertext will be at most one block (16 bytes) larger than the plaintext
	char *ciphertext = calloc(1, plaintext_len + 16);
	size_t ciphertext_len;
	CCCryptorStatus status = CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding | kCCOptionECBMode, key, key_len, NULL, plaintext, plaintext_len, ciphertext, plaintext_len + 16, &ciphertext_len);
	if (status != kCCSuccess) {
		free(ciphertext);
		fprintf(stderr, "failed to encrypt: %d\n", status);
		return -1;
	}

	if (out_ciphertext) {
		*out_ciphertext = ciphertext;
	} else {
		free(ciphertext);
	}

	if (out_ciphertext_len) {
		*out_ciphertext_len = ciphertext_len;
	}

	return 0;
}

int aes_128_ecb_decrypt(const char *ciphertext, size_t ciphertext_len, const char *key, size_t key_len, char **out_plaintext, size_t *out_plaintext_len)
{
	// Plaintext has to fit into ciphertext since we can only remove padding
	char *plaintext = calloc(1, ciphertext_len);
	size_t plaintext_len;
	CCCryptorStatus status = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding | kCCOptionECBMode, key, key_len, NULL, ciphertext, ciphertext_len, plaintext, ciphertext_len, &plaintext_len);
	if (status != kCCSuccess) {
		free(plaintext);
		fprintf(stderr, "failed to decrypt: %d\n", status);
		return -1;
	}

	if (out_plaintext) {
		*out_plaintext = plaintext;
	} else {
		free(plaintext);
	}

	if (out_plaintext_len) {
		*out_plaintext_len = plaintext_len;
	}

	return 0;
}

bool is_aes_128_ecb(const char *ciphertext, size_t ciphertext_len)
{
	size_t block_count = ciphertext_len / 16;
	for (size_t i = 0; i < block_count; i++) {
		for (size_t j = i + 1; j < block_count; j++) {
			if (memcmp(ciphertext + (i * 16), ciphertext + (j * 16), 16) == 0) {
				return true;
			}
		}
	}

	return false;
}

#if AES_128_ECB_TEST

int main(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "no input file for AES decrypt\n");
		exit(-1);
	}

	size_t encrypted_len;
	char *encrypted = load_buffer_from_file(argv[1], &encrypted_len);
	if (encrypted == NULL) {
		fprintf(stderr, "failed to open input file %s\n", argv[1]);
		exit(-1);
	}

	size_t raw_encrypted_len;
	char *raw_encrypted = base64_to_raw(encrypted, encrypted_len, &raw_encrypted_len);
	if (raw_encrypted == NULL) {
		fprintf(stderr, "failed to convert input to raw bytes\n");
		exit(-1);
	}

	char *plaintext = NULL;
	size_t plaintext_len;
	if (aes_128_ecb_decrypt(raw_encrypted, raw_encrypted_len, argv[2], strlen(argv[2]), &plaintext, &plaintext_len) != 0 || plaintext == NULL) {
		fprintf(stderr, "AES 128 ECB: failed to decrypt\n");
		exit(-1);
	}

	char *reencrypted = NULL;
	size_t reencrypted_len;
	if (aes_128_ecb_encrypt(plaintext, plaintext_len, argv[2], strlen(argv[2]), &reencrypted, &reencrypted_len) != 0 || reencrypted == NULL) {
		fprintf(stderr, "AES 128 ECB: failed to reencrypt\n");
		exit(-1);
	}

	if (strncmp(reencrypted, raw_encrypted, raw_encrypted_len) != 0) {
		fprintf(stderr, "AES 128 ECB: input and reencrypted don't match\n");
		exit(-1);
	}

	foreach_line_in_file(argv[3], ^(const char *line, size_t line_len, int index) {
		if (line[line_len - 1] == '\n') {
			line_len--;
		}
		size_t raw_len;
		char *raw = hex_to_raw(line, line_len, &raw_len);
		if (raw == NULL) {
			fprintf(stderr, "failed to convert hex to raw\n");
			exit(-1);
		}

		if (is_aes_128_ecb(raw, raw_len) && index != 132) {
			fprintf(stderr, "AES 128 ECB: detected wrong line (%d)\n", index);
		}
		free(raw);
	});

	printf("AES 128 CBC OK\n");

	free(reencrypted);
	free(plaintext);
	free(encrypted);
	free(raw_encrypted);

	return 0;
}

#endif