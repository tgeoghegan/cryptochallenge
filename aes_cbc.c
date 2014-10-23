#include <stdbool.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes_cbc.h"
#include "aes_128_ecb.h"
#include "pkcs7_padding.h"
#include "xor_buffers.h"
#include "hex_to_base64.h"
#include "utility.h"

bool aes_cbc(aes_cbc_op_t op, const char *buffer, size_t buffer_len, const char *init_vector, const char *key, size_t key_len, char **out_buffer, size_t *out_buffer_len)
{
	bool success = false;

	if (op < AES_CBC_OP_ENCRYPT || op > AES_CBC_OP_DECRYPT) {
		fprintf(stderr, "invalid operation\n");
		goto out;
	}

	// Sanity check: if decrypting, the input should be padded to key_len == block size
	if (op == AES_CBC_OP_DECRYPT && buffer_len % key_len != 0) {
		fprintf(stderr, "decryption input size %zu not a multiple of block size %zu\n", buffer_len, key_len);
		goto out;
	}

	char *padded_buffer = NULL;
	size_t output_size;

	// If encrypting, we must pad
	if (op == AES_CBC_OP_ENCRYPT) {
		padded_buffer = pkcs7_pad_buffer(false, buffer, buffer_len, key_len, &output_size);
		if (padded_buffer == NULL) {
			fprintf(stderr, "failed to allocate padded buffer\n");
			goto out;
		}
	} else {
		// Useless copy, but allows unconditional free(3) at the end
		padded_buffer = malloc(buffer_len);
		if (padded_buffer == NULL) {
			fprintf(stderr, "failed to allocate buffer\n");
			goto out;
		}
		memcpy(padded_buffer, buffer, buffer_len);
		output_size = buffer_len;
	}

	char *output = calloc(1, output_size);
	if (output == NULL) {
		fprintf(stderr, "failed to allocate output buffer\n");
		goto out;
	}

	size_t block_count = output_size / key_len;
	for (size_t i = 0; i < block_count; i++) {
		char *output_block = NULL;
		if (op == AES_CBC_OP_ENCRYPT) {
			char *xored_buffer = malloc(key_len);
			xor_buffers(padded_buffer + (i * key_len), i == 0 ? init_vector : output + ((i - 1) * key_len), xored_buffer, key_len);
			if (xored_buffer == NULL) {
				fprintf(stderr, "failed to XOR plaintext block %zu\n", i);
				goto out;
			}

			size_t encrypted_block_len;
			int status = aes_128_ecb_encrypt(xored_buffer, key_len, key, key_len, &output_block, &encrypted_block_len);
			free(xored_buffer);
			if (status != 0) {
				fprintf(stderr, "failed to AES ECB encrypt block %zu\n", i);
				goto out;
			}
			if (encrypted_block_len != key_len) {
				fprintf(stderr, "block should not get padded during AES ECB encryption\n");
				free(output_block);
				goto out;
			}
		} else if (op == AES_CBC_OP_DECRYPT) {
			size_t decrypted_block_len;
			char *decrypted_block = NULL;
			int status = aes_128_ecb_decrypt(padded_buffer + (i * key_len), key_len, key, key_len, &decrypted_block, &decrypted_block_len);
			if (status != 0) {
				fprintf(stderr, "failed to AES CBC decrypt block %zu\n", i);
				goto out;
			}

			if (decrypted_block_len != key_len) {
				fprintf(stderr, "unexpected decrypted block size change during AES ECB decryption\n");
				free(decrypted_block);
				goto out;
			}

			output_block = malloc(key_len);
			const char *other_buffer = NULL;
			xor_buffers(decrypted_block, i == 0 ? init_vector : padded_buffer + ((i - 1)  * key_len), output_block, key_len);
			free(decrypted_block);
			if (output_block == NULL) {
				fprintf(stderr, "failed to XOR decrypted block %zu\n", i);
				free(output_block);
				goto out;
			}
		}

		memcpy(output + (i * key_len), output_block, key_len);
		free(output_block);
		output_block = NULL;
	}

	if (op == AES_CBC_OP_DECRYPT) {
		output_size = pkcs7_unpad_buffer(output, output_size);
	}

	if (out_buffer) {
		*out_buffer = output;
		output = NULL;
	}
	if (out_buffer_len) {
		*out_buffer_len = output_size;
	}

	success = true;
out:
	free(padded_buffer);
	free(output);

	return success;
}

#if AES_CBC_TEST

int main(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "AES CBC: bad arguments\n");
		exit(-1);
	}

	size_t base64_size;
	char *base64_buffer = load_buffer_from_file(argv[1], &base64_size);
	if (base64_buffer == NULL) {
		fprintf(stderr, "AES CBC: failed to load file %s\n", argv[1]);
		exit(-1);
	}

	size_t raw_encrypted_len;
	char *raw_encrypted = base64_to_raw(base64_buffer, base64_size, &raw_encrypted_len);
	if (raw_encrypted == NULL) {
		fprintf(stderr, "AES CBC: failed to convert base 64input to raw\n");
		exit(-1);
	}

	char *init_vector = malloc(16);
	bzero(init_vector, 16);

	char *decrypted = NULL;
	size_t decrypted_len;
	if (!aes_cbc(AES_CBC_OP_DECRYPT, raw_encrypted, raw_encrypted_len, init_vector, argv[2], strlen(argv[2]), &decrypted, &decrypted_len)) {
		fprintf(stderr, "AES CBC: failed to decrypt\n");
		exit(-1);
	}

	size_t expected_decrypt_len;
	char *expected_decrypt = load_buffer_from_file(argv[3], &expected_decrypt_len);
	if (expected_decrypt == NULL) {
		fprintf(stderr, "AES CBC: failed to load expected decrypt file %s\n", argv[3]);
		exit(-1);
	}

	size_t wrong = memcmp_where(decrypted, expected_decrypt, decrypted_len);
	if (wrong != -1) {
		fprintf(stderr, "AES CBC: decrypted wrong (%zu) %s\n", wrong, decrypted);
		exit(-1);
	}

	char *re_encrypted = NULL;
	size_t re_encrypted_len;
	if (!aes_cbc(AES_CBC_OP_ENCRYPT, decrypted, decrypted_len, init_vector, argv[2], strlen(argv[2]), &re_encrypted, &re_encrypted_len)) {
		fprintf(stderr, "AES CBC: failed to re-encrypt\n");
		exit(-1);
	}

	if (raw_encrypted_len != re_encrypted_len) {
		fprintf(stderr, "AES CBC: mismatch between encrypted lengths %zu - %zu\n", raw_encrypted_len, re_encrypted_len);
		exit(-1);
	}
	size_t psn = memcmp_where(raw_encrypted, re_encrypted, raw_encrypted_len);
	if (psn != -1) {
		fprintf(stderr, "AES CBC: mismatch between ciphertexts at %zu\n", psn);
		exit(-1);
	}
	
	char *re_decrypted = NULL;
	size_t re_decrypted_len;
	if (!aes_cbc(AES_CBC_OP_DECRYPT, re_encrypted, re_encrypted_len, init_vector, argv[2], strlen(argv[2]), &re_decrypted, &re_decrypted_len)) {
		fprintf(stderr, "AES CBC: failed to re-decrypt\n");
		exit(-1);
	}

	wrong = memcmp_where(decrypted, re_decrypted, re_decrypted_len);
	if (wrong != -1) {
		fprintf(stderr, "AES CBC: re-decryption wrong (%zu) %s\n", wrong, re_decrypted);
		exit(-1);
	}

	printf("AES CBC OK\n");

	free(expected_decrypt);
	free(re_encrypted);
	free(base64_buffer);
	free(raw_encrypted);
	free(decrypted);

	return 0;
}

#endif // AES_CBC_TEST
