#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes_128_ecb.h"
#include "aes_cbc.h"
#include "hex_to_base64.h"
#include "utility.h"

static const char *MESSAGE_STRINGS[] = {
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
};

static const size_t BLOCKSIZE = 16;

static char *aes_key = NULL;

static bool generate_ciphertext(char **out_ciphertext, size_t *out_ciphertext_len, char **out_iv, size_t *out_string_index) {
	bool success = false;
	char *decoded_message = NULL;
	char *iv = NULL;

	if (aes_key == NULL) {
		aes_key = aes_generate_key();
		if (aes_key == NULL) {
			goto done;
		}
	}

	// Pick one of the prefix strings
	size_t message_index = arc4random_uniform(sizeof(MESSAGE_STRINGS) / sizeof(MESSAGE_STRINGS[0]));

	if (out_string_index != NULL) {
		*out_string_index = message_index;
	}

	// The challenge isn't clear about this but I assume the string should be decoded from base64
	// before encryption
	size_t message_length;
	// strlen is naughty but in this case we can convince ourselves all the strings we might pass in
	// are safely NUL-terminated
	if (!base64_to_raw(MESSAGE_STRINGS[message_index], strlen(MESSAGE_STRINGS[message_index]),
		&decoded_message, &message_length)) {
		goto done;
	}

	iv = malloc(BLOCKSIZE);
	if (iv == NULL) {
		goto done;
	}
	arc4random_buf(iv, BLOCKSIZE);

	if (aes_cbc(AES_CBC_OP_ENCRYPT, decoded_message, message_length, iv, aes_key, BLOCKSIZE, 
			out_ciphertext, out_ciphertext_len) != AES_CBC_ERROR_NONE) {
		goto done;
	}

	if (out_iv != NULL) {
		*out_iv = iv;
		iv = NULL;
	}

	success = true;
done:
	free(decoded_message);
	free(iv);

	return success;
}

// It's crude to return aes_cbc_error_t here, but it allows us to distinguish between incorrect
// padding and other failures (i.e. failure to allocate) without defining another enum for some toy
// code.
static aes_cbc_error_t validate_padding(const char *ciphertext, size_t ciphertext_len, const char *iv)
{
	if (aes_key == NULL) {
		return AES_CBC_ERROR_MISC;
	}

	// We don't care about the plaintext so drop it
	return aes_cbc(AES_CBC_OP_DECRYPT, ciphertext, ciphertext_len, iv, aes_key, BLOCKSIZE, NULL, NULL);
}

int main(int argc, char const *argv[])
{
	char *ciphertext = NULL;
	size_t ciphertext_len;
	char *iv = NULL;
	size_t message_index;

	if (!generate_ciphertext(&ciphertext, &ciphertext_len, &iv, &message_index)) {
		print_fail("AES CBC padding oracle: failed to encrypt");
		exit(-1);
	}

	if (validate_padding(ciphertext, ciphertext_len, iv) != AES_CBC_ERROR_NONE) {
		print_fail("AES CBC padding oracle: failed to validate correct padding");
		exit(-1);
	}

	// Verify bad padding is rejected
	char *tampered_ciphertext = malloc(ciphertext_len);
	if (tampered_ciphertext == NULL) {
		print_fail("AES CBC padding oracle: failed to allocate");
		exit(-1);
	}

	memcpy(tampered_ciphertext, ciphertext, ciphertext_len);

	tampered_ciphertext[ciphertext_len - BLOCKSIZE] = ciphertext[ciphertext_len - BLOCKSIZE] ^ 1;

	aes_cbc_error_t xored_with_1 = validate_padding(tampered_ciphertext, ciphertext_len, iv);

	tampered_ciphertext[ciphertext_len - BLOCKSIZE] = ciphertext[ciphertext_len - BLOCKSIZE] ^ 2;

	aes_cbc_error_t xored_with_2 = validate_padding(tampered_ciphertext, ciphertext_len, iv);

	// We might get unlucky and have one of the two accidentally yield valid padding but at least
	// one must yield bad padding
	if (xored_with_1 == AES_CBC_ERROR_NONE && xored_with_2 == AES_CBC_ERROR_NONE) {
		print_fail("AES CBC padding oracle: failed to reject bad padding");
	}

	/*
	 * Now the oracle attack. We have a padding oracle, which means we can tell when an arbitrary
	 * ciphertext decrypts to some plaintext that has correct padding. Let's say we have a message
	 * of a single block C of ciphertext, CBC encrypted using an initialization vector IV. Let I be
	 * the AES block decryption of C, i.e. the intermediate text before being XORed iwth the IV to
	 * produce the true plaintext, P. Finally let C[n] denote the nth byte of block C.
	 * We can construct an artificial IV (called IV') with guess values at IV'[16] in order to
	 * yield a modified plaintext P' with some target value P'[16]. We will know P'[16] is 0x01 if
	 * we get AES_CBC_ERROR_NONE back from the decryption/padding oracle, as that one byte sequence
	 * is valid PKCS#7 padding. Now, we know that:
	 *
	 * 		I[16] ^ IV'[16] = 0x01
	 *
	 * and so
	 *
	 *		I[16] = IV'[16] ^ 0x01
	 *
	 * and by the definition of CBC,
	 *
	 *		P[16] = I[16] ^ IV[16]
	 *
	 * Since we attack one character at a time, there are only 256 possible guesses for each step,
	 * which is easy to brute force.
	 * To get Pk[15], we construct an IV' such that we get a plaintext P' whose last two bytes are
	 * [0x02, 0x02]. We do this by setting IV'[16] to I[16] ^ 0x02, which we can do as we obtained
	 * I[16] in the previous step. We can continue this way all the way down the block.
	 * We can attack CBC encrypted messages of arbitrary lengths in this manner: we can simply
	 * extract the current target block from the real ciphertext and feed that with our crafted IVs
	 * into the decryption/padding oracle. In the example above, we computer P[16] = I[16] ^ IV[16],
	 * but when attacking a message longer than one block, we use the block of ciphertext preceding
	 * the currently targeted block of plaintext, unless we are attacking the first block, in which
	 * case we use the IV.
	 */
	char *plaintext = calloc(1, ciphertext_len + 1);
	char *intermediate = calloc(1, ciphertext_len);
	if (plaintext == NULL || intermediate == NULL) {
		print_fail("AES CBC padding oracle: allocation failed");
		exit(-1);
	}
	for (size_t i = ciphertext_len; i > 0; i--) {
		size_t target_index = i - 1;
		char *target_block = ciphertext + (target_index / BLOCKSIZE * BLOCKSIZE);
		char fake_iv[BLOCKSIZE] = {};
		size_t tamper_index = target_index % BLOCKSIZE;
		unsigned char target_padding_value = BLOCKSIZE - (target_index % BLOCKSIZE);

		// Fill remainder of fake IV with values chosen based on intermediate text computed so far
		// to yield the padding we want
		for (size_t j = tamper_index + 1; j < BLOCKSIZE; j++) {
			fake_iv[j] = intermediate[target_index + j - tamper_index] ^ target_padding_value;
		}

		// Iterate over guesses
		bool guessed_padding = false;
		for (unsigned char tamper = 0; tamper <= UCHAR_MAX; tamper++) {
			fake_iv[tamper_index] = tamper;

			aes_cbc_error_t error = validate_padding(target_block, BLOCKSIZE, fake_iv);
			if (error == AES_CBC_ERROR_BAD_PADDING) {
				continue;
			}
			if (error != AES_CBC_ERROR_NONE) {
				print_fail("AES CBC padding oracle: unexpected error %d", error);
				exit(-1);
			}
			guessed_padding = true;
			intermediate[target_index] = tamper ^ target_padding_value;
			char prev = target_index >= BLOCKSIZE
				? ciphertext[target_index - BLOCKSIZE] : iv[target_index];
			plaintext[target_index] = intermediate[target_index] ^ prev;

			break;
		}

		if (!guessed_padding) {
			print_fail("AES CBC padding oracle: failed to guess padding at index %zu", target_index);
			exit(-1);
		}
	}

	char *decoded_message = NULL;
	size_t decoded_message_len;
	if (!base64_to_raw(MESSAGE_STRINGS[message_index], strlen(MESSAGE_STRINGS[message_index]), &decoded_message, &decoded_message_len)) {
		print_fail("AES CBC padding oracle: failed to decode message");
		exit(-1);
	}

	if (strncmp(decoded_message, plaintext, decoded_message_len) != 0) {
		print_fail("AES CBC padding oracle: unexpected plaintext %s\n wanted %s\n", plaintext, MESSAGE_STRINGS[message_index]);
		exit(-1);
	}

	print_success("AES CBC padding oracle OK");

	free(ciphertext);
	free(tampered_ciphertext);
	free(iv);
	free(plaintext);
	free(intermediate);

	return 0;
}
