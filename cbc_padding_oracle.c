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

static bool generate_ciphertext(char **out_ciphertext, size_t *out_ciphertext_len, char **out_iv) {
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

	// We don't care about the plaintext (yet?) so drop it
	return aes_cbc(AES_CBC_OP_DECRYPT, ciphertext, ciphertext_len, iv, aes_key, BLOCKSIZE, NULL, NULL);
}

int main(int argc, char const *argv[])
{
	char *ciphertext = NULL;
	size_t ciphertext_len;
	char *iv = NULL;

	if (!generate_ciphertext(&ciphertext, &ciphertext_len, &iv)) {
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

	print_success("AES CBC padding oracle OK");

	free(ciphertext);
	free(tampered_ciphertext);
	free(iv);

	return 0;
}
