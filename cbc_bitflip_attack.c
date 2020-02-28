#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes_128_ecb.h"
#include "aes_cbc.h"
#include "pkcs7_padding.h"
#include "utility.h"

static const char *PREFIX = "comment1=cooking%20MCs;userdata=";
static const char *SUFFIX = ";comment2=%20like%20a%20pound%20of%20bacon";
static const char *ADMIN_STRING = ";admin=true;";

/*
 * Takes the provided userdata, adds the prefix and suffix above to either end, encrypts the
 * resulting string under the provided key (which is assumed to be 16 bytes long) and places the
 * result in out_encrypted. A 16 byte IV is also created and passed to the caller in out_iv.
 */
bool encrypt_userdata(bool force_admin, const char *userdata, size_t userdata_len, const char *key, 
	char **out_encrypted, size_t *out_encrypted_len, char **out_iv)
{
	bool success = false;
	char *plaintext = NULL;
	size_t blocksize = 16;
	char *iv = NULL;

	// The challenge says to 'quote out the ";" and "=" characters.'. It's not really clear to me
	// what they mean by that, but I think the point is to rule out an attack where the user
	// provided data can just contain ;admin=true;. I'll achieve that by rejecting any userdata
	// containing those characters.
	for (size_t i = 0; i < userdata_len; i++) {
		if (userdata[i] == ';' || userdata[i] == '=') {
			goto done;
		}
	}

	size_t plaintext_len = strlen(PREFIX) + userdata_len + strlen(PREFIX);
	if (force_admin) {
		plaintext_len += strlen(ADMIN_STRING);
	}
	plaintext = calloc(1, plaintext_len);
	if (plaintext == NULL) {
		goto done;
	}

	char *dest = plaintext;
	memcpy(dest, PREFIX, strlen(PREFIX));
	dest += strlen(PREFIX);
	memcpy(dest, userdata, userdata_len);
	dest += userdata_len;
	if (force_admin) {
		memcpy(dest, ADMIN_STRING, strlen(ADMIN_STRING) - 1);
		dest += strlen(ADMIN_STRING) - 1;
	}
	memcpy(dest, SUFFIX, strlen(SUFFIX));

	printf("plaintext is %s\n", plaintext);

	iv = malloc(blocksize);
	if (iv == NULL) {
		goto done;
	}
	arc4random_buf(iv, blocksize);

	if (!aes_cbc(AES_CBC_OP_ENCRYPT, plaintext, plaintext_len, iv, key, blocksize, 
			out_encrypted, out_encrypted_len)) {
		goto done;
	}

	if (out_iv != NULL) {
		*out_iv = iv;
		iv = NULL;
	}

	success = true;
done:
	free(plaintext);
	free(iv);

	return success;

}

bool is_encrypted_userdata_admin(const char *encrypted, size_t encrypted_len, const char *key,
	const char *iv) {
	bool success = false;
	char *plaintext = NULL;
	size_t plaintext_len;

	if (!aes_cbc(AES_CBC_OP_DECRYPT, encrypted, encrypted_len, iv, key, 16, &plaintext, &plaintext_len)) {
		goto done;
	}

	// strnstr returns NULL if needle doesn't occur in haystack
	if (strnstr(plaintext, ADMIN_STRING, plaintext_len) == NULL) {
		goto done;
	}

	success = true;
done:
	free(plaintext);

	return success;
}

int main(int argc, char const *argv[])
{
	char *key = NULL;

	key = aes_generate_key();
	if (key == NULL) {
		print_fail("CBC bitflip: failed to generate key");
		exit(-1);
	}

	const char *userdata = "hello";
	char *encrypted = NULL;
	size_t encrypted_len;
	char *iv = NULL;

	if (!encrypt_userdata(false, userdata, strlen(userdata), key, &encrypted, &encrypted_len, &iv)) {
		print_fail("CBC bitflip: failed to encrypt userdata");
		exit(-1);
	}

	if (is_encrypted_userdata_admin(encrypted, encrypted_len, key, iv)) {
		print_fail("CBC bitflip: profile misidentified as admin");
	}

	free(encrypted);
	encrypted = NULL;

	if (!encrypt_userdata(true, userdata, strlen(userdata), key, &encrypted, &encrypted_len, &iv)) {
		print_fail("CBC bitflip: failed to encrypt userdata");
		exit(-1);
	}

	if (!is_encrypted_userdata_admin(encrypted, encrypted_len, key, iv)) {
		print_fail("CBC bitflip: profile misidentified as non-admin");
	}

	free(encrypted);
	encrypted = NULL;

	if (encrypt_userdata(false, ADMIN_STRING, strlen(ADMIN_STRING), key, &encrypted, &encrypted_len, &iv)) {
		print_fail("CBC bitflip: bogus userdata should be rejected");
		exit(-1);
	}


	print_success("CBC bitflip OK!");

	free(key);
	free(encrypted);
	free(iv);

	return 0;
}