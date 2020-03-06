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
static bool encrypt_userdata(bool force_admin, const char *userdata, size_t userdata_len, const char *key, 
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

	iv = malloc(blocksize);
	if (iv == NULL) {
		goto done;
	}
	arc4random_buf(iv, blocksize);

	if (aes_cbc(AES_CBC_OP_ENCRYPT, plaintext, plaintext_len, iv, key, blocksize,
			out_encrypted, out_encrypted_len) != AES_CBC_ERROR_NONE) {
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

static bool is_encrypted_userdata_admin(const char *encrypted, size_t encrypted_len, const char *key,
	const char *iv) {
	bool success = false;
	char *plaintext = NULL;
	size_t plaintext_len;

	if (aes_cbc(AES_CBC_OP_DECRYPT, encrypted, encrypted_len, iv, key, 16, &plaintext, &plaintext_len)
		!= AES_CBC_ERROR_NONE) {
		goto done;
	}

	// Inefficiently crawl along the plaintext doing memcmps, because strnstr doesn't quite do what
	// we want. Tampering with ciphertext will cause the corresponding block of plaintext to be
	// totally garbled, which might insert NUL characters into the plaintext. That will cause
	// strnstr to give up regardless of the length passed to it (which is fair, as it's defined to
	// work on C strings). We laboriously use memcmp to ensure the entire string gets checked.
	for (size_t i = 0; i < plaintext_len - strlen(ADMIN_STRING); i++) {
		if (memcmp(plaintext + i, ADMIN_STRING, strlen(ADMIN_STRING)) == 0) {
			success = true;
			break;
		}
	}

done:
	free(plaintext);

	return success;
}

static bool forge_admin_profile(void)
{
	bool success = false;
	char *encrypted = NULL;
	char *key = NULL;
	char *iv = NULL;

	key = aes_generate_key();
	if (key == NULL) {
		print_fail("CBC bitflip: failed to generate key");
		goto done;
	}

	/*
	 * We are performing a CBC bitflip attack. This depends first and foremost on the fact that CBC
	 * is not an authenticated mode so we can tamper with the ciphertext. Beyond that, it's possible
	 * because of how CBC decryption works: after decrypting block n, the ciphertext of block n - 1
	 * is XORed in. Since we control the ciphertext, that means we can tamper with bits in block
	 * n - 1 and then write whatever bits we want in the next block. Tampering with ciphertext does
	 * mean that the block we tamper with will decrypt to garbage, but we can construct our attacker
	 * provided userdata to make sure that the corrupted block only contains userdata, which
	 * hopefully wouldn't be checked by the server we're attacking. Specifically, let's construct a
	 * userdata of "aaaaaaaaaaaaaaaaaaaaa:admin<true". This will yield a plaintext:
	 * 
	 * comment1=cooking
	 * %20MCs;userdata=
	 * aaaaaaaaaaaaaaaa
	 * aaaaa:admin<true
 	 * ;comment2=%20lik
	 * e%20a%20pound%20
	 * of%20bacon
	 *
	 * ASCII : and < are one less than ; and =, respectively, so if we make sure the corresponding
	 * bits in the previous ciphertext block are set, then the CBC decryption will rewrite us into
	 * admins. Frankly much simpler than the previous ECB exercises! Mind you I don't know how we
	 * would solve this if we didn't know the length of the prefix and suffix strings. The tricks we
	 * used in ECB wouldn't work as blocks don't encrypt deterministically in CBC.
	 */
	const char *userdata = "aaaaaaaaaaaaaaaaaaaaa:admin<true";
	size_t encrypted_len;

	if (!encrypt_userdata(false, userdata, strlen(userdata), key, &encrypted, &encrypted_len, &iv)) {
		print_fail("CBC bitflip: failed to encrypt userdata");
		exit(-1);
	}

	size_t colon_index = strlen(PREFIX) + 5;
	encrypted[colon_index] = encrypted[colon_index] ^ 1;
	size_t opening_angle_bracket_index = strlen(PREFIX) + 11;
	encrypted[opening_angle_bracket_index] = encrypted[opening_angle_bracket_index] ^ 1;

	if (!is_encrypted_userdata_admin(encrypted, encrypted_len, key, iv)) {
		print_fail("CBC bitflip: tampered ciphertext did not decrypt to admin profile");
	}

	success = true;
done:
	free(key);
	free(encrypted);
	free(iv);

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

	const char *userdata = "aaaaaaaaaaaaaaaahello";
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
	free(iv);
	iv = NULL;

	if (!encrypt_userdata(true, userdata, strlen(userdata), key, &encrypted, &encrypted_len, &iv)) {
		print_fail("CBC bitflip: failed to encrypt userdata");
		exit(-1);
	}

	if (!is_encrypted_userdata_admin(encrypted, encrypted_len, key, iv)) {
		print_fail("CBC bitflip: profile misidentified as non-admin");
	}

	free(encrypted);
	encrypted = NULL;
	free(iv);
	iv = NULL;

	if (encrypt_userdata(false, ADMIN_STRING, strlen(ADMIN_STRING), key, &encrypted, &encrypted_len, &iv)) {
		print_fail("CBC bitflip: bogus userdata should be rejected");
		exit(-1);
	}

	if (!forge_admin_profile()) {
		print_fail("CBC bitflip: failed to forge admin profile");
		exit(-1);
	}


	print_success("CBC bitflip OK!");

	free(key);
	free(encrypted);
	free(iv);

	return 0;
}
