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
#include "hex_to_base64.h"

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

bool aes_ecb_encryption_oracle(char *plaintext, size_t plaintext_len, char **out_ciphertext, size_t *out_ciphertext_len, bool *used_cbc)
{
	bool success = false;
	char *padded_plaintext = NULL;
	size_t padded_len;
	char *ciphertext = NULL;
	size_t ciphertext_len;

	padded_plaintext = pkcs7_pad_buffer(false, plaintext, plaintext_len, 16, &padded_len);
	if (padded_plaintext == NULL) {
		goto out;
	}
	
	if (fixed_key == NULL) {
		fixed_key = aes_generate_key();
		if (fixed_key == NULL) {
			goto out;
		}
	}

	if (aes_128_ecb_encrypt(padded_plaintext, padded_len, fixed_key, 16, &ciphertext, &ciphertext_len) != 0)  {
		goto out;
	}

	if (used_cbc) {
		*used_cbc = false;
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
	free(padded_plaintext);

	return success;
}

bool aes_encryption_oracle_fixed_key_unknown_string(const char *unknown_string, size_t unknown_string_len,
	const char *plaintext, size_t plaintext_len, char **out_ciphertext, size_t *out_ciphertext_len)
{
	bool success = false;

	char *doctored_plaintext = NULL;
	size_t doctored_plaintext_len = plaintext_len + unknown_string_len;
	char *ciphertext = NULL;

	doctored_plaintext = calloc(1, doctored_plaintext_len);
	if (doctored_plaintext == NULL) {
		print_fail("failed to allocate doctored plaintext");
		goto out;
	}

	memcpy(doctored_plaintext, plaintext, plaintext_len);
	memcpy(doctored_plaintext + plaintext_len, unknown_string, unknown_string_len);

	size_t ciphertext_len;
	if (!aes_ecb_encryption_oracle(doctored_plaintext, doctored_plaintext_len, &ciphertext, &ciphertext_len, NULL)) {
		print_fail("failed to encrypt doctored plaintext");
		goto out;
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
	free(doctored_plaintext);
	free(ciphertext);

	return success;
}

/*
 * Random prefix string for use in the challenge 14 ECB oracle. Declared static as we will lazily
 * initialize it and use a fixed random string for each individual exercise.
 */
static char *random_prefix = NULL;
static size_t random_prefix_len = 0;

/*
 * ECB oracle for challenge 14. Here we construct a plaintext like this:
 * random-prefix || plaintext || unknown_string
 * random prefix is a string of random  printable characters whose length is random (though capped
 * at 110 characters to facilitate debugging in hex dumps). plaintext is the "attacker" controlled
 * plaintext, and unknown_string is the fixed target of the byte-at-a-time ECB decryption attack.
 */
bool aes_encryption_oracle_fixed_key_unknown_string_random_prefix(const char *unknown_string, size_t unknown_string_len,
	const char *plaintext, size_t plaintext_len, char **out_ciphertext, size_t *out_ciphertext_len)
{
	bool success = false;
	char *doctored_plaintext = NULL;

	if (random_prefix == NULL) {
		random_prefix_len = arc4random_uniform(100) + 10;
		random_prefix = calloc(1, random_prefix_len + 1);
		if (random_prefix == NULL) {
			goto done;
		}

		generate_random_string(random_prefix, random_prefix_len);
		printf("cheat: random prefix is %zu long\n", random_prefix_len);
	}

	size_t doctored_plaintext_len = plaintext_len + random_prefix_len;

	doctored_plaintext = calloc(1, doctored_plaintext_len);
	if (doctored_plaintext == NULL) {
		print_fail("failed to allocate doctored plaintext");
		goto done;
	}

	memcpy(doctored_plaintext, random_prefix, random_prefix_len);
	memcpy(doctored_plaintext + random_prefix_len, plaintext, plaintext_len);

	success = aes_encryption_oracle_fixed_key_unknown_string(unknown_string, unknown_string_len,
		doctored_plaintext, doctored_plaintext_len, out_ciphertext, out_ciphertext_len);

done:
	free(doctored_plaintext);

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
		print_fail("oracle failed to encrypt plaintext");
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
	char *ciphertext = NULL;
	size_t blocksize = 16;
	char plaintext[blocksize];
	memset(plaintext, 'a', blocksize);
	char *unknown_string_guess = NULL;

	if (unknown_string == NULL || unknown_string_len == 0) {
		print_fail("no unknown string");
		goto out;
	}

	// Ensure ECB is in use
	if (aes_encryption_oracle_is_cbc(aes_ecb_encryption_oracle, NULL)) {
		print_fail("AES ECB byte at a time: oracle is not ECB");
		goto out;
	}

	// Figure out length of unknown string. Just encrypting it yields the padded
	// length, so we have to encrypt a sequence of controlled plaintexts of up
	// to blocksize bytes. The first time that the ciphertext gets bigger than
	// the ciphertext produced by the bare unknown string, we have found the
	// amount of padding needed for the unknown string and so we know how many
	// bytes short of a block the unknown string is. That then allows us to
	// compute the unknown string's length from the length of the ciphertext
	// that the unknown string alone yields.
	// Of course this is just unknown_string_len but the exercise is worthwhile.
	size_t bare_unknown_string_ciphertext_len;
	size_t plaintext_len_guess;
	for (plaintext_len_guess = 0; plaintext_len_guess < blocksize; plaintext_len_guess++) {
		size_t ciphertext_len;
		if (!aes_encryption_oracle_fixed_key_unknown_string(unknown_string, unknown_string_len, plaintext, plaintext_len_guess, &ciphertext, &ciphertext_len)) {
			print_fail("AES ECB byte at a time: failed to encrypt string");
			goto out;
		}

		if (plaintext_len_guess == 0) {
			bare_unknown_string_ciphertext_len = ciphertext_len;
		}

		if (ciphertext_len > bare_unknown_string_ciphertext_len) {
			break;
		}
	}

	size_t unknown_string_len_guess = bare_unknown_string_ciphertext_len - (plaintext_len_guess - 1);

	if (unknown_string_len_guess != unknown_string_len) {
		print_fail("AES ECB byte at a time: Failed to guess unknown string length (guessed %zd, actually %zd)", unknown_string_len_guess, unknown_string_len);
		goto out;
	}

	unknown_string_guess = calloc(1, unknown_string_len_guess);
	if (unknown_string_guess == NULL) {
		goto out;
	}

	// Guess each letter of plaintext
	for (size_t i = 0; i < unknown_string_len_guess; i++) {
		char *curr_ciphertext = NULL;
		size_t curr_ciphertext_len;
		size_t curr_plaintext_len = blocksize - 1 - (i % blocksize);

		// Encrypt an input that will put the target character of the unknown
		// string at the end of a block in the ciphertext
		if (!aes_encryption_oracle_fixed_key_unknown_string(unknown_string, unknown_string_len, plaintext, curr_plaintext_len, &curr_ciphertext, &curr_ciphertext_len)) {
			print_fail("failed to encrypt ciphertext %zd", i);
			goto out;
		}

		// Construct a plaintext such that everything but the last character in
		// a block looks like the string we just encrypted.
		// Guess is what we just encrypted || the portion of the unknown string
		// we have decrypted so far || current guess char
		char guess_plaintext[256];
		size_t guess_plaintext_len = curr_plaintext_len + i + 1;
		if (guess_plaintext_len > sizeof(guess_plaintext)) {
			print_fail("guess plaintext buffer not large enough");
			goto out;
		}

		memcpy(guess_plaintext, plaintext, curr_plaintext_len);
		memcpy(guess_plaintext + curr_plaintext_len, unknown_string_guess, i);

		// Iterate over all characters until we find one such that the
		// ciphertext block containing the current target character of the
		// unknown string matches the ciphertext block from the encryption done
		// above
		int c;
		for (c = 0; c < 256; c++) {
			guess_plaintext[guess_plaintext_len - 1] = (char)c;

			char *guess_ciphertext = NULL;
			size_t guess_ciphertext_len;
			if (!aes_encryption_oracle_fixed_key_unknown_string(unknown_string, unknown_string_len, guess_plaintext, guess_plaintext_len, &guess_ciphertext, &guess_ciphertext_len)) {
				print_fail("failed to encrypt guess ciphertext %d", c);
				goto out;
			}

			bool match = memcmp(curr_ciphertext + i / blocksize * blocksize, guess_ciphertext + i / blocksize * blocksize, blocksize) == 0;

			free(guess_ciphertext);
			guess_ciphertext = NULL;

			if (match) {
				unknown_string_guess[i] = c;
				break;
			}
		}
		free(curr_ciphertext);
		curr_ciphertext = NULL;

		if (c == 256) {
			print_fail("failed to find a match");
			goto out;
		}
	}

	if (memcmp(unknown_string, unknown_string_guess, unknown_string_len) == 0) {
		success = true;
	} else {
		print_fail("AES ECB byte at a time: wrong unknown string");
	}

out:
	free(unknown_string_guess);
	free(ciphertext);

	return success;
}

bool aes_ecb_byte_at_a_time_decrypt_random_prefix(const char *unknown_string, size_t unknown_string_len)
{
	/*
	 * The random prefix oracle will take our provided plaintext and prepend a random prefix, then
	 * append the target string. We denote the random characters of the prefix with '#', the
	 * message we control as 'a' and the
	 * unknown/target string as "YELLOW SUBMARINE". Let's start by feeding in a message three blocks
	 * long. We get a plaintext like:
	 *
	 * ################ <-|
	 * ...                |- n blocks containing any portion of the random prefix
	 * ################   |
	 * #####aaaaaaaaaaa <-|
	 * aaaaaaaaaaaaaaaa <-   a block containing exclusively attacker string
	 * aaaaaaaaaaaaaaaa <-   identical to the previous block
	 * aaaaaYELLOW SUBM <-   first block containing target string
	 * ARINE            <-   PKCS7 padding omitted here
	 *
	 * For a fixed key and random prefix, and if we don't shrink the attacker string, the ciphertext
	 * of the first n blocks will never change. Further, because of ECB mode, the ciphertext blocks
	 * containing exclusively the attacker string will all be identical to each other. So we can
	 * seek two identical, consecutive blocks of ciphertext and assume that the block after that is
	 * where the target string begins.
	 */
	bool success = false;
	const size_t blocksize = 16;
	char *ciphertext = NULL;
	size_t ciphertext_len;

	char attacker_string[blocksize * 3];
	memset(attacker_string, 'a', sizeof(attacker_string));

	if (!aes_encryption_oracle_fixed_key_unknown_string_random_prefix(unknown_string, unknown_string_len,
		attacker_string, sizeof(attacker_string), &ciphertext, &ciphertext_len)) {
		print_fail("AES ECB byte at a time (harder): failed to encrypt plaintext");
		goto done;
	}

	printf("ciphertext len %zu blocks: %zu ", ciphertext_len, ciphertext_len / blocksize);
	dump_hex(ciphertext, ciphertext_len);

	// Compare each ciphertext block to its successor, looking for the two blocks made up of
	// attacker string
	size_t match_index = 0;
	char controlled_ciphertext_block[blocksize];
	for (size_t i = 0; i < ciphertext_len / blocksize; i++) {
		if (memcmp(ciphertext + (i * blocksize), ciphertext + ((i+1) * blocksize), blocksize) == 0) {
			printf("matching ciphertext blocks at %zu\n", i);
			match_index = i;
			// Record contents of controlled ciphertext
			memcpy(controlled_ciphertext_block, ciphertext + (i * blocksize), blocksize);
			break;
		}
	}
	if (match_index == 0) {
		print_fail("AES ECB byte at a time (harder): failed to find identical blocks in ciphertext");
		goto done;
	}

	/*
	 * Now we suspect that the block at match_index is the first block containing no random prefix.
	 * We can confirm that guess by growing our plaintext by one block: if we're right, we'll see
	 * one more ciphertext block whose contents match the two we saw before, immediately after those
	 * blocks. Like so:
	 *
	 * ################ <-|
	 * ...                |- n blocks containing any portion of the random prefix
	 * ################   |
	 * #####aaaaaaaaaaa <-|
	 * aaaaaaaaaaaaaaaa <-   a block containing exclusively attacker string
	 * aaaaaaaaaaaaaaaa <-   identical to the previous block
	 * aaaaaaaaaaaaaaaa <-   extra block relative to previous encryption
	 * aaaaaYELLOW SUBM <-   first block containing target string
	 * ARINE
	 */
	char attacker_string_four_blocks[blocksize * 4];
	memset(attacker_string_four_blocks, 'a', sizeof(attacker_string_four_blocks));

	free(ciphertext);
	ciphertext = NULL;
	if (!aes_encryption_oracle_fixed_key_unknown_string_random_prefix(unknown_string, unknown_string_len,
		attacker_string_four_blocks, sizeof(attacker_string_four_blocks), &ciphertext, &ciphertext_len)) {
		print_fail("AES ECB byte at a time (harder): failed to encrypt plaintext");
		goto done;
	}

	// We know how many blocks the random prefix occupies so we can directly check the three blocks
	// we are interested in, all of which ought to match the recorded block from before.
	if (memcmp(controlled_ciphertext_block, ciphertext + (match_index * blocksize), sizeof(controlled_ciphertext_block)) != 0
		|| memcmp(controlled_ciphertext_block, ciphertext + ((match_index + 1) * blocksize), sizeof(controlled_ciphertext_block)) != 0
		|| memcmp(controlled_ciphertext_block, ciphertext + ((match_index + 2) * blocksize), sizeof(controlled_ciphertext_block)) != 0) {
		print_fail("AES ECB byte at a time (harder): unexpected result from growing plaintext");
	}

	/*
	 * Now we are confident of which block the unknown string will start in, for arbitary attacker
	 * controlled strings. Next, we want to figure out the exact length of the unknown string. Let's
	 * take the ciphertext from before and only consider the blocks containing the target string:
	 *
	 * aaaaaYELLOW SUBM <- prefixed with blocksize - p bytes of attacker controlled string
	 * ARINE            <- p bytes of PKCS7 padding omitted here
	 *
	 * Let us denote the index of the first block containing the target string as k. So, the length
	 * of the target string is:
	 *      ciphertext_len - (k * blocksize) - p - (blocksize - p)
	 *
	 *
	 * We know everything here except p. Note that the portion of block k made up of the target
	 * string has the same length as the padding that will be applied to the last block. So, we can
	 * grow our controlled input by a byte at a time until we see a new ciphertext block matching
	 * our known block from before, indicating that we've pushed the unknown string to the start of
	 * the next block, and have figured out the padding length.
	 */
	free(ciphertext);
	ciphertext = NULL;


	success = true;
done:
	free(ciphertext);

	return success;
}

#if AES_ECB_CBC_ORACLE_TEST

int main(int argc, char **argv)
{
	for (int i = 0; i < 1000; i++) {
		bool correct;
		if (aes_encryption_oracle_is_cbc(aes_encryption_oracle_random, &correct)) {
			if (!correct) {
				print_fail("AES ECB CBC oracle: guessed wrong");
				exit(-1);
			}
		}
	}

	print_success("AES ECB CBC oracle OK");

	if (argc < 2) {
		print_fail("AES ECB CBC oracle: bad arguments");
		exit(-1);
	}

	size_t base64_unknown_string_len;
	char *base64_unknown_string = load_buffer_from_file(argv[1], &base64_unknown_string_len);
	if (base64_unknown_string == NULL) {
		print_fail("AES ECB byte at a time decrypt: failed to load Base64 unknown string from path %s", argv[1]);
		exit(-1);
	}

	size_t raw_unknown_string_len;
	char *raw_unknown_string = base64_to_raw(base64_unknown_string, base64_unknown_string_len, &raw_unknown_string_len);
	if (raw_unknown_string == NULL) {
		print_fail("AES ECB byte at a time decrypt: failed to decode base64 input string");
	}

	if (!aes_ecb_byte_at_a_time_decrypt(raw_unknown_string, raw_unknown_string_len)) {
		print_fail("AES ECB byte at a time decrypt: failed to byte at a time decrypt ECB");
		exit(-1);
	}

	print_success("AES ECB byte at a time decrypt OK");

	if (!aes_ecb_byte_at_a_time_decrypt_random_prefix(raw_unknown_string, raw_unknown_string_len)) {
		print_fail("AES ECB byte at a time decrypt (harder): failed");
		exit(-1);
	}

	print_success("AES ECB byte at a time decrypt (harder) OK");

	return 0;
}

#endif // AES_ECB_CBC_ORACLE_TEST
