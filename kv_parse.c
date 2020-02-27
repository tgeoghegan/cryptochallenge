#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <xpc/xpc.h>

#include "kv_parse.h"
#include "aes_128_ecb.h"
#include "pkcs7_padding.h"
#include "utility.h"

#define PAIR_SEP 	'='
#define RECORD_SEP 	'&'

// Parse a string of the form "foo=bar" and insert into dict a pair like
// foo: bar. The string may not contain '&'; that is, it must not be a profile.
// Also the string must contain '=' or it is not a pair.
static bool parse_pair_into_dict(xpc_object_t dict, char *pair)
{
	bool success = false;
	char *pair_dup = NULL;
	char *tofree = NULL;

	if (dict == NULL) {
		goto out;
	}

	if (strchr(pair, RECORD_SEP) != NULL) {
		goto out;
	}

	if (strchr(pair, PAIR_SEP) == NULL) {
		goto out;
	}

	tofree = pair_dup = strdup(pair);
	if (pair_dup == NULL) {
		goto out;
	}

	char *key = strsep(&pair_dup, "=");
	if (key == NULL) {
		goto out;
	}

	char *value = strsep(&pair_dup, "=");
	if (value == NULL) {
		goto out;
	}

	if (strsep(&pair_dup, "=") != '\0') {
		return false;
	}

	xpc_dictionary_set_string(dict, key, value);

	success = true;
out:
	free(tofree);

	return success;
}

// Parse a profile string of the form "foo=bar&blat=baz&qux=fux" and yield a
// dictionary of the form { foo: bar, blat: baz, qux: fux }
xpc_object_t parse_profile(char *profile)
{
	bool success = false;
	char *profile_dup = NULL;
	char *tofree = NULL;
	xpc_object_t dict = NULL;

	if (profile == NULL) {
		goto out;
	}

	tofree = profile_dup = strdup(profile);
	if (profile_dup == NULL) {
		goto out;
	}

	dict = xpc_dictionary_create(NULL, NULL, 0);
	if (dict == NULL) {
		goto out;
	}

	char *pair = NULL;
	while ((pair = strsep(&profile_dup, "&")) != NULL) {
		if (!parse_pair_into_dict(dict, pair)) {
			goto out;
		}
	}

	success = true;
	xpc_retain(dict);

out:
	if (dict) {
		xpc_release(dict);
	}
	free(tofree);
	return success ? dict : NULL;
}

static char *unparse_profile(xpc_object_t profile)
{
	bool success = false;
	char *unparsed = NULL;
	__block size_t profile_len = 0;

	if (profile == NULL || xpc_dictionary_get_count(profile) == 0) {
		goto out;
	}

	// Compute profile size based on lengths of keys and values
	xpc_dictionary_apply(profile, ^bool (const char *key, xpc_object_t value) {
		profile_len += strlen(key);
		profile_len += 1; // '='
		profile_len += xpc_string_get_length(value);
		profile_len += 1; // '&'

		return true;
	});

	unparsed = malloc(profile_len);
	if (unparsed == NULL) {
		goto out;
	}
	unparsed[0] = '\0';

	// The attack in challenge 13 relies on the ordering of the keys in the encoded profile: role
	// can't be first or we can't control the position of its value. So instead of handling
	// arbitrary keys, we hard code specific keys in a specific order.
	const char *keys[3] = {"email", "uid", "role"};
	for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
		strlcat(unparsed, keys[i], profile_len);
		strlcat(unparsed, "=", profile_len);

		const char *value = xpc_dictionary_get_string(profile, keys[i]);
		if (value == NULL) {
			goto out;
		}

		strlcat(unparsed, value, profile_len);
		strlcat(unparsed, "&", profile_len);
	}

	// Replace trailing '&' with NUL
	unparsed[profile_len] = '\0';

	success = true;
out:
	if (!success) {
		free(unparsed);
		unparsed = NULL;
	}

	return unparsed;
}

static int uid = 1;

char *profile_for(const char *email)
{
	char *profile_string = NULL;

	// email may not contain '=' or '&'
	if (strchr(email, RECORD_SEP) != NULL || strchr(email, PAIR_SEP) != 0) {
		return NULL;
	}

	xpc_object_t profile = xpc_dictionary_create(NULL, NULL, 0);
	if (profile == NULL) {
		return NULL;
	}
	xpc_dictionary_set_string(profile, "email", email);
	char uid_string[1024];
	memset(uid_string, 0, sizeof(uid_string));
	snprintf(uid_string, sizeof(uid_string), "%d", uid);
	xpc_dictionary_set_string(profile, "uid", uid_string);
	uid++;
	xpc_dictionary_set_string(profile, "role", "user");

	profile_string = unparse_profile(profile);
	xpc_release(profile);

	return profile_string;
}

static char *aes_key = NULL;

bool encrypted_profile_for(const char *email, char **out_encrypted_profile, size_t *out_encrypted_profile_len)
{
	bool success = false;
	char *encrypted_profile = NULL;
	char *padded_profile = NULL;
	char *unencrypted_profile = NULL;

	if (aes_key == NULL) {
		aes_key = aes_generate_key();
		if (aes_key == NULL) {
			goto out;
		}
	}

	unencrypted_profile = profile_for(email);
	if (unencrypted_profile == NULL) {
		goto out;
	}

	size_t padded_len = 0;
	padded_profile = pkcs7_pad_buffer(false, unencrypted_profile, strlen(unencrypted_profile), 16, &padded_len);
	if (padded_profile == NULL) {
		goto out;
	}

	size_t encrypted_profile_len = 0;
	if (aes_128_ecb_encrypt(unencrypted_profile, padded_len, aes_key, 16, &encrypted_profile, &encrypted_profile_len) != 0) {
		goto out;
	}

	if (out_encrypted_profile) {
		*out_encrypted_profile = encrypted_profile;
	}
	if (out_encrypted_profile_len) {
		*out_encrypted_profile_len = encrypted_profile_len;
	}

	success = true;

out:
	free(unencrypted_profile);
	free(padded_profile);
	if (out_encrypted_profile == NULL) {
		free(encrypted_profile);
	}

	return success;
}

xpc_object_t parse_encrypted_profile(const char *encrypted_profile, size_t encrypted_profile_len)
{
	char *decrypted_profile = NULL;
	xpc_object_t parsed = NULL;

	if (aes_key == NULL) {
		aes_key = aes_generate_key();
		if (aes_key == NULL) {
			goto out;
		}
	}

	size_t decrypted_profile_len = 0;
	if (aes_128_ecb_decrypt(encrypted_profile, encrypted_profile_len, aes_key, 16, &decrypted_profile, &decrypted_profile_len) != 0) {
		goto out;
	}

	// Strip padding from plaintext by truncating string with NUL
	decrypted_profile[pkcs7_unpad_buffer(decrypted_profile, decrypted_profile_len)] = '\0';

	parsed = parse_profile(decrypted_profile);
	if (parsed == NULL) {
		goto out;
	}

out:
	free(decrypted_profile);

	return parsed;
}

#if KV_PARSE_TEST

int main()
{
	xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
	if (!parse_pair_into_dict(dict, "foo=bar")) {
		print_fail("KV parse: failed to parse valid pair");
		exit(-1);
	}

	const char *value = xpc_dictionary_get_string(dict, "foo");
	if (!value || strcmp(value, "bar") != 0) {
		print_fail("KV parse: wrong key in dict");
	}

	if (parse_pair_into_dict(dict, "blat")) {
		print_fail("KV parse: parsed bad string");
		exit(-1);
	}

	value = xpc_dictionary_get_string(dict, "blat");
	if (value) {
		print_fail("KV parse: unexpected key in dict");
		exit(-1);
	}

	if (parse_pair_into_dict(dict, "qux=fux&")) {
		print_fail("KV parse: parsed bad string");
		exit(-1);
	}

	if (parse_pair_into_dict(dict, "&qux=fux&")) {
		print_fail("KV parse: parsed bad string");
		exit(-1);
	}

	if (parse_pair_into_dict(dict, "&qux=fux&")) {
		print_fail("KV parse: parsed bad string");
		exit(-1);
	}

	if (xpc_dictionary_get_string(dict, "qux") || xpc_dictionary_get_string(dict, "fux") || xpc_dictionary_get_string(dict, "&") || xpc_dictionary_get_string(dict, "&qux") || xpc_dictionary_get_string(dict, "fux&")) {
		print_fail("KV parse: parsed bad string");
		exit(-1);
	}

	if (parse_pair_into_dict(dict, "foo=bar=baz")) {
		print_fail("KV parse: parsed bad string");
		exit(-1);
	}

	xpc_release(dict);

	dict = parse_profile("foo=bar");
	if (dict == NULL) {
		print_fail("KV parse: failed to parse valid profile");
		exit(-1);
	}

	value = xpc_dictionary_get_string(dict, "foo");
	if (!value || strcmp(value, "bar") != 0) {
		print_fail("KV parse: fwrong value in dict");
		exit(-1);
	}

	xpc_release(dict);

	char *profile = "email=bar&uid=111&role=blat";
	char *profile_backwards = "role=blat&uid=111&email=bar";
	dict = parse_profile(profile);
	if (dict == NULL) {
		print_fail("KV parse: failed to parse valid profile");
		exit(-1);
	}

	xpc_object_t dict_backwards = parse_profile(profile_backwards);
	if (dict_backwards == NULL) {
		print_fail("KV parse: failed to parse valid profile");
		exit(-1);
	}

	if (xpc_dictionary_get_string(dict, "email") == NULL || strcmp(xpc_dictionary_get_string(dict, "email"), "bar") != 0
		|| xpc_dictionary_get_string(dict, "role") == NULL || strcmp(xpc_dictionary_get_string(dict, "role"), "blat") != 0
		|| xpc_dictionary_get_string(dict, "uid") == NULL || strcmp(xpc_dictionary_get_string(dict, "uid"), "111") != 0
		|| xpc_dictionary_get_string(dict_backwards, "email") == NULL || strcmp(xpc_dictionary_get_string(dict_backwards, "email"), "bar") != 0
		|| xpc_dictionary_get_string(dict_backwards, "role") == NULL || strcmp(xpc_dictionary_get_string(dict_backwards, "role"), "blat") != 0
		|| xpc_dictionary_get_string(dict_backwards, "uid") == NULL || strcmp(xpc_dictionary_get_string(dict_backwards, "uid"), "111") != 0) {
		char *desc = xpc_copy_description(dict);
		char *desc_backwards = xpc_copy_description(dict_backwards);
		print_fail("KV parse: incorrect parse of valid profiles (%s\n%s)", desc, desc_backwards);
		free(desc);
		free(desc_backwards);
		exit(-1);
	}

	xpc_release(dict_backwards);

	char *unparsed = unparse_profile(dict);
	if (unparsed == NULL) {
		print_fail("KV parse: failed to unparse profile");
		exit(-1);
	}

	if (strcmp(unparsed, profile) != 0 && strcmp(unparsed, profile_backwards) != 0) {
		print_fail("KV parse: incorrect profile unparse: %s", unparsed);
		exit(-1);
	}

	value = xpc_dictionary_get_string(dict, "email");
	if (!value || strcmp(value, "bar") != 0) {
		print_fail("KV parse: frong value in dict");
		exit(-1);
	}

	value = xpc_dictionary_get_string(dict, "role");
	if (!value || strcmp(value, "blat") != 0) {
		print_fail("KV parse: fwrong value in dict");
		exit(-1);
	}

	xpc_release(dict);

	dict = parse_profile("foo=bar&qux=blat&");
	if (dict != NULL) {
		print_fail("KV parse: parsed invalid profile");
		exit(-1);
	}

	dict = parse_profile("&foo=bar&qux=blat&");
	if (dict != NULL) {
		print_fail("KV parse: parsed invalid profile");
		exit(-1);
	}

	dict = parse_profile("foo=bar=bat&qux=fux");
	if (dict != NULL) {
		print_fail("KV parse: parsed invalid profile");
		exit(-1);
	}

	char *user_profile = profile_for("joe@blow.com");
	if (user_profile == NULL) {
		print_fail("KV parse: failed to create profile");
		exit(-1);
	}

	dict = parse_profile(user_profile);
	if (dict == NULL) {
		print_fail("KV parse: failed to parse user profile");
		exit(-1);
	}

	if (xpc_dictionary_get_string(dict, "email") == NULL || strcmp(xpc_dictionary_get_string(dict, "email"), "joe@blow.com") != 0
		|| xpc_dictionary_get_string(dict, "uid") == NULL || strcmp(xpc_dictionary_get_string(dict, "uid"), "0") != 0
		|| xpc_dictionary_get_string(dict, "role") == NULL || strcmp(xpc_dictionary_get_string(dict, "role"), "user") != 0
		|| xpc_dictionary_get_count(dict) != 3) {
		print_fail("KV parse: unexpected values in user profile %s", user_profile);
		exit(-1);
	}

	free(user_profile);
	xpc_release(dict);
	dict = NULL;

	user_profile = profile_for("jane@blow.com");
	if (user_profile == NULL) {
		print_fail( "KV parse: failed to create profile");
		exit(-1);
	}

	dict = parse_profile(user_profile);
	if (dict == NULL) {
		print_fail("KV parse: failed to parse user profile");
		exit(-1);
	}

	if (xpc_dictionary_get_string(dict, "email") == NULL || strcmp(xpc_dictionary_get_string(dict, "email"), "jane@blow.com") != 0
		|| xpc_dictionary_get_string(dict, "uid") == NULL || strcmp(xpc_dictionary_get_string(dict, "uid"), "1") != 0
		|| xpc_dictionary_get_string(dict, "role") == NULL || strcmp(xpc_dictionary_get_string(dict, "role"), "user") != 0
		|| xpc_dictionary_get_count(dict) != 3) {
		print_fail("KV parse: unexpected values in user profile %s", user_profile);
		exit(-1);
	}

	free(user_profile);
	xpc_release(dict);
	dict = NULL;

	user_profile = profile_for("joe@blow.com&");
	if (user_profile != NULL) {
		print_fail("KV parse: generated profile for invalid email address: %s", user_profile);
		exit(-1);
	}

	user_profile = profile_for("joe@blow.com=");
	if (user_profile != NULL) {
		print_fail("KV parse: generated profile for invalid email address: %s", user_profile);
		exit(-1);
	}

	user_profile = profile_for("joe@blow.com&role=admin");
	if (user_profile != NULL) {
		print_fail("KV parse: generated profile for invalid email address: %s", user_profile);
		exit(-1);
	}

	user_profile = profile_for("role=admin");
	if (user_profile != NULL) {
		print_fail("KV parse: generated profile for invalid email address: %s", user_profile);
		exit(-1);
	}

	char *encrypted_profile = NULL;
	size_t encrypted_profile_len = 0;
	if (!encrypted_profile_for("joe@blow.com", &encrypted_profile, &encrypted_profile_len)) {
		print_fail("KV parse: failed to generate encrypted profile");
		exit(-1);
	}

	dict = parse_encrypted_profile(encrypted_profile, encrypted_profile_len);
	if (dict == NULL) {
		print_fail("KV parse: failed to decrypt profile");
		exit(-1);
	}

	if (xpc_dictionary_get_string(dict, "email") == NULL || strcmp(xpc_dictionary_get_string(dict, "email"), "joe@blow.com") != 0
		|| xpc_dictionary_get_string(dict, "uid") == NULL || strcmp(xpc_dictionary_get_string(dict, "uid"), "2") != 0
		|| xpc_dictionary_get_string(dict, "role") == NULL || strcmp(xpc_dictionary_get_string(dict, "role"), "user") != 0
		|| xpc_dictionary_get_count(dict) != 3) {
		char *desc = xpc_copy_description(dict);
		print_fail("KV parse: unexpected values in user profile %s", desc);
		free(desc);
		exit(-1);
	}

	xpc_release(dict);
	free(encrypted_profile);

	print_success("KV parse OK");

	return 0;
}

#endif // KV_PARSE_TEST
