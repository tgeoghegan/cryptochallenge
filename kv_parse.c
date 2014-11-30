#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <xpc/xpc.h>

#include "kv_parse.h"
#include "aes_128_ecb.h"
#include "pkcs7_padding.h"

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

	xpc_dictionary_apply(profile, ^bool (const char *key, xpc_object_t value) {
		strlcat(unparsed, key, profile_len);
		strlcat(unparsed, "=", profile_len);
		strlcat(unparsed, xpc_string_get_string_ptr(value), profile_len);
		strlcat(unparsed, "&", profile_len);

		return true;
	});

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

static int uid = 0;

char *profile_for(const char *email)
{
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

	return unparse_profile(profile);
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

	// grow decrypted profile by one byte for '\0'
	decrypted_profile = realloc(decrypted_profile, decrypted_profile_len + 1);
	if (decrypted_profile == NULL) {
		goto out;
	}

	decrypted_profile[decrypted_profile_len] = '\0';

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
		fprintf(stderr, "KV parse: failed to parse valid pair\n");
		exit(-1);
	}

	const char *value = xpc_dictionary_get_string(dict, "foo");
	if (!value || strcmp(value, "bar") != 0) {
		fprintf(stderr, "KV parse: wrong key in dict\n");
	}

	if (parse_pair_into_dict(dict, "blat")) {
		fprintf(stderr, "KV parse: parsed bad string\n");
		exit(-1);
	}

	value = xpc_dictionary_get_string(dict, "blat");
	if (value) {
		fprintf(stderr, "KV parse: unexpected key in dict\n");
		exit(-1);
	}

	if (parse_pair_into_dict(dict, "qux=fux&")) {
		fprintf(stderr, "KV parse: parsed bad string\n");
		exit(-1);
	}

	if (parse_pair_into_dict(dict, "&qux=fux&")) {
		fprintf(stderr, "KV parse: parsed bad string\n");
		exit(-1);
	}

	if (parse_pair_into_dict(dict, "&qux=fux&")) {
		fprintf(stderr, "KV parse: parsed bad string\n");
		exit(-1);
	}

	if (xpc_dictionary_get_string(dict, "qux") || xpc_dictionary_get_string(dict, "fux") || xpc_dictionary_get_string(dict, "&") || xpc_dictionary_get_string(dict, "&qux") || xpc_dictionary_get_string(dict, "fux&")) {
		fprintf(stderr, "KV parse: parsed bad string\n");
		exit(-1);
	}

	if (parse_pair_into_dict(dict, "foo=bar=baz")) {
		fprintf(stderr, "KV parse: parsed bad string\n");
		exit(-1);
	}

	xpc_release(dict);

	dict = parse_profile("foo=bar");
	if (dict == NULL) {
		fprintf(stderr, "KV parse: failed to parse valid profile\n");
		exit(-1);
	}

	value = xpc_dictionary_get_string(dict, "foo");
	if (!value || strcmp(value, "bar") != 0) {
		fprintf(stderr, "KV parse: fwrong value in dict\n");
		exit(-1);
	}

	xpc_release(dict);

	char *profile = "foo=bar&qux=blat";
	char *profile_backwards = "qux=blat&foo=bar";
	dict = parse_profile(profile);
	if (dict == NULL) {
		fprintf(stderr, "KV parse: failed to parse valid profile\n");
		exit(-1);
	}

	xpc_object_t dict_backwards = parse_profile(profile_backwards);
	if (dict_backwards == NULL) {
		fprintf(stderr, "KV parse: failed to parse valid profile\n");
		exit(-1);
	}

	if (xpc_dictionary_get_string(dict, "foo") == NULL || strcmp(xpc_dictionary_get_string(dict, "foo"), "bar") != 0
		|| xpc_dictionary_get_string(dict, "qux") == NULL || strcmp(xpc_dictionary_get_string(dict, "qux"), "blat") != 0
		|| xpc_dictionary_get_string(dict_backwards, "foo") == NULL || strcmp(xpc_dictionary_get_string(dict_backwards, "foo"), "bar") != 0
		|| xpc_dictionary_get_string(dict_backwards, "qux") == NULL || strcmp(xpc_dictionary_get_string(dict_backwards, "qux"), "blat") != 0) {
		char *desc = xpc_copy_description(dict);
		char *desc_backwards = xpc_copy_description(dict_backwards);
		fprintf(stderr, "KV parse: incorrect parse of valid profiles (%s\n%s)\n", desc, desc_backwards);
		free(desc);
		free(desc_backwards);
		exit(-1);
	}

	xpc_release(dict_backwards);

	char *unparsed = unparse_profile(dict);
	if (unparsed == NULL) {
		fprintf(stderr, "KV parse: failed to unparse profile\n");
		exit(-1);
	}

	if (strcmp(unparsed, profile) != 0 && strcmp(unparsed, profile_backwards) != 0) {
		fprintf(stderr, "KV parse: incorrect profile unparse: %s\n", unparsed);
		exit(-1);
	}

	value = xpc_dictionary_get_string(dict, "foo");
	if (!value || strcmp(value, "bar") != 0) {
		fprintf(stderr, "KV parse: fwrong value in dict\n");
		exit(-1);
	}

	value = xpc_dictionary_get_string(dict, "qux");
	if (!value || strcmp(value, "blat") != 0) {
		fprintf(stderr, "KV parse: fwrong value in dict\n");
		exit(-1);
	}

	xpc_release(dict);

	dict = parse_profile("foo=bar&qux=blat&");
	if (dict != NULL) {
		fprintf(stderr, "KV parse: parsed invalid profile\n");
		exit(-1);
	}

	dict = parse_profile("&foo=bar&qux=blat&");
	if (dict != NULL) {
		fprintf(stderr, "KV parse: parsed invalid profile\n");
		exit(-1);
	}

	dict = parse_profile("foo=bar=bat&qux=fux");
	if (dict != NULL) {
		fprintf(stderr, "KV parse: parsed invalid profile\n");
		exit(-1);
	}

	char *user_profile = profile_for("joe@blow.com");
	if (user_profile == NULL) {
		fprintf(stderr, "KV parse: failed to create profile\n");
		exit(-1);
	}

	dict = parse_profile(user_profile);
	if (dict == NULL) {
		fprintf(stderr, "KV parse: failed to parse user profile\n");
		exit(-1);
	}

	if (xpc_dictionary_get_string(dict, "email") == NULL || strcmp(xpc_dictionary_get_string(dict, "email"), "joe@blow.com") != 0
		|| xpc_dictionary_get_string(dict, "uid") == NULL || strcmp(xpc_dictionary_get_string(dict, "uid"), "0") != 0
		|| xpc_dictionary_get_string(dict, "role") == NULL || strcmp(xpc_dictionary_get_string(dict, "role"), "user") != 0
		|| xpc_dictionary_get_count(dict) != 3) {
		fprintf(stderr, "KV parse: unexpected values in user profile %s\n", user_profile);
		exit(-1);
	}

	free(user_profile);
	xpc_release(dict);
	dict = NULL;

	user_profile = profile_for("jane@blow.com");
	if (user_profile == NULL) {
		fprintf(stderr, "KV parse: failed to create profile\n");
		exit(-1);
	}

	dict = parse_profile(user_profile);
	if (dict == NULL) {
		fprintf(stderr, "KV parse: failed to parse user profile\n");
		exit(-1);
	}

	if (xpc_dictionary_get_string(dict, "email") == NULL || strcmp(xpc_dictionary_get_string(dict, "email"), "jane@blow.com") != 0
		|| xpc_dictionary_get_string(dict, "uid") == NULL || strcmp(xpc_dictionary_get_string(dict, "uid"), "1") != 0
		|| xpc_dictionary_get_string(dict, "role") == NULL || strcmp(xpc_dictionary_get_string(dict, "role"), "user") != 0
		|| xpc_dictionary_get_count(dict) != 3) {
		fprintf(stderr, "KV parse: unexpected values in user profile %s\n", user_profile);
		exit(-1);
	}

	free(user_profile);
	xpc_release(dict);
	dict = NULL;

	char *encrypted_profile = NULL;
	size_t encrypted_profile_len = 0;
	if (!encrypted_profile_for("joe@blow.com", &encrypted_profile, &encrypted_profile_len)) {
		fprintf(stderr, "KV parse: failed to generate encrypted profile\n");
		exit(-1);
	}

	dict = parse_encrypted_profile(encrypted_profile, encrypted_profile_len);
	if (dict == NULL) {
		fprintf(stderr, "KV parse: failed to decrypt profile\n");
		exit(-1);
	}

	if (xpc_dictionary_get_string(dict, "email") == NULL || strcmp(xpc_dictionary_get_string(dict, "email"), "joe@blow.com") != 0
		|| xpc_dictionary_get_string(dict, "uid") == NULL || strcmp(xpc_dictionary_get_string(dict, "uid"), "2") != 0
		|| xpc_dictionary_get_string(dict, "role") == NULL || strcmp(xpc_dictionary_get_string(dict, "role"), "user") != 0
		|| xpc_dictionary_get_count(dict) != 3) {
		char *desc = xpc_copy_description(dict);
		fprintf(stderr, "KV parse: unexpected values in user profile %s\n", desc);
		free(desc);
		exit(-1);
	}

	xpc_release(dict);
	free(encrypted_profile);

	printf("KV parse OK\n");

	return 0;
}

#endif // KV_PARSE_TEST
