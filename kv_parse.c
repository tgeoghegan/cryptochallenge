#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <xpc/xpc.h>

#define PAIR_SEP 	'='
#define RECORD_SEP 	'&'

// Parse a string of the form "foo=bar" and insert into dict a pair like
// foo: bar. The string may not contain '&'; that is, it must not be a profile.
// Also the string must contain '=' or it is not a pair.
bool parse_pair_into_dict(xpc_object_t dict, char *pair)
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

char *unparse_profile(xpc_object_t profile)
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

	dict = parse_profile("foo=bar&qux=blat");
	if (dict == NULL) {
		fprintf(stderr, "KV parse: failed to parse valid profile\n");
		exit(-1);
	}

	char *unparsed = unparse_profile(dict);
	if (unparsed == NULL) {
		fprintf(stderr, "KV parse: failed to unparse profile\n");
		exit(-1);
	} else {
		printf("unparsed: %s\n", unparsed);
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

	printf("KV parse OK\n");

	return 0;
}

#endif // KV_PARSE_TEST
