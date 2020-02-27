#include <xpc/xpc.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "kv_parse.h"
#include "utility.h"

int main(void)
{
	char *first_encrypted_profile = NULL;
	size_t first_encrypted_profile_len = 0;
	char *second_encrypted_profile = NULL;
	size_t second_encrypted_profile_len = 0;
	xpc_object_t parsed_doctored_profile = NULL;

	// We control the length of the user email, but the length of the UID may also vary. For now,
	// we assume UIDs are one digit. First, we get an encrypted profile for a chosen email that
	// places the string "user" at the beginning of the third block of the ciphertext:
	//
	// email=fooooo@bar
	// .com&uid=1&role=
	// usercccccccccccc <-- here the c is hex 12, the PKCS padding value
	//
	// We will replace that third block with one that is the string "admin". We'll achieve that by
	// crafting an email address that contains "admin" plus 11 bytes of PKCS7 padding.
	//
	// email=fooooooooo
	// adminbbbbbbbbbbb <-- here the b is hex 11
	// @bar.com&uid=2&r
	// ole=user
	//
	// Then we should be able to take the second block from the second encrypted profile and replace
	// the third block from the first profile, yielding:
	//
	// email=fooooo@bar
	// .com&uid=1&role=
	// adminbbbbbbbbbbb
	//
	// ...which should decrypt into a valid profile.
	if (!encrypted_profile_for("fooooo@bar.com", &first_encrypted_profile, &first_encrypted_profile_len)) {
		print_fail("ECB cut and paste: failed to create encrypted profile");
		goto done;
	}

	// These lines are wrapped to match where each character ends up in the output ciphertext blocks
	char second_email[10+5+11+8] = {
		/* email=                   */'f', 'o', 'o', 'o', 'o', 'o', 'o', 'o', 'o', 'o',
		'a', 'd', 'm', 'i', 'n', 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb,
		 '@', 'b', 'a', 'r', '.', 'c', 'o', 'm' /* remainder of profile */
	};

	if (!encrypted_profile_for(second_email, &second_encrypted_profile, &second_encrypted_profile_len)) {
		print_fail("ECB cut and paste: failed to create encrypted profile");
		goto done;
	}

	// Paste block 2 of second profile into block 3 of the first one
	memcpy(first_encrypted_profile + 32, second_encrypted_profile + 16, 16);

	parsed_doctored_profile = parse_encrypted_profile(first_encrypted_profile, first_encrypted_profile_len);
	if (parsed_doctored_profile == NULL) {
		print_fail("ECB cut and paste: failed to decrypt doctored profile");
		goto done;
	}

	if (xpc_dictionary_get_string(parsed_doctored_profile, "email") == NULL || strcmp(xpc_dictionary_get_string(parsed_doctored_profile, "email"), "fooooo@bar.com") != 0
		|| xpc_dictionary_get_string(parsed_doctored_profile, "uid") == NULL || strcmp(xpc_dictionary_get_string(parsed_doctored_profile, "uid"), "1") != 0
		|| xpc_dictionary_get_string(parsed_doctored_profile, "role") == NULL || strcmp(xpc_dictionary_get_string(parsed_doctored_profile, "role"), "admin") != 0) {
		char *desc = xpc_copy_description(parsed_doctored_profile);
		print_fail("ECB cut and paste: unexpected parsed profile %s", desc);
		free(desc);
		goto done;
	}

	print_success("ECB cut and paste OK");

done:
	free(first_encrypted_profile);
	free(second_encrypted_profile);
	if (parsed_doctored_profile != NULL) {
		xpc_release(parsed_doctored_profile);
	}

	return 0;
}
