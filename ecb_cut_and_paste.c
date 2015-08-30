#include <xpc/xpc.h>
#include <stdbool.h>
#include <stdio.h>

#include "kv_parse.h"

int main(void)
{
	char *encrypted_profile = NULL;
	size_t encrypted_profile_len = 0;
	if (!encrypted_profile_for("joe@blow.com", &encrypted_profile, &encrypted_profile_len)) {
		print_fail("ECB cut and paste: failed to create encrypted profile");
		exit(-1);
	}


	print_success("ECB cut and paste OK");
	return 0;
}

/*
We know profile is always role= email= uid=
in that order
so we want first to figure out what the string "admin" gets encrypted to when it's at character 5 (after "role=") of a block
so craft an input such that admin ends up at that position
then we can just drop in that ciphertext
but changing "user" (4 chars) to "admin" (5 chars) can't just be dropped in
In any case, I have to replace an entire block

role=user&email=
joe@blow.com&uid
=10

role=admin&email

role=user&email=
role


*/