xpc_object_t parse_profile(char *profile);
char *profile_for(const char *email);
bool encrypted_profile_for(const char *email, char **out_encrypted_profile, size_t *out_encrypted_profile_len);
xpc_object_t parse_encrypted_profile(const char *encrypted_profile, size_t encrypted_profile_len);
