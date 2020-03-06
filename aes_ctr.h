bool aes_ctr(const char *text, size_t text_len, const char *key, const char *nonce,
	char **out_transformed, size_t *out_transformed_len);
