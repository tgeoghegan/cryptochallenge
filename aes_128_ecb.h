int aes_128_ecb_encrypt(const char *plaintext, size_t plaintext_len, const char *key, size_t key_len, char **out_ciphertext, size_t *out_ciphertext_len);
int aes_128_ecb_decrypt(const char *ciphertext, size_t ciphertext_len, const char *key, size_t key_len, char **out_plaintext, size_t *out_plaintext_len);
bool is_aes_128_ecb(const char *ciphertext, size_t ciphertext_len);
char *aes_generate_key(void);
