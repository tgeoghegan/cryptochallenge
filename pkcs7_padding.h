char *pkcs7_pad_buffer(const char *buffer, size_t buffer_len, size_t block_size, size_t *out_padded_len);
bool pkcs7_unpad_buffer(const char *buffer, size_t buffer_len, size_t *out_unpadded_len);
