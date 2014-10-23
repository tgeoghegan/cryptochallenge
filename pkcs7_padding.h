// If force_padding is true and buffer length is a multiple of block size, then
// an entire block of padding will be added.
char *pkcs7_pad_buffer(bool force_padding, const char *buffer, size_t buffer_len, size_t block_size, size_t *out_padded_len);
size_t pkcs7_unpad_buffer(const char *buffer, size_t buffer_len);
