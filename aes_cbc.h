typedef enum {
	AES_CBC_OP_ENCRYPT,
	AES_CBC_OP_DECRYPT,
} aes_cbc_op_t;

bool aes_cbc(aes_cbc_op_t op, const char *buffer, size_t buffer_len, const char *init_vector, const char *key, size_t key_len, char **out_buffer, size_t *out_buffer_len);
