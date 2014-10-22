char *hex_to_base64(const char *hex, size_t length);
char *base64_to_raw(const char *base64, size_t length, size_t *out_raw_len);
long long_at_index(const char *hex_string, size_t index);
bool is_base64_encoded(const char *candidate, size_t len);
char *hex_print_string(const char *string, size_t len);
char *hex_to_raw(const char *hex, size_t length, size_t *out_raw_len);
