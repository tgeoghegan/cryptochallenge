char *load_buffer_from_file(const char *path, size_t *out_size);
void foreach_line_in_file(const char *path, void (^handler)(const char *, size_t, int));
size_t memcmp_where(const char *lhs, const char *rhs, size_t size);
void dump_hex(const char *string, size_t len);
void dump_hex_label(FILE *filedes, const char *label, const char *string, size_t len);
void print_success(const char *format, ...);
void print_fail(const char *format, ...);
