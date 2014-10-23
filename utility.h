char *load_buffer_from_file(const char *path, size_t *out_size);
void foreach_line_in_file(const char *path, void (^handler)(const char *, size_t, int));
size_t memcmp_where(const char *lhs, const char *rhs, size_t size);
