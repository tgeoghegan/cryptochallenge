#include <stdint.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdarg.h>

#include "utility.h"

char *load_buffer_from_file(const char *path, size_t *out_size)
{
	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "failed to open(2) file %s: %s\n", path, strerror(errno));
		exit(-1);
	}

	struct stat sb;
	if (fstat(fd, &sb) != 0) {
		fprintf(stderr, "failed to fstat(2) %s: %s\n", path, strerror(errno));
		exit(-1);
	}
	off_t size = sb.st_size;
	char *buf = calloc(1, size);
	if (buf == NULL) {
		fprintf(stderr, "failed to allocate input buffer\n");
		exit(-1);
	}

	if (read(fd, buf, size) != size) {
		fprintf(stderr, "failed to read %lld bytes from %s: %s\n", size, path, strerror(errno));
		exit(-1);
	}

	close(fd);

	if (out_size) {
		*out_size = size;
	}

	return buf;
}

void foreach_line_in_file(const char *path, void (^handler)(const char *, size_t, int))
{
	FILE *input = fopen(path, "r");
	if (input == NULL) {
		fprintf(stderr, "failed to open input '%s': %s\n", path, strerror(errno));
		exit(-1);
	}

	char *line = NULL;
	size_t linecap = 0;
	ssize_t linelen = 0;
	int index = 0;
	while ((linelen = getline(&line, &linecap, input)) > 0) {
		handler(line, linelen, index);
		index++;
	}
	free(line);
	fclose(input);
}

size_t memcmp_where(const char *lhs, const char *rhs, size_t size)
{
	for (size_t i = 0; i < size; i++) {
		if (lhs[i] != rhs[i]) {
			return i;
		}
	}

	return -1;
}

void dump_hex_fd(FILE *filedes, const char *string, size_t len)
{
	fprintf(filedes, "0x");
	for (size_t i = 0; i < len; i++) {
		if (i % 16 == 0 && i > 0) {
			fprintf(filedes, " ");
		}
		fprintf(filedes, "%02x", (unsigned char)string[i]);
	}

	fprintf(filedes, "\n");
}

void dump_hex(const char *string, size_t len)
{
	dump_hex_fd(stdout, string, len);
}

void dump_hex_label(FILE *filedes, const char *label, const char *string, size_t len)
{
	fprintf(filedes, "%s:\t", label);
	dump_hex_fd(filedes, string, len);
}

static void print_color(bool success, const char *format, va_list ap)
{
	int color = 31;
	FILE *outfd = stderr;
	if (success) {
		color = 32;
		outfd = stdout;
	}

	fprintf(outfd, "\033[0;%dm", color);
	vfprintf(outfd, format, ap);
	fprintf(outfd, "\033[0m\n");
}

void print_success(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	print_color(true, format, ap);
	va_end(ap);
}

void print_fail(const char *format, ...)
{
	va_list(ap);
	va_start(ap, format);
	print_color(false, format, ap);
	va_end(ap);
}

void generate_random_string(char *buf, size_t len)
{
	const char *printables = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()";

	for (size_t i = 0; i < len; i++) {
		uint32_t printable = arc4random_uniform(strlen(printables));
		buf[i] = printables[printable];
	}
}
