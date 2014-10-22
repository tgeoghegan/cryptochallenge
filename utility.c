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
