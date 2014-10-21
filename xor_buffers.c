#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "xor_buffers.h"

void xor_buffers(uint8_t *buffer1, uint8_t *buffer2, uint8_t *out_buffer, size_t len)
{
	for (int i = 0; i < len; i++) {
		out_buffer[i] = buffer1[i] ^ buffer2[i];
	}
}

#ifdef XOR_BUFFER_TEST

int main(void)
{

	uint8_t buffer1[] = { 0x1c, 0x01, 0x11, 0x00, 0x1f, 0x01, 0x01, 0x00, 0x06, 0x1a, 0x02, 0x4b, 0x53, 0x53, 0x50, 0x09, 0x18, 0x1c };
	uint8_t buffer2[] = { 0x68, 0x69, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x62, 0x75, 0x6c, 0x6c, 0x27, 0x73, 0x20, 0x65, 0x79, 0x65 };
	uint8_t expected_result[] = { 0x74, 0x68, 0x65, 0x20, 0x6b, 0x69, 0x64, 0x20, 0x64, 0x6f, 0x6e, 0x27, 0x74, 0x20, 0x70, 0x6c, 0x61, 0x79 };
	uint8_t result[sizeof(expected_result)];

	xor_buffers(buffer1, buffer2, result, sizeof(buffer1));
	if (memcmp(result, expected_result, sizeof(expected_result)) == 0) {
		printf("xor_buffers OK\n");
	} else {
		fprintf(stderr, "xor_buffers failed\n");
		exit(-1);
	}

	return 0;
}

#endif // XOR_BUFFER_TEST
