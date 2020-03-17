typedef enum {
	ENGLISHNESS_CHECK_MONOGRAMS = 1 << 0,
	ENGLISHNESS_CHECK_DIGRAMS = 1 << 1,
	ENGLISHNESS_CHECK_TRIGRAMS = 1 << 2,
	ENGLISHNESS_CHECK_QUADGRAMS = 1 << 3,
	ENGLISHNESS_VERBOSE = 1 << 5,
} englishness_flags_t;

float compute_englishness(const char *string, size_t len, englishness_flags_t options);
