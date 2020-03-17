#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include "compute_englishness.h"
#include "utility.h"

typedef struct {
	const char *gram;
	float expectation;
} gram_occurrence_t;

typedef struct {
	size_t gram_len;
	size_t gram_count;
	const gram_occurrence_t *gram_table;
} gram_occurrence_table_t;

// Data for statistical occurrence of mono, di, tri and quadgrams is mostly
// sourced from http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/.
static const gram_occurrence_t MONOGRAMS[] = {
	{ "A", 0.0855 },
	{ "B", 0.0160 },
	{ "C", 0.0316 },
	{ "D", 0.0387 },
	{ "E", 0.1210 },
	{ "F", 0.0218 },
	{ "G", 0.0209 },
	{ "H", 0.0496 },
	{ "I", 0.0733 },
	{ "J", 0.0022 },
	{ "K", 0.0081 },
	{ "L", 0.0421 },
	{ "M", 0.0253 },
	{ "N", 0.0717 },
	{ "O", 0.0747 },
	{ "P", 0.0207 },
	{ "Q", 0.0010 },
	{ "R", 0.0633 },
	{ "S", 0.0673 },
	{ "T", 0.0894 },
	{ "U", 0.0268 },
	{ "V", 0.0106 },
	{ "W", 0.0183 },
	{ "X", 0.0019 },
	{ "Y", 0.0172 },
	{ "Z", 0.0011 },
};

static const gram_occurrence_t DIGRAMS[] = {
	{ "TH", 0.0271 },
	{ "EN", 0.0113 },
	{ "NG", 0.0089 },
	{ "HE", 0.0233 },
	{ "AT", 0.0112 },
	{ "AL", 0.0088 },
	{ "IN", 0.0203 },
	{ "ED", 0.0108 },
	{ "IT", 0.0088 },
	{ "ER", 0.0178 },
	{ "ND", 0.0107 },
	{ "AS", 0.0087 },
	{ "AN", 0.0161 },
	{ "TO", 0.0107 },
	{ "IS", 0.0086 },
	{ "RE", 0.0141 },
	{ "OR", 0.0106 },
	{ "HA", 0.0083 },
	{ "ES", 0.0132 },
	{ "EA", 0.0100 },
	{ "ET", 0.0076 },
	{ "ON", 0.0132 },
	{ "TI", 0.0099 },
	{ "SE", 0.0073 },
	{ "ST", 0.0125 },
	{ "AR", 0.0098 },
	{ "OU", 0.0072 },
	{ "NT", 0.0117 },
	{ "TE", 0.0098 },
	{ "OF", 0.0071 },
};

static const gram_occurrence_t TRIGRAMS[] = {
	{ "THE", 0.0181 },
	{ "ERE", 0.0031 },
	{ "HES", 0.0024 },
	{ "AND", 0.0073 },
	{ "TIO", 0.0031 },
	{ "VER", 0.0024 },
	{ "ING", 0.0072 },
	{ "TER", 0.0030 },
	{ "HIS", 0.0024 },
	{ "ENT", 0.0042 },
	{ "EST", 0.0028 },
	{ "OFT", 0.0022 },
	{ "ION", 0.0042 },
	{ "ERS", 0.0028 },
	{ "ITH", 0.0021 },
	{ "HER", 0.0036 },
	{ "ATI", 0.0026 },
	{ "FTH", 0.0021 },
	{ "FOR", 0.0034 },
	{ "HAT", 0.0026 },
	{ "STH", 0.0021 },
	{ "THA", 0.0033 },
	{ "ATE", 0.0025 },
	{ "OTH", 0.0021 },
	{ "NTH", 0.0033 },
	{ "ALL", 0.0025 },
	{ "RES", 0.0021 },
	{ "INT", 0.0032 },
	{ "ETH", 0.0024 },
	{ "ONT", 0.0020 },
};

static const gram_occurrence_t QUADGRAMS[] = {
	{ "TION", 0.31 },
	{ "OTHE", 0.16 },
	{ "THEM", 0.12 },
	{ "NTHE", 0.27 },
	{ "TTHE", 0.16 },
	{ "RTHE", 0.12 },
	{ "THER", 0.24 },
	{ "DTHE", 0.15 },
	{ "THEP", 0.11 },
	{ "THAT", 0.21 },
	{ "INGT", 0.15 },
	{ "FROM", 0.10 },
	{ "OFTH", 0.19 },
	{ "ETHE", 0.15 },
	{ "THIS", 0.10 },
	{ "FTHE", 0.19 },
	{ "SAND", 0.14 },
	{ "TING", 0.10 },
	{ "THES", 0.18 },
	{ "STHE", 0.14 },
	{ "THEI", 0.10 },
	{ "WITH", 0.18 },
	{ "HERE", 0.13 },
	{ "NGTH", 0.10 },
	{ "INTH", 0.17 },
	{ "THEC", 0.13 },
	{ "IONS", 0.10 },
	{ "ATIO", 0.17 },
	{ "MENT", 0.12 },
	{ "ANDT", 0.10 },
};

static const gram_occurrence_table_t OCCURENCE_EXPECTATIONS[] = {
	{
		.gram_len = 1,
		.gram_count = 26,
		.gram_table = MONOGRAMS,
	},
	{
		.gram_len = 2,
		.gram_count = 30,
		.gram_table = DIGRAMS,
	},
	{
		.gram_len = 3,
		.gram_count = 30,
		.gram_table = TRIGRAMS,
	},
	{
		.gram_len = 4,
		.gram_count = 30,
		.gram_table = QUADGRAMS,
	},
};

static void pretty_print(const char *string, size_t len);
static float compute_englishness_with_table(const char *string, size_t len, gram_occurrence_table_t table, bool verbose);

float compute_englishness(const char *string, size_t len, englishness_flags_t options)
{
	float contribution_count = 0;
	float total_englishness = 0;
	bool verbose = false;
	if (options & ENGLISHNESS_VERBOSE) {
		verbose = true;
	}

	if (options & ENGLISHNESS_CHECK_MONOGRAMS) {
		contribution_count++;
		total_englishness += compute_englishness_with_table(string, len, OCCURENCE_EXPECTATIONS[0], verbose);
	}
	if (options & ENGLISHNESS_CHECK_DIGRAMS) {
		contribution_count++;
		total_englishness += compute_englishness_with_table(string, len, OCCURENCE_EXPECTATIONS[1], verbose);
	}
	if (options & ENGLISHNESS_CHECK_TRIGRAMS) {
		contribution_count++;
		total_englishness += compute_englishness_with_table(string, len, OCCURENCE_EXPECTATIONS[2], verbose);
	}
	if (options & ENGLISHNESS_CHECK_QUADGRAMS) {
		contribution_count++;
		total_englishness += compute_englishness_with_table(string, len, OCCURENCE_EXPECTATIONS[3], verbose);
	}

	return total_englishness;
}

static void toupper_buf(char *gram, size_t gram_len)
{
	for (size_t i = 0; i < gram_len; i++) {
		gram[i] = toupper(gram[i]);
	}
}

static float compute_englishness_with_table(const char *string, size_t len, gram_occurrence_table_t table, bool verbose)
{
	// The biggest gram occurrence table we have is 30 entries, so use that to statically allocate
	// the array. Similarly the biggest gram is 4.
	int occurrences[30] = { 0 };
	char current_gram[4];

	int space_count = 0;
	int other_count = 0;

	/*
	 * Wolfram says the average English word is five letters, meaning there
	 * should be a space about that often. That's pretty soft, but fuck it.
	 */
	float space_occurrence_expectation = (float)len / 6;
	/* Rough guess that we expect one punctuation, paren, etc. per string */
	float other_occurrence_expectation = 1.0f;

	// Scan along the string, counting up occurrence of each gram
	for (size_t i = 0; i < len - table.gram_len; i++) {
		memcpy(current_gram, string + i, table.gram_len);

		// normalize current gram to uppercase
		toupper_buf(current_gram, table.gram_len);

		for (size_t j = 0; j < table.gram_count; j++) {
			if (strncmp(table.gram_table[j].gram, current_gram, table.gram_len) == 0) {
				occurrences[j]++;
				break;
			}
		}

		if (string[i] == ' ') {
			space_count++;
		} else if (!isupper(string[i]) && !islower(string[i])) {
			other_count++;
		}
	}

	float delta_sum = 0;
	for (size_t i = 0; i < table.gram_count; i++) {
		const char *c = table.gram_table[i].gram;
		float expectation = table.gram_table[i].expectation * (len - table.gram_len);
		float occurred = occurrences[i];
		float delta = (occurred - expectation) * (occurred - expectation) / expectation;
		if (verbose)
			printf("expect %f saw %f contribution %f for %s\n", expectation, occurred, delta, c);
		delta_sum += delta;
	}

	// Cheating here a bit: we tally up the occurrences of spaces and unprintables when evaluating
	// monograms only, to avoid double counting their contributions.
	if (table.gram_len == 1) {
		float space_contrib = (space_count - space_occurrence_expectation) * (space_count - space_occurrence_expectation) / space_occurrence_expectation;
		delta_sum += space_contrib;
		float other_contrib = (other_count - other_occurrence_expectation) * (other_count - other_occurrence_expectation) / other_occurrence_expectation;
		delta_sum += other_contrib;
		if (verbose) {
			printf("expect %f saw %d contribution %f for space\n", space_occurrence_expectation, space_count, space_contrib);
			printf("expect %f saw %d contribution %f for other\n", other_occurrence_expectation, other_count, other_contrib);
		}
	}

	if (verbose) {
		printf("string:\n");
		pretty_print(string, len);
		printf("score %f\n", delta_sum);
	}

	return delta_sum;
}

static void pretty_print(const char *string, size_t len)
{
	if (string == NULL) {
		printf("NULL\n");
		return;
	}
	for (size_t i = 0; i < len; i++) {
		if (isprint(string[i])) {
			printf("%c", string[i]);
		}

	}
	printf("\n");
}

#if COMPUTE_ENGLISHNESS_TEST

int main(int argc, char const *argv[])
{
	char *english_text = "This is a short piece of text in English.";
	char gibberish[40];
	arc4random_buf(gibberish, sizeof(gibberish));

	float english_score = compute_englishness(english_text, strlen(english_text), 
		ENGLISHNESS_CHECK_MONOGRAMS | ENGLISHNESS_CHECK_DIGRAMS | ENGLISHNESS_CHECK_TRIGRAMS | ENGLISHNESS_CHECK_QUADGRAMS);
	float gibberish_score = compute_englishness(gibberish, strlen(gibberish),
		ENGLISHNESS_CHECK_MONOGRAMS | ENGLISHNESS_CHECK_DIGRAMS | ENGLISHNESS_CHECK_TRIGRAMS | ENGLISHNESS_CHECK_QUADGRAMS);
	if (gibberish_score < english_score) {
		print_fail("Compute englishness: Gibberish string (%f) deemed more English than English (%f)", gibberish_score, english_score);
		exit(-1);
	}

	print_success("Compute englishness OK");

	return 0;
}

#endif // COMPUTE_ENGLISHNESS_TEST
