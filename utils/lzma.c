#ifdef HAVE_LIBLZMA
#include <lzma.h>
#include <stdio.h>
#include <stdlib.h>

#include "uftrace.h"

#define LZMA_PRESET 6

static lzma_ret uftrace_lzma_loop(lzma_stream *s, void **outp, int *out_len)
{
	unsigned char buf[8192];
	lzma_ret ret = LZMA_OK;
	void *out = NULL;
	int len = 0;

	s->next_out = buf;
	s->avail_out = sizeof(buf);

	while (ret != LZMA_STREAM_END) {
		void *tmp;
		size_t size;

		ret = lzma_code(s, LZMA_FINISH);
		if (ret != LZMA_OK && ret != LZMA_STREAM_END)
			break;

		size = sizeof(buf) - s->avail_out;
		tmp = realloc(out, len + size);
		if (tmp == NULL) {
			ret = LZMA_MEM_ERROR;
			break;
		}

		memcpy(tmp + len, buf, size);
		out = tmp;
		len += size;

		s->next_out = buf;
		s->avail_out = sizeof(buf);
	}

	if (ret != LZMA_STREAM_END) {
		pr_dbg("lzma failed: ret = %d\n", (int)ret);
		free(out);
		out = NULL;
		len = 0;
	}
	*outp = out;
	*out_len = len;

	return ret;
}

/* callers should free *@outp after use */
int uftrace_lzma_compress(void *inp, int in_len, void **outp, int *out_len)
{
	lzma_stream s = LZMA_STREAM_INIT;
	lzma_ret ret;

	if (lzma_easy_encoder(&s, LZMA_PRESET, LZMA_CHECK_CRC64) != LZMA_OK)
		return -1;

	s.next_in = inp;
	s.avail_in = in_len;

	ret = uftrace_lzma_loop(&s, outp, out_len);
	lzma_end(&s);

	return (ret == LZMA_STREAM_END) ? 0 : -1;
}

/* callers should free *@outp after use */
int uftrace_lzma_decompress(void *inp, int in_len, void **outp, int *out_len)
{
	lzma_stream s = LZMA_STREAM_INIT;
	lzma_ret ret;

	if (lzma_stream_decoder(&s, 1 << 30, 0) != LZMA_OK)
		return -1;

	s.next_in = inp;
	s.avail_in = in_len;

	ret = uftrace_lzma_loop(&s, outp, out_len);
	lzma_end(&s);

	return (ret == LZMA_STREAM_END) ? 0 : -1;
}

#ifdef UNIT_TEST
TEST_CASE(utils_lzma)
{
	char test_data[] = "This is a test data for liblzma compression and decompression.";
	void *lzma_data1 = NULL;
	void *lzma_data2 = NULL;
	int len1, len2;

	pr_dbg("compressing data\n");
	TEST_EQ(uftrace_lzma_compress(test_data, sizeof(test_data), &lzma_data1, &len1), 0);
	TEST_NE(lzma_data1, NULL);
	TEST_NE(len1, 0);

	pr_dbg("decompressing data\n");
	TEST_EQ(uftrace_lzma_decompress(lzma_data1, len1, &lzma_data2, &len2), 0);
	TEST_NE(lzma_data2, NULL);
	TEST_NE(len2, 0);

	TEST_STREQ(test_data, lzma_data2);
	TEST_EQ(len2, sizeof(test_data));

	free(lzma_data1);
	free(lzma_data2);
	return TEST_OK;
}
#endif /* UNIT_TEST */

#endif /* HAVE_LIBLZMA */
