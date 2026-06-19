#include <lzma.h>

int main(void)
{
	lzma_stream strm = LZMA_STREAM_INIT;

	lzma_end(&strm);
	return 0;
}
