#include <linux/types.h> /* for __u32, size_t */

static inline __u32 rol32 (__u32 word, unsigned int shift)
{
	return (word << shift) | (word >> ((-shift) & 31));
}

static unsigned short rotate_bits = 0;
static unsigned short pool_index = 0;

static const __u32 twist_table [8] = {
	0x00000000,
	0x3b6e20c8,
	0x76dc4190,
	0x4db26158,
	0xedb88320,
	0xd6d6a3e8,
	0x9b64c2b0,
	0xa00ae278
};

void mix (const void *in, size_t nbytes, void *pooldata)
{
	__u32 *pool = pooldata;
	const char *bytes = in;

	while (nbytes--) {
		__u32 w = rol32 (*bytes++, rotate_bits);

		pool_index = (pool_index - 1) & 127;

		w ^= pool [pool_index];
		w ^= pool [(pool_index + 104) & 127];
		w ^= pool [(pool_index + 76) & 127];
		w ^= pool [(pool_index + 51) & 127];
		w ^= pool [(pool_index + 25) & 127];
		w ^= pool [(pool_index + 1) & 127];

		pool [pool_index] = (w >> 3) ^ twist_table [w & 7];

		rotate_bits = (rotate_bits + (pool_index ? 7 : 14)) & 31;
	}
}
