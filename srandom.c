#include <linux/ctype.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>  	
#include <linux/slab.h>
#include <linux/fs.h>       		
#include <linux/errno.h>  
#include <linux/types.h> 
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <linux/wait.h>
#include <linux/random.h>
#include <linux/signal.h>
//#include "mix.h"
//#include "sha1.h"
#include <linux/ioctl.h>

#include <linux/types.h> /* for __u32, size_t */

#include <linux/string.h>

#define POOL_SIZE 512
#define WRITE_CHUNK_SIZE 64
#define READ_CHUNK_SIZE 20
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Omri&Or");
static ssize_t device_read(struct file *, char * buffer, size_t n, loff_t *);
static ssize_t device_write(struct file *, const char* buffer, size_t n, loff_t *);
int ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg);
int init_module(void);
void cleanup_module(void);



void mix(const void *in, size_t nbytes, void *pooldata);
void hash_pool(const void *pooldata, void *out);
int rndaddentropy(struct rand_pool_info *p);
int rndclearpool();
int rndgetentcnt(int* p);

struct file_operations fops = {
	.open = NULL,
	.release = NULL,
	.read = device_read,
	.write = device_write,
	.llseek = NULL,
	.ioctl = ioctl,
	.owner = THIS_MODULE,
};

char entropy_pool[POOL_SIZE];
int entropy_count=0;
wait_queue_head_t wait_list;

int init_module(void)
{	
	int i;
	//SET_MODULE_OWNER(&fops);
	int retval = register_chrdev(62,"srandom",&fops);
	if (retval < 0)
		return retval;
	DECLARE_WAIT_QUEUE_HEAD(wait_list);
	for (i = 0; i < POOL_SIZE; i++) {
		entropy_pool[i] = 0;
	}
	return 0;
}
void cleanup_module(void)
{
	unregister_chrdev(62,  "srandom");
	return;
}

/*static int device_open(struct inode *, struct file *) { 
	
	return 0;
}
static int device_release(struct inode *, struct file *) {

	return 0;
}
*/

static ssize_t device_read(struct file * flip, char * buffer, size_t n, loff_t * f_pos) {
	if (n == 0) {
		return 0;
	}
	if (buffer == NULL) {
		return -EINVAL;
	}
	while (entropy_count < 8) {
		wait_event_interruptible(wait_list, entropy_count >= 8);
	}
	if (signal_pending(current) != 0)
		return -ERESTARTSYS;

	int E = entropy_count / 8;
	if (n > E) {
		n = E;
	}
	entropy_count -= 8 * n;
	int i;
	int retval=0;
	char* tmp = kmalloc(READ_CHUNK_SIZE, GFP_KERNEL);
	if (tmp == NULL) {
		return -ENOMEM;
	}
	int last_size = n % READ_CHUNK_SIZE;
	for (i = 0;i < n / READ_CHUNK_SIZE; i++) {
		
		hash_pool(entropy_pool, tmp);
		mix(tmp, READ_CHUNK_SIZE, entropy_pool);
		retval = copy_to_user(buffer +i*READ_CHUNK_SIZE, tmp, READ_CHUNK_SIZE);
		if (retval > 0) { 
			kfree(tmp);
			return -EFAULT;
		}
	}
	hash_pool(entropy_pool, tmp);
	mix(tmp, READ_CHUNK_SIZE, entropy_pool);
	retval = copy_to_user(buffer + i*READ_CHUNK_SIZE, tmp, last_size);
	if (retval > 0) {
		kfree(tmp);
		return -EFAULT;
	}
	kfree(tmp);

	
	return n;

}
static ssize_t device_write(struct file * flip, const char* buffer, size_t n, loff_t * f_pos) {
	if (buffer == NULL) {
		return -EFAULT;
	}
	int full_amount = n / WRITE_CHUNK_SIZE;
	int last_size = n % WRITE_CHUNK_SIZE;
	int retval = 0;
	int i;
	/*check hw4*/
	char* chunk = kmalloc(n, GFP_KERNEL);
	if (chunk == NULL) {
		return -ENOMEM;
	}
	retval = copy_from_user((void*)chunk, buffer, n);
	if (retval > 0) {
		kfree(chunk);
		return -EFAULT;
	}
	for ( i = 0;i < full_amount;i++) {		
		mix(chunk+i*WRITE_CHUNK_SIZE, WRITE_CHUNK_SIZE, entropy_pool);
	}
	mix(chunk+ i*WRITE_CHUNK_SIZE, last_size, entropy_pool);
	kfree(chunk);
	return n;
}
int ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg) {

	switch (cmd) {
	case RNDGETENTCNT:
		return rndgetentcnt((int*)arg);
			break;

	case RNDCLEARPOOL:
		return rndclearpool();
		break;
	case RNDADDENTROPY:
		return rndaddentropy((struct rand_pool_info*)arg);
		break;

	default: return -EINVAL;		
	}
	return 0;
}


int rndgetentcnt(int* p) {
	if (p == NULL) {
		return -EFAULT;
	}
	int retval = copy_to_user(p, &entropy_count, sizeof(int));
	if (retval != 0) {
		return -EFAULT;
	}
	return 0;
}
int rndclearpool() {
	int retval = capable(CAP_SYS_ADMIN);
	if (retval == 0) {
		return -EPERM;
	}
	entropy_count = 0;
	return 0;
}
int rndaddentropy(struct rand_pool_info *p) {	int retval = capable(CAP_SYS_ADMIN);
	if (retval == 0) {
		return -EPERM;
	}	struct rand_pool_info* tmp_info = kmalloc(sizeof(struct rand_pool_info), GFP_KERNEL);	if (p == NULL || p->buf == NULL) {		return -EFAULT;	}	if (tmp_info->entropy_count < 0) {		return -EINVAL;	}	retval = 0;	/*check hw4 what if we can not read buf_size*/	retval =device_write(NULL,(char*)(p->buf),(size_t) p->buf_size, NULL);	if (retval < 0) {		return retval;	}		entropy_count += tmp_info->entropy_count;	/*ADD hw4 add signal wake  VV*/	if (entropy_count > 4096) {		entropy_count = 4096;	}		wake_up_interruptible(&wait_list);	kfree(tmp_info);	return 0;}/*
* Public Domain SHA-1 implementation by Steve Reid <steve@edmweb.com>
*
* Taken from:
*    http://download.redis.io/redis-stable/src/sha1.c
*/



typedef struct {
	__u32 state[5];
	__u32 count[2];
	unsigned char buffer[64];
} SHA1_CTX;

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

/* Hash a single 512-bit block. This is the core of the algorithm. */

void SHA1Transform(__u32 state[5], const unsigned char buffer[64])
{
	__u32 a, b, c, d, e;

	typedef union {
		unsigned char c[64];
		__u32 l[16];
	} CHAR64LONG16;

	CHAR64LONG16 block[1];  /* use array to appear as a pointer */

	memcpy(block, buffer, 64);

	/* Copy context->state[] to working vars */
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];

	/* 4 rounds of 20 operations each. Loop unrolled. */
	R0(a, b, c, d, e, 0); R0(e, a, b, c, d, 1); R0(d, e, a, b, c, 2); R0(c, d, e, a, b, 3);
	R0(b, c, d, e, a, 4); R0(a, b, c, d, e, 5); R0(e, a, b, c, d, 6); R0(d, e, a, b, c, 7);
	R0(c, d, e, a, b, 8); R0(b, c, d, e, a, 9); R0(a, b, c, d, e, 10); R0(e, a, b, c, d, 11);
	R0(d, e, a, b, c, 12); R0(c, d, e, a, b, 13); R0(b, c, d, e, a, 14); R0(a, b, c, d, e, 15);
	R1(e, a, b, c, d, 16); R1(d, e, a, b, c, 17); R1(c, d, e, a, b, 18); R1(b, c, d, e, a, 19);

	R2(a, b, c, d, e, 20); R2(e, a, b, c, d, 21); R2(d, e, a, b, c, 22); R2(c, d, e, a, b, 23);
	R2(b, c, d, e, a, 24); R2(a, b, c, d, e, 25); R2(e, a, b, c, d, 26); R2(d, e, a, b, c, 27);
	R2(c, d, e, a, b, 28); R2(b, c, d, e, a, 29); R2(a, b, c, d, e, 30); R2(e, a, b, c, d, 31);
	R2(d, e, a, b, c, 32); R2(c, d, e, a, b, 33); R2(b, c, d, e, a, 34); R2(a, b, c, d, e, 35);
	R2(e, a, b, c, d, 36); R2(d, e, a, b, c, 37); R2(c, d, e, a, b, 38); R2(b, c, d, e, a, 39);

	R3(a, b, c, d, e, 40); R3(e, a, b, c, d, 41); R3(d, e, a, b, c, 42); R3(c, d, e, a, b, 43);
	R3(b, c, d, e, a, 44); R3(a, b, c, d, e, 45); R3(e, a, b, c, d, 46); R3(d, e, a, b, c, 47);
	R3(c, d, e, a, b, 48); R3(b, c, d, e, a, 49); R3(a, b, c, d, e, 50); R3(e, a, b, c, d, 51);
	R3(d, e, a, b, c, 52); R3(c, d, e, a, b, 53); R3(b, c, d, e, a, 54); R3(a, b, c, d, e, 55);
	R3(e, a, b, c, d, 56); R3(d, e, a, b, c, 57); R3(c, d, e, a, b, 58); R3(b, c, d, e, a, 59);

	R4(a, b, c, d, e, 60); R4(e, a, b, c, d, 61); R4(d, e, a, b, c, 62); R4(c, d, e, a, b, 63);
	R4(b, c, d, e, a, 64); R4(a, b, c, d, e, 65); R4(e, a, b, c, d, 66); R4(d, e, a, b, c, 67);
	R4(c, d, e, a, b, 68); R4(b, c, d, e, a, 69); R4(a, b, c, d, e, 70); R4(e, a, b, c, d, 71);
	R4(d, e, a, b, c, 72); R4(c, d, e, a, b, 73); R4(b, c, d, e, a, 74); R4(a, b, c, d, e, 75);
	R4(e, a, b, c, d, 76); R4(d, e, a, b, c, 77); R4(c, d, e, a, b, 78); R4(b, c, d, e, a, 79);

	/* Add the working vars back into context.state[] */
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;

	/* Wipe variables */
	a = b = c = d = e = 0;

	memset(block, '\0', sizeof(block));
}

/* SHA1Init - Initialize new context */

void SHA1Init(SHA1_CTX* context)
{
	/* SHA1 initialization constants */
	context->state[0] = 0x67452301;
	context->state[1] = 0xEFCDAB89;
	context->state[2] = 0x98BADCFE;
	context->state[3] = 0x10325476;
	context->state[4] = 0xC3D2E1F0;
	context->count[0] = context->count[1] = 0;
}


/* Run your data through this. */

void SHA1Update(SHA1_CTX* context, const unsigned char* data, __u32 len)
{
	__u32 i, j;

	j = context->count[0];
	if ((context->count[0] += len << 3) < j)
		context->count[1]++;
	context->count[1] += (len >> 29);
	j = (j >> 3) & 63;
	if ((j + len) > 63) {
		memcpy(&context->buffer[j], data, (i = 64 - j));
		SHA1Transform(context->state, context->buffer);
		for (; i + 63 < len; i += 64) {
			SHA1Transform(context->state, &data[i]);
		}
		j = 0;
	}
	else i = 0;
	memcpy(&context->buffer[j], &data[i], len - i);
}

/* Add padding and return the message digest. */

void SHA1Final(unsigned char digest[20], SHA1_CTX* context)
{
	unsigned i;
	unsigned char finalcount[8];
	unsigned char c;

	for (i = 0; i < 8; i++) {
		finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)]
			>> ((3 - (i & 3)) * 8)) & 255);  /* Endian independent */
	}
	c = 0200;
	SHA1Update(context, &c, 1);
	while ((context->count[0] & 504) != 448) {
		c = 0000;
		SHA1Update(context, &c, 1);
	}
	SHA1Update(context, finalcount, 8);  /* Should cause a SHA1Transform() */
	for (i = 0; i < 20; i++) {
		digest[i] = (unsigned char)
			((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
	}
	/* Wipe variables */
	memset(context, '\0', sizeof(*context));
	memset(&finalcount, '\0', sizeof(finalcount));
}

void hash_pool(const void *pooldata, void *out)
{
	SHA1_CTX ctx;

	SHA1Init(&ctx);
	SHA1Update(&ctx, pooldata, 512);
	SHA1Final(out, &ctx);
}





/*mix*/


static inline __u32 rol32(__u32 word, unsigned int shift)
{
	return (word << shift) | (word >> ((-shift) & 31));
}

static unsigned short rotate_bits = 0;
static unsigned short pool_index = 0;

static const __u32 twist_table[8] = {
	0x00000000,
	0x3b6e20c8,
	0x76dc4190,
	0x4db26158,
	0xedb88320,
	0xd6d6a3e8,
	0x9b64c2b0,
	0xa00ae278
};

void mix(const void *in, size_t nbytes, void *pooldata)
{
	__u32 *pool = pooldata;
	const char *bytes = in;

	while (nbytes--) {
		__u32 w = rol32(*bytes++, rotate_bits);

		pool_index = (pool_index - 1) & 127;

		w ^= pool[pool_index];
		w ^= pool[(pool_index + 104) & 127];
		w ^= pool[(pool_index + 76) & 127];
		w ^= pool[(pool_index + 51) & 127];
		w ^= pool[(pool_index + 25) & 127];
		w ^= pool[(pool_index + 1) & 127];

		pool[pool_index] = (w >> 3) ^ twist_table[w & 7];

		rotate_bits = (rotate_bits + (pool_index ? 7 : 14)) & 31;
	}
}
