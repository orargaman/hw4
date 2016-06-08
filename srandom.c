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
#include <signal.h>
#include "mix.h"
#include "sha1.h"

#include "srandom.h"
#define POOL_SIZE 512
#define WRITE_CHUNK_SIZE 64
#define READ_CHUNK_SIZE 20
struct file_operations fops = {
	.open = my_open,
	/*.release = device_release,
	.read = device_read,
	.write = device_write,
	.llseek = NULL,
	.ioctl = my_ioctl,
	.owner = THIS_MODULE,*/
};

char entropy_pool[POOL_SIZE];
int entropy_count;

int init_module(void)
{	
	
	//SET_MODULE_OWNER(&fops);
	printk("Hello, World\n");
	int retval = register_chrdev(62,"srandom",&fops);
	if (retval < 0)
		return retval;
	return 0;
}
void cleanup_module(void)
{
	unregister_chrdev(62,  "srandom");
	printk("Goodbye cruel world\n");
}

static int device_open(struct inode *, struct file *) { 
	
	return 0;
}
static int device_release(struct inode *, struct file *) {

	return 0;
}

static ssize_t device_read(struct file *, char * buffer, size_t n, loff_t *) { 
	if (n == 0) {
		return 0;
	}
	sigset_t set;
	int retval = 0;
	sigemptyset(&set);


	while (entropy_pool < 8) {
		/*check hw4 take care of signals*/
		retval = sigpending(&set);
		if (retval < 0) {
			return -EFAULT;
		}
	}
	int E = entropy_count / 8;
	if (n > E) {
		n = E;
	}
	entropy_count -= 8 * n;
	char* read_chunk = kmalloc(READ_CHUNK_SIZE, GFP_KERNEL);
	int last_size = n % READ_CHUNK_SIZE;
	for (int i = 0;i < n / READ_CHUNK_SIZE; i++) {
		retval = copy_from_user((void*)read_chunk, buffer + i*READ_CHUNK_SIZE, READ_CHUNK_SIZE);
		if (retval > 0) {
			return -EFAULT;
		}
		hash_pool(entropy_pool, read_chunk);
		mix(read_chunk, READ_CHUNK_SIZE, entropy_pool);
	}
	/*check hw4 take care of last chunk*/
	
	return 0;

}
static ssize_t device_write(struct file *, const char* buffer, size_t n, loff_t *) {
	int full_amount = n / WRITE_CHUNK_SIZE;
	int last_size = n % WRITE_CHUNK_SIZE;
	int retval = 0;
	/*check hw4*/
	char* chunk = kmalloc(WRITE_CHUNK_SIZE, GFP_KERNEL);
	for (int i = 0;i < full_amount;i++) {
		retval=copy_from_user((void*)chunk, buffer+i*WRITE_CHUNK_SIZE, WRITE_CHUNK_SIZE);
		if (retval > 0) {
			return -EFAULT;
		}
		mix(chunk, WRITE_CHUNK_SIZE, entropy_pool);
	}
	retval = copy_from_user((void*)chunk, buffer, last_size);
	if (retval > 0) {
		return -EFAULT;
	}
	mix(chunk, last_size, entropy_pool);
	free(chunk);
	return 0;
}
