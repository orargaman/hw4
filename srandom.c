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
#include "mix.h"
#include "sha1.h"

#include "srandom.h"
#define POOL_SIZE 512
#define WRITE_CHUNK_SIZE 64
#define READ_CHUNK_SIZE 20

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
int entropy_count;
wait_queue_head_t wait_list;

int init_module(void)
{	
	
	//SET_MODULE_OWNER(&fops);
	int retval = register_chrdev(62,"srandom",&fops);
	if (retval < 0)
		return retval;
	DECLARE_WAIT_QUEUE_HEAD(wait_list);
	return 0;
}
void cleanup_module(void)
{
	unregister_chrdev(62,  "srandom");

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
	
	int result=wait_event_interruptible(wait_list, n >= 8);
	if (result != 0) {
		return -ERESTARTSYS;
	}

	int E = entropy_count / 8;
	if (n > E) {
		n = E;
	}
	entropy_count -= 8 * n;
	int i;
	int retval=0;
	char* tmp = kmalloc(READ_CHUNK_SIZE, GFP_KERNEL);
	int last_size = n % READ_CHUNK_SIZE;
	for (i = 0;i < n / READ_CHUNK_SIZE; i++) {
		
		hash_pool(entropy_pool, tmp);
		mix(tmp, READ_CHUNK_SIZE, entropy_pool);
		retval = copy_to_user(buffer +i*READ_CHUNK_SIZE, tmp, READ_CHUNK_SIZE);
		if (retval > 0) { 
			return -EFAULT;
		}
	}
	hash_pool(entropy_pool, tmp);
	mix(tmp, READ_CHUNK_SIZE, entropy_pool);
	retval = copy_to_user(buffer + n / READ_CHUNK_SIZE, tmp, last_size);
	if (retval > 0) {
		return -EFAULT;
	}
	kfree(tmp);

	
	return 0;

}
static ssize_t device_write(struct file * flip, const char* buffer, size_t n, loff_t * f_pos) {
	int full_amount = n / WRITE_CHUNK_SIZE;
	int last_size = n % WRITE_CHUNK_SIZE;
	int retval = 0;
	int i;
	/*check hw4*/
	char* chunk = kmalloc(WRITE_CHUNK_SIZE, GFP_KERNEL);
	for ( i = 0;i < full_amount;i++) {
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
	kfree(chunk);
	return 0;
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
	}	if (p == NULL || p->buf == NULL) {		return -EFAULT;	}	if (p->entropy_count < 0) {		return -EINVAL;	}	retval = 0;	/*check hw4 what if we can not read buf_size*/	retval =device_write(NULL,(char*) p->buf,(size_t) p->buf_size, NULL);	if (retval != 0) {		return retval;	}		entropy_count += p->entropy_count;	/*ADD hw4 add signal wake  VV*/	if (entropy_count >= 8) {		wake_up_interruptible(&wait_list);	}	if (entropy_count > 4096) {		entropy_count = 4096;	}	return 0;}