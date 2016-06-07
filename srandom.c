#include <stdio.h>
#include "srandom.h"

static struct file_operations fops = {
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release
};

int init_module(void)
{
	SET_MODULE_OWNER(&fops);
	printk("Hello, World\n");
	register_chrdev(62,"srandom",&fops);
	return 0;
}
void cleanup_module(void)
{
	unregister_chrdev(62,  "srandom");
	printk("Goodbye cruel world\n");
}

static int device_open(struct inode *, struct file *) { return 0; }
static int device_release(struct inode *, struct file *) {
	return 0;
}
static ssize_t device_read(struct file *, char *, size_t, loff_t *) { return 0; }
static ssize_t device_write(struct file *, const char *, size_t, loff_t *) { return 0; }