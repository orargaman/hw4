#ifndef _MY_MODULE_H_
#define _MY_MODULE_H_

#define SRANDOM_MAGIC 'r'
static ssize_t device_read(struct file *, char * buffer, size_t n, loff_t *);
static ssize_t device_write(struct file *, const char* buffer, size_t n, loff_t *);
int ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg);
int init_module(void);
void cleanup_module(void);

#include <linux/ioctl.h>


#endif
