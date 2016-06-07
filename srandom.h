#ifndef srandom
#define srandom

#include <linux/module.h>
#include <linux/kernel.h> /* for using printk */
//#include <linux/fs.h>
MODULE_LICENSE("GPL");
//ssize_t read(struct file *filp, char *buff, size_t	count, loff_t *offp);
//ssize_t write(struct file *filp, const char *buff,	size_t count, loff_t *offp);
int init_module(void);
void cleanup_module(void);
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);


#endif