#pragma once

#include <linux/module.h>
#include <linux/kernel.h> /* for using printk */
MODULE_LICENSE("GPL");
ssize_t read(struct file *filp, char *buff, size_t	count, loff_t *offp);
ssize_t write(struct file *filp, const char *buff,	size_t count, loff_t *offp);