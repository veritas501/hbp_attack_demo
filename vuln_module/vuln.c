#include "linux/printk.h"
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

MODULE_AUTHOR("veritas");
MODULE_LICENSE("Dual BSD/GPL");

static long vuln_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct {
        uint64_t addr;
        uint64_t val;
    } u;

    long ret = 0;
    if (copy_from_user(&u, (void *)arg, sizeof(u))) {
        return -1;
    }

    // write anything anywhere
    // pr_err("Arb Write [0x%016llx] = 0x%016llx\n", u.addr, u.val);
    *(uint64_t *)(u.addr) = u.val;

    return ret;
}

static struct file_operations vuln_fops = {.owner = THIS_MODULE,
                                           .open = NULL,
                                           .release = NULL,
                                           .read = NULL,
                                           .write = NULL,
                                           .unlocked_ioctl = vuln_ioctl};

static struct miscdevice vuln_miscdev = {
    .minor = MISC_DYNAMIC_MINOR, .name = "vuln", .fops = &vuln_fops};

static int __init vuln_init(void) {
    pr_info("vuln: module init.\n");
    misc_register(&vuln_miscdev);
    return 0;
}

static void __exit vuln_exit(void) {
    pr_info("vuln: module exit.\n");
    misc_deregister(&vuln_miscdev);
}

module_init(vuln_init);
module_exit(vuln_exit);