#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/slab.h>

// TODO: rework this ?? how ??
#include <../drivers/firmware/google/coreboot_table.h>

extern struct kobject *cb_kobj;

static ssize_t irq_tbl_read(struct file *filp, struct kobject *kobp,
			       struct bin_attribute *bin_attr, char *buf,
			       loff_t pos, size_t count)
{
	pr_info("irq_tbl_read() \n");

	return 0;
}

static struct bin_attribute irq_tbl_bin_attr = {
	.attr = {.name = "irq", .mode = 0444},
	.read = irq_tbl_read,
};

static int __init cb_irq_tbl_init(void)
{
	int ret;

	pr_debug("cb_irq_tbl_init()\n");

	

	ret = sysfs_create_bin_file(cb_kobj, &irq_tbl_bin_attr);
	if (ret) {
		pr_err("sysfs_create_bin_file() failed for for file: %s\n",
			irq_tbl_bin_attr.attr.name);
		return -EINVAL;
	}	

	return ret;
}

static void __exit cb_irq_tbl_exit(void)
{
	sysfs_remove_bin_file(cb_kobj, &irq_tbl_bin_attr);
} 

module_init(cb_irq_tbl_init);
module_exit(cb_irq_tbl_exit);

MODULE_AUTHOR("Oleksii Kurochko<oleksii.kurochko@gmail.com>");
MODULE_LICENSE("GPL");
