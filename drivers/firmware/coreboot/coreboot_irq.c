#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "../google/coreboot_table.h"

#define COREBOOT_IRQ_TABLE_ID (0x49525154)

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
	struct lb_cbmem_entry entry;

	pr_debug("cb_irq_tbl_init()\n");

	entry.id = COREBOOT_IRQ_TABLE_ID;
	ret = coreboot_table_find(LB_TAG_CBMEM_ENTRY, &entry, sizeof(entry));
	if (ret) {
		pr_err("coreboot IRQ table was not found\n");
		return ret;
	}

	pr_info("tag: 0x%x, size: 0x%x, cbmem_addr: 0x%llx\n",
		entry.tag,
		entry.entry_size,
		entry.address);

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
