#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "../google/coreboot_table.h"

#define LB_TAG_MEMORY           (0x0001)
#define MAX_NUM_ENTRIES		(0x10)

struct lb_uint64 {
        uint32_t lo;
        uint32_t hi;
};

static inline uint64_t unpack_lb64(struct lb_uint64 value)
{
        uint64_t result;
        result = value.hi;
        result = (result << 32) + value.lo;
        return result;
}

static inline struct lb_uint64 pack_lb64(uint64_t value)
{
        struct lb_uint64 result;
        result.lo = (value >> 0) & 0xffffffff;
        result.hi = (value >> 32) & 0xffffffff;
        return result;
}

struct lb_memory_range {
        struct lb_uint64 start;
        struct lb_uint64 size;
        uint32_t type;
#define LB_MEM_RAM               1      /* Memory anyone can use */
#define LB_MEM_RESERVED          2      /* Don't use this memory region */
#define LB_MEM_ACPI              3      /* ACPI Tables */
#define LB_MEM_NVS               4      /* ACPI NVS Memory */
#define LB_MEM_UNUSABLE          5      /* Unusable address space */
#define LB_MEM_VENDOR_RSVD       6      /* Vendor Reserved */
#define LB_MEM_TABLE            16    /* Ram configuration tables are kept in */
};

struct lb_memory {
        uint32_t tag;
        uint32_t size;
        struct lb_memory_range map[MAX_NUM_ENTRIES];
};

extern struct kobject *cb_kobj;

static ssize_t memory_tbl_read(struct file *filp, struct kobject *kobp,
			       struct bin_attribute *bin_attr, char *buf,
			       loff_t pos, size_t count)
{
	pr_info("memory_tbl_read!!!()\n");
	return 0;
}

static struct bin_attribute memory_tbl_bin_attr = {
	.attr = {.name = "memory", .mode = 0444},
	.read = memory_tbl_read,
};

static int __init cb_memory_tbl_init(void)
{
	int ret;
	struct lb_memory entry;

	pr_info("cb_memory_tbl_init()\n");

	ret = coreboot_table_find(LB_TAG_MEMORY, &entry, sizeof(entry));
	if (ret) {
		// it is not possible to detect how many entries will be
		// in memory table because coreboot_table_find() function
		// returns the entrire memory table, so it should have 
		// enough memory where to copy.
		pr_err("coreboot memory table was not found"
			"or there is not enough memory"
			"try to increate MAX_NUM_ENTRIES\n");
		goto cb_memory_tbl_init_err;
	}

	pr_info("tag: 0x%x, size: 0x%x\n",
		entry.tag,
		entry.size);

	ret = sysfs_create_bin_file(cb_kobj, &memory_tbl_bin_attr);
	if (ret) {
		pr_err("sysfs_create_bin_file() failed for for file: %s\n",
			memory_tbl_bin_attr.attr.name);
		goto cb_memory_tbl_init_err;
	}	

cb_memory_tbl_init_err:

	return ret;
}

static void __exit cb_memory_tbl_exit(void)
{
	sysfs_remove_bin_file(cb_kobj, &memory_tbl_bin_attr);
} 

module_init(cb_memory_tbl_init);
module_exit(cb_memory_tbl_exit);

MODULE_AUTHOR("Oleksii Kurochko<oleksii.kurochko@gmail.com>");
MODULE_LICENSE("GPL");
