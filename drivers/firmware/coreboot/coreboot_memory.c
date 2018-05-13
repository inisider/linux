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
} __packed;

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

struct lb_mem_range {
        struct lb_uint64 start;
        struct lb_uint64 size;
        uint32_t type;
#define LB_MEM_RAM               1      /* Memory anyone can use */
#define LB_MEM_RESERVED          2      /* Don't use this mem region */
#define LB_MEM_ACPI              3      /* ACPI Tables */
#define LB_MEM_NVS               4      /* ACPI NVS Memory */
#define LB_MEM_UNUSABLE          5      /* Unusable address space */
#define LB_MEM_VENDOR_RSVD       6      /* Vendor Reserved */
#define LB_MEM_TABLE            16    /* Ram configuration tables are kept in */
} __packed;

struct lb_mem {
        uint32_t tag;
        uint32_t size;
        struct lb_mem_range map[0];
} __packed;

extern struct kobject *cb_kobj;

static ssize_t mem_tbl_read(struct file *filp, struct kobject *kobp,
			       struct bin_attribute *bin_attr, char *buf,
			       loff_t pos, size_t count)
{
	pr_info("mem_tbl_read!!!()\n");
	return 0;
}

static struct bin_attribute mem_tbl_bin_attr = {
	.attr = {.name = "mem", .mode = 0444},
	.read = mem_tbl_read,
};

static int convert_mem_table_to_buf(struct lb_mem *entry)
{
	int ret;
	uint32_t entries;

        entries = (entry->size - sizeof(*entry)) / sizeof(entry->map[0]);
        pr_debug("real number of entries: 0x%x\n", entries);

	// TODO: implement current function
	ret = -EINVAL;

	return ret;
}

static int __init cb_mem_tbl_init(void)
{
	int ret;
	struct lb_mem *entry;
	uint32_t entries;
	uint32_t len;
	void *mem_table;

	pr_debug("cb_mem_tbl_init()\n");

	len = sizeof(*entry) + sizeof(entry->map[0]) * MAX_NUM_ENTRIES;
	mem_table = kmalloc(len, GFP_KERNEL);
	if (!mem_table) {
		pr_err("there is no mem for coreboot memory table\n");
		ret = -ENOMEM;
		goto cb_mem_tbl_init_err;
	}

	ret = coreboot_table_find(LB_TAG_MEMORY, mem_table, len);
	if (ret) {
		// it is not possible to detect how many entries will be
		// in mem table because coreboot_table_find() function
		// returns the entrire mem table, so it should have
		// enough mem where to copy.
		pr_err("coreboot mem table was not found"
			"or there is not enough mem"
			"try to increate MAX_NUM_ENTRIES\n");
		goto cb_mem_tbl_init_err;
	}

	entry = mem_table;

	pr_debug("tag: 0x%x, size: 0x%x\n",
		entry->tag,
		entry->size);

	ret = convert_mem_table_to_buf(entry);
	if (ret) {
		pr_err("convert mem table to buf failed\n");
		goto cb_mem_tbl_init_err;
	}

	ret = sysfs_create_bin_file(cb_kobj, &mem_tbl_bin_attr);
	if (ret) {
		pr_err("sysfs_create_bin_file() failed for for file: %s\n",
			mem_tbl_bin_attr.attr.name);
		goto cb_mem_tbl_init_err;
	}

cb_mem_tbl_init_err:
	if (mem_table)
		kfree(mem_table);

	return ret;
}

static void __exit cb_mem_tbl_exit(void)
{
	sysfs_remove_bin_file(cb_kobj, &mem_tbl_bin_attr);
} 

module_init(cb_mem_tbl_init);
module_exit(cb_mem_tbl_exit);

MODULE_AUTHOR("Oleksii Kurochko<oleksii.kurochko@gmail.com>");
MODULE_LICENSE("GPL");
