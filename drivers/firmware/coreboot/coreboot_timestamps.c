#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/cpufreq.h>
#include <linux/slab.h>

#include "timestamp.h"

#include "../google/coreboot_table.h"

#define CB_TAG_TIMESTAMPS   0x0016

struct ts_entry {
	uint32_t id;
	uint64_t stamp;
	uint64_t prev_stamp;
	char *name;
}

extern struct kobject *cb_kobj;
static unsigned long tick_freq_mhz;

static char *ts_tbl_buf;
static uint32_t curr_ts_tbl_buf_indx;
#define PARSED_TS_TBL_SIZE (4096)

static ssize_t ts_tbl_read(struct file *filp, struct kobject *kobp,
			       struct bin_attribute *bin_attr, char *buf,
			       loff_t pos, size_t count)
{
	pr_debug("ts_tbl_read() \n");

	return memory_read_from_buffer(buf, count, &pos,
				ts_tbl_buf, curr_ts_tbl_buf_indx);
}

static struct bin_attribute ts_tbl_bin_attr = {
	.attr = {.name = "timestamps", .mode = 0444},
	.read = ts_tbl_read,
};

static int ts_set_tick_freq(unsigned long table_tick_freq_mhz)
{
	int ret = 0;

	tick_freq_mhz = table_tick_freq_mhz;

	if (!tick_freq_mhz) {
//		tick_freq_mhz = arch_set_tick_frequency();
		struct cpufreq_policy *cpufreq_policy;

//		pr_info("cpu_khz = %d\n", cpu_khz);

		cpufreq_policy = cpufreq_cpu_get(0);
		if (cpufreq_policy) {
			pr_debug("max1 = %d, max2 = %d\n",
				cpufreq_policy->max,
				cpufreq_policy->cpuinfo.max_freq);

			tick_freq_mhz = cpufreq_policy->cpuinfo.max_freq;

			cpufreq_cpu_put(cpufreq_policy);
		} else {
			pr_debug("cpufreq policy is NULL; looks like U are "
				"using QEMU\n");
			// for QEMU case where there is no scaling, seems that
			// cpu_khz is the maximum frequency
			tick_freq_mhz = cpu_khz / 1000;
		}

		ret = 1;
	}

	if (!tick_freq_mhz) {
		pr_err("Cannot determine timestamp tick frequency\n");
		ret = 0;
	}

	pr_debug("Timestamp tick frequency: %ld MHz\n", tick_freq_mhz);

	return ret;
}

static struct timestamp_table* cb_ts_tbl_map(phys_addr_t physaddr)
{
	struct timestamp_table *ts_tbl;
	size_t size;

	size = sizeof(*ts_tbl);
	ts_tbl = memremap(physaddr, size, MEMREMAP_WB);
	if (!ts_tbl) {
		pr_err("(1) timestamp table could not be mapped\n");
		return ts_tbl;
	}

	pr_debug("number of entries in coreboot timestamp table: %d\n", ts_tbl->num_entries);

	size += ts_tbl->num_entries * sizeof(ts_tbl->entries[0]);

	pr_debug("size of coreboot timestamp table: 0x%lx\n", size);

	if (!ts_set_tick_freq(ts_tbl->tick_freq_mhz)) {
		memunmap(ts_tbl);
		return NULL;
	}

	memunmap(ts_tbl);

	ts_tbl = memremap(physaddr, size, MEMREMAP_WB);
	if (!ts_tbl) {
		pr_err("(2) timestamp table could not be mapped\n");
		return ts_tbl;
	}

	return ts_tbl;
}

uint64_t convert_raw_ts_entry(uint64_t ts)
{
	return ts / tick_freq_mhz;
}

static const char *ts_name(uint32_t id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(timestamp_ids); i++) {
		if (timestamp_ids[i].id == id)
			return timestamp_ids[i].name;
	}

	return "<unknown>";
}

static void write_to_ts_tbl_buf(const char *fmt, ...)
{
	va_list args;
	uint32_t curr_ts_tbl_buf_size = PARSED_TS_TBL_SIZE - curr_ts_tbl_buf_indx;

	if (!curr_ts_tbl_buf_size) {
		pr_warn("too small buffer for timestamp table\n");
		return;
	}

	va_start(args, fmt);
	curr_ts_tbl_buf_indx += vsnprintf(ts_tbl_buf + curr_ts_tbl_buf_indx,
				curr_ts_tbl_buf_size,
				fmt,
				args);
	va_end(args);
}

static uint64_t ts_get_entry(struct ts_entry *ts_entry,
			uint32_t id, uint64_t stamp, uint64_t prev_stamp)
{
	ts_entry->name = ts_name(id);
	ts_entry->step_time = convert_raw_ts_entry(stamp - prev_stamp);
	ts_entry->stamp = convert_raw_ts_entry(stamp);
	ts_entry->id = id;

	/* ID<tab>absolute time<tab>relative time<tab>description */
	pr_debug("%d\t", ts_entry->id);
	pr_debug("%llu\t", ts_entry->stamp);
	pr_debug("%llu\t", ts_entry->step_time);
	pr_debug("%s\n", ts_entry->name);

	return ts_entry->step_time;
}

void parse_ts_table(struct timestamp_table *ts_tbl)
{
	struct ts_entry ts_entry;
	uint64_t prev_stamp = 0;
	uint64_t total_time = 0;
	int i;

	write_to_ts_tbl_buf("%s\t%s\t%s\t%s\n",
			"ID", "Absolute time", "Relative time", "Description");

	/* Report the base time within the table. */
	ts_get_entry(&ts_entry, 0,  ts_tbl->base_time, prev_stamp);

	write_to_ts_tbl_buf("%d\t%llu\t\t%llu\t\t%s\n",
			ts_entry->id, ts_entry->stamp,
			ts_entry->step_time, ts_etnry->name);

	prev_stamp = ts_tbl->base_time;

	for (i = 0; i < ts_tbl->num_entries; i++) {
		uint64_t stamp;
		const struct timestamp_entry *tse = &ts_tbl->entries[i];

		/* Make all timestamps absolute. */
		stamp = tse->entry_stamp + ts_tbl->base_time;
		total_time += ts_get_entry(&ts_entry,
					tse->entry_id, stamp, prev_stamp);

		write_to_ts_tbl_buf("%d\t%llu\t\t%llu\t\t%s\n",
			ts_entry->id, ts_entry->stamp,
			ts_entry->step_time, ts_etnry->name);

		prev_stamp = stamp;
	}
}

static int __init cb_ts_tbl_init(void)
{
	int ret;
	struct lb_cbmem_ref entry;
	struct timestamp_table *ts_tbl;

	pr_debug("cb_ts_tbl_init()\n");

	ret = coreboot_table_find(CB_TAG_TIMESTAMPS, &entry, sizeof(entry));
	if (ret) {
		pr_err("timestamp table was not found\n");
		return ret;
	}

	pr_debug("tag: 0x%x, size: 0x%x, cbmem_addr: 0x%llx\n",
		entry.tag,
		entry.size,
		entry.cbmem_addr);

	ts_tbl = cb_ts_tbl_map(entry.cbmem_addr);
	if (!ts_tbl) {
		pr_err("coreboot timestamp table was not mapped\n");
		return -ENOMEM;
	}

	ts_tbl_buf = kzalloc(PARSED_TS_TBL_SIZE, GFP_KERNEL);
	if (!ts_tbl_buf) {
		pr_err("memory for parsed timestamp table was not allocated\n");
		ret = -ENOMEM;
		goto cb_ts_tbl_init_err;
	}

	parse_ts_table(ts_tbl);

	memunmap(ts_tbl);

	ret = sysfs_create_bin_file(cb_kobj, &ts_tbl_bin_attr);
	if (ret) {
		pr_err("sysfs_create_bin_file() failed for for file: %s\n",
			ts_tbl_bin_attr.attr.name);
		ret = -EINVAL;
		goto cb_ts_tbl_init_err;
	}

	return ret;

cb_ts_tbl_init_err:
	if (ts_tbl)
		memunmap(ts_tbl);
	if (ts_tbl_buf)
		memunmap(ts_tbl_buf);
	return ret;
}

static void __exit cb_ts_tbl_exit(void)
{
	sysfs_remove_bin_file(cb_kobj, &ts_tbl_bin_attr);

	if (ts_tbl_buf)
		kfree(ts_tbl_buf);
} 

module_init(cb_ts_tbl_init);
module_exit(cb_ts_tbl_exit);

MODULE_AUTHOR("Oleksii Kurochko<oleksii.kurochko@gmail.com>");
MODULE_LICENSE("GPL");
