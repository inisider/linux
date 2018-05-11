#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "../google/coreboot_table.h"

#define IRQ_TABLE_BUF_SIZE	(0x1000)
#define COREBOOT_IRQ_TABLE_ID	(0x49525154)

#define PIRQ_SIGNATURE  (('$' << 0) + ('P' << 8) + ('I' << 16) + ('R' << 24))
#define PIRQ_VERSION 0x0100

struct irq_info {
        u8 bus, devfn;      /* Bus, device and function */
        struct {
                u8 link;    /* IRQ line ID, chipset dependent, 0=not routed */
                u16 bitmap; /* Available IRQs */
        } __packed irq[4];
        u8 slot;            /* Slot number, 0=onboard */
        u8 rfu;
} __packed;

struct irq_routing_table {
        u32 signature;          /* PIRQ_SIGNATURE should be here */
        u16 version;            /* PIRQ_VERSION */
        u16 size;               /* Table size in bytes */
        u8  rtr_bus, rtr_devfn; /* Where the interrupt router lies */
        u16 exclusive_irqs;     /* IRQs devoted exclusively to PCI usage */
        u16 rtr_vendor, rtr_device;/* Vendor/device ID of interrupt router */
        u32 miniport_data;
        u8  rfu[11];
        u8  checksum;           /* Modulo 256 checksum must give zero */
        struct irq_info slots[0]; /* instead of 0 was CONFIG_IRQ_SLOT_COUNT */
				/* CONFIG_IRQ_SLOT_COUNT defined in coreboot */
				/* source code */
} __packed;

extern struct kobject *cb_kobj;
static char irq_table_buf[IRQ_TABLE_BUF_SIZE] = {0}; // maybe as static variable it will be 0 by default??
static u32 irq_table_indx;

static ssize_t irq_tbl_read(struct file *filp, struct kobject *kobp,
			       struct bin_attribute *bin_attr, char *buf,
			       loff_t pos, size_t count)
{
	return memory_read_from_buffer(buf, count, &pos,
				irq_table_buf, irq_table_indx);
}

static struct bin_attribute irq_tbl_bin_attr = {
	.attr = {.name = "irq_info", .mode = 0444},
	.read = irq_tbl_read,
};

static int write_to_buf(const char *fmt, ...)
{
	u32 curr_irq_table_buf_size =
		IRQ_TABLE_BUF_SIZE - irq_table_indx;
	va_list args;

	if (!curr_irq_table_buf_size) {
		pr_warn("too small buffer for irq table\n");
		return -EINVAL;
	}

	va_start(args, fmt);
	irq_table_indx += vsnprintf(irq_table_buf + irq_table_indx,
				curr_irq_table_buf_size,
				fmt,
				args);
	va_end(args);

	return 0;
}

static int covert_irq_routing_table_to_buf(struct irq_routing_table *irq_table)
{
	int ret = 0;
	struct irq_info *info;
	u16 irq_slot_num;
	unsigned long table_struct_size;
	unsigned long info_struct_size;
	int i, j;

	ret = write_to_buf(
		"info from coreboot irq table:\n"
		"\tversion: %x\n"
		"\trtr_bus: %u, rtr_devfn: %u\n"
		"\texclusive_irqs: 0x%x\n"
		"\trtr_vendor = 0x%x, rtr_device = 0x%x\n"
		"\tminiport_data: %u\n"
		"\trfu: %08llx%x%x%x\n"
		"\tchecksum: 0x%x\n",
		irq_table->version,
		(u32)irq_table->rtr_bus, (u32)irq_table->rtr_devfn,
		(u32)irq_table->exclusive_irqs,
		(u32)irq_table->rtr_vendor, (u32)irq_table->rtr_device,
		irq_table->miniport_data,
                *(u64 *)(irq_table->rfu + 0),
                (u32)irq_table->rfu[8],
                (u32)irq_table->rfu[9],
                (u32)irq_table->rfu[10],
		irq_table->checksum);

	table_struct_size = sizeof(struct irq_routing_table);
	info_struct_size = sizeof(struct irq_info);
	irq_slot_num =
		(irq_table->size - table_struct_size) / info_struct_size;

	pr_debug("IRQ_SLOT_COUNT = %d\n", irq_slot_num);

	ret = write_to_buf(
		"%s\n\t%s\t\t%s\t\t%s\t\t%s\t\t%s\t\t%s\n",
		"irq info:",
		"bus",
		"devfn",
		"link",
		"bitmap",
		"slot",
		"rfu");

	for (i = 0; i < irq_slot_num; i++) {
		info = (struct irq_info *)(irq_table->slots + i);
		ret = write_to_buf(
			"\t0x%x\t\t0x%x\t\t",
			info->bus, info->devfn);

		ret = write_to_buf(
			"0x%x\t\t0x%x\t\t0x%x\t\t0x%x\n",
			info->irq[0].link,
			info->irq[0].bitmap,
			info->slot,
			info->rfu);
		for (j = 1; j < 4; j++) {
			ret = write_to_buf(
				"\t\t\t\t\t0x%x\t\t0x%x\n",
				info->irq[j].link,
				info->irq[j].bitmap);
		}
	}

	pr_debug("%s\n", irq_table_buf);

	return ret;
}

static int check_irq_table(const struct irq_routing_table *irq_table)
{
	u8 checksum = 0x00;
	u32 i;

        if (irq_table->signature != PIRQ_SIGNATURE) {
                pr_err("signature of coreboot irq table is uncorrect\n");
		return -EINVAL;
        }

	for (i = 0; i < irq_table->size; i++) {
		checksum += *((u8 *)(irq_table) + i);
	}

	pr_debug("irq table checksum=%x\n", checksum);

	return checksum;
}

static int __init cb_irq_tbl_init(void)
{
	int ret;
	struct lb_cbmem_entry entry;
	struct irq_routing_table *irq_table = NULL;

	pr_debug("cb_irq_tbl_init()\n");

	entry.id = COREBOOT_IRQ_TABLE_ID;
	ret = coreboot_table_find(LB_TAG_CBMEM_ENTRY, &entry, sizeof(entry));
	if (ret) {
		pr_err("coreboot IRQ table was not found\n");
		goto cb_irq_tbl_init_err;
	}

	pr_debug("tag: 0x%x, size: 0x%x, cbmem_addr: 0x%llx\n",
		entry.tag,
		entry.entry_size,
		entry.address);

	irq_table = memremap(entry.address, entry.entry_size, MEMREMAP_WB);
	if (!irq_table) {
		pr_err("coreboot irq tables could not be mapped\n");
		ret = -ENOMEM;
		goto cb_irq_tbl_init_err;
	}

	ret = check_irq_table(irq_table);
	if (ret) {
		pr_err("irq table was not verified\n");
		goto cb_irq_tbl_init_err;
	}

	ret = covert_irq_routing_table_to_buf(irq_table);
	if (ret) {
		pr_err("converting of irq routing table failed\n");
		goto cb_irq_tbl_init_err;
	}

	ret = sysfs_create_bin_file(cb_kobj, &irq_tbl_bin_attr);
	if (ret) {
		pr_err("sysfs_create_bin_file() failed for for file: %s\n",
			irq_tbl_bin_attr.attr.name);
		goto cb_irq_tbl_init_err;
	}	

cb_irq_tbl_init_err:
	if (irq_table)
		memunmap(irq_table);

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
