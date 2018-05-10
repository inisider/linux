#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "../google/coreboot_table.h"

#define COREBOOT_IRQ_TABLE_ID (0x49525154)

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

	pr_debug("tag: 0x%x, size: 0x%x, cbmem_addr: 0x%llx\n",
		entry.tag,
		entry.entry_size,
		entry.address);

	// TODO: rework this!
	{
		struct irq_routing_table *irq_table;
		struct irq_info *info;
		u16 irq_slot_num;
		unsigned long table_struct_size;
		unsigned long info_struct_size;
		int i, j;

		irq_table = memremap(entry.address, entry.entry_size, MEMREMAP_WB);
		if (!irq_table) {
			pr_err("coreboot irq tables could not be mapped\n");
			return -ENOMEM;
		}

		if (irq_table->signature != PIRQ_SIGNATURE) {
			pr_err("signature of coreboot irq table is uncorrect\n");
			memunmap(irq_table);
			return -EINVAL;
		}
		// TODO: check checksum

		pr_debug("info from coreboot irq table:\n");
		pr_debug("\tversion: 0x%x\n",
			irq_table->version);
		pr_debug("\trtr_bus: %u, rtr_devfn: %u\n",
			(u32)irq_table->rtr_bus,
			(u32)irq_table->rtr_devfn);
		pr_debug("\texclusive_irqs: 0x%x\n",
			(u32)irq_table->exclusive_irqs);
		pr_debug("\trtr_vendor = 0x%x, rtr_device = 0x%x\n",
			(u32)irq_table->rtr_vendor,
			(u32)irq_table->rtr_device);
		pr_debug("\tminiport_data: %u\n",
			irq_table->miniport_data);

		pr_debug("\trfu: %x %x %x %x %x %x %x %x %x %x %x\n",
			(u32)irq_table->rfu[0],    
			(u32)irq_table->rfu[1],		
			(u32)irq_table->rfu[2],
			(u32)irq_table->rfu[3],
			(u32)irq_table->rfu[4],    
			(u32)irq_table->rfu[5],		
			(u32)irq_table->rfu[6],
			(u32)irq_table->rfu[7],
			(u32)irq_table->rfu[8],    
			(u32)irq_table->rfu[9],		
			(u32)irq_table->rfu[10]);

		pr_debug("\tchecksum: 0x%x\n", irq_table->checksum);
		
		table_struct_size = sizeof(struct irq_routing_table);
		info_struct_size = sizeof(struct irq_info);
		irq_slot_num =
			(irq_table->size - table_struct_size) / info_struct_size;

		pr_debug("IRQ_SLOT_COUNT = %d\n", irq_slot_num);
		pr_debug("irq info:");
		for (i = 0; i < irq_slot_num; i++) {
			info = (struct irq_info *)(irq_table->slots + i);
			pr_debug("\tbus: 0x%x, devfn: 0x%x\n",
				info->bus,
				info->devfn);
			
			for (j = 0; j < 4; j++) {
				pr_debug("\t\t[%d] link: 0x%x, bitmap: 0x%x\n",
					j,
					info->irq[j].link,
					info->irq[j].bitmap);
			}
			
			pr_debug("\tslot: 0x%x\n", info->slot);
			pr_debug("\trfu: 0x%x\n", info->rfu);
		}

		memunmap(irq_table);
	}

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
