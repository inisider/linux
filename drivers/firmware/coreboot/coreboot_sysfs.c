#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
 
struct kobject *cb_kobj;
EXPORT_SYMBOL_GPL(cb_kobj);

static int __init cb_sysfs_init(void)
{
	pr_debug("cb_sysfs_init()\n");

	if (!cb_kobj)
		cb_kobj = kobject_create_and_add("coreboot", firmware_kobj);
	if (!cb_kobj) {
		pr_err("kobject_create_and_add coreboot failed\n");
		return -EINVAL;
	}

	return 0;
}
 
static void __exit cb_sysfs_exit(void){
	pr_debug("cb_sysfs_exit()\n");

	if (cb_kobj)
		kobject_put(cb_kobj);
}
 
module_init(cb_sysfs_init);
module_exit(cb_sysfs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Oleksii Kurochko <oleksii.kurochko@gmail.com>");
MODULE_DESCRIPTION("A sysfs Linux driver that provide access to cb tables.");
MODULE_VERSION("0.1");
