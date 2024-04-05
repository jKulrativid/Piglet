#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x4c1a7013, "module_layout" },
	{ 0xcf91a422, "param_ops_int" },
	{ 0x7f9e60da, "platform_driver_unregister" },
	{ 0xc7d93ae1, "__platform_driver_register" },
	{ 0xdcb764ad, "memset" },
	{ 0x5c1c3eb4, "cpu_hwcaps" },
	{ 0x12a4e128, "__arch_copy_from_user" },
	{ 0xb788fb30, "gic_pmr_sync" },
	{ 0x5e2d7875, "cpu_hwcap_keys" },
	{ 0x14b89635, "arm64_const_caps_ready" },
	{ 0xc5b6f236, "queue_work_on" },
	{ 0x2d3385d3, "system_wq" },
	{ 0xff89440, "dmam_alloc_attrs" },
	{ 0xdbbfc349, "device_create" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0xf9c0b663, "strlcat" },
	{ 0x3c3e92e3, "__class_create" },
	{ 0x37195461, "cdev_add" },
	{ 0xecf9891d, "cdev_init" },
	{ 0xe3ec2f2b, "alloc_chrdev_region" },
	{ 0xb8cd0e13, "dma_request_chan" },
	{ 0xb1b88f6d, "device_property_read_string_array" },
	{ 0x3299aa3e, "_dev_err" },
	{ 0xd800f6ed, "devm_kmalloc" },
	{ 0x8da6585d, "__stack_chk_fail" },
	{ 0x4a3ad70e, "wait_for_completion_timeout" },
	{ 0x608741b5, "__init_swait_queue_head" },
	{ 0xf888ca21, "sg_init_table" },
	{ 0xa6257a2f, "complete" },
	{ 0x9f5a1b18, "dma_mmap_attrs" },
	{ 0x4b0a3f52, "gic_nonsecure_priorities" },
	{ 0xcd4e277b, "dma_release_channel" },
	{ 0x6091b333, "unregister_chrdev_region" },
	{ 0xefb96bd8, "cdev_del" },
	{ 0x6a495d46, "class_destroy" },
	{ 0xebb15dd0, "device_destroy" },
	{ 0x92997ed8, "_printk" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "F9FF24ED6E841648BFA0F14");
