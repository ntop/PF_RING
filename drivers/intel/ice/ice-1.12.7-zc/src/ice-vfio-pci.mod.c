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
	{ 0x4cf819e6, "module_layout" },
	{ 0x696f0c3, "kmalloc_caches" },
	{ 0x1603a6b4, "vfio_pci_core_match" },
	{ 0xf9416a26, "vfio_pci_core_err_handlers" },
	{ 0xa8fb2ab1, "vfio_pci_core_finish_enable" },
	{ 0x4ed07420, "vfio_pci_core_close_device" },
	{ 0x94f9f484, "ice_migration_suspend_vf" },
	{ 0x86777e4, "vfio_unregister_notifier" },
	{ 0x76a211cd, "vfio_pci_register_dev_region" },
	{ 0x469fd558, "vfio_register_notifier" },
	{ 0x6b10bee1, "_copy_to_user" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x26dcb8c2, "ice_migration_get_vf" },
	{ 0xfdc4e7aa, "vfio_pci_core_ioctl" },
	{ 0x904354ef, "pci_iounmap" },
	{ 0xe69bda93, "vfio_pci_core_read" },
	{ 0x403cc389, "ice_migration_save_devstate" },
	{ 0xd4a22cbe, "vfio_pci_core_disable" },
	{ 0x9682c984, "ice_migration_uninit_vf" },
	{ 0xac7ab837, "_dev_err" },
	{ 0xb9218de3, "vfio_pci_core_request" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0xe740fbad, "_dev_info" },
	{ 0x5630ba7f, "vfio_pci_core_unregister_device" },
	{ 0x7c74333f, "vfio_pci_core_register_device" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0xb8b9f817, "kmalloc_order_trace" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xc0b2bc48, "pci_unregister_driver" },
	{ 0x4f00afd3, "kmem_cache_alloc_trace" },
	{ 0xe5ad994f, "vfio_pci_core_init_device" },
	{ 0x37a0cba, "kfree" },
	{ 0x3790c63b, "ice_migration_init_vf" },
	{ 0x433f0b06, "__pci_register_driver" },
	{ 0xbe1c83e0, "vfio_pci_core_mmap" },
	{ 0xd6928da2, "pci_iomap" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0x6dc5ee87, "vfio_pci_core_write" },
	{ 0x407f20a8, "vfio_pci_core_enable" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0x3b80ec24, "ice_migration_restore_devstate" },
	{ 0xbd02d3d, "vfio_pci_core_uninit_device" },
};

MODULE_INFO(depends, "ice");

MODULE_ALIAS("vfio_pci:v00008086d00001889sv*sd*bc*sc*i*");

MODULE_INFO(srcversion, "8954801294C70D6ABC3DBA8");
