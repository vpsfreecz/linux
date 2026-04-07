// SPDX-License-Identifier: GPL-2.0
/*
 * Provide kernel BTF information for introspection and use by eBPF tools.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/vmalloc.h>

/* See scripts/link-vmlinux.sh, gen_btf() func for details */
extern char __start_BTF[];
extern char __stop_BTF[];

static void *btf_vmlinux_container_view __ro_after_init;

static size_t btf_raw_type_size(const struct btf_type *type)
{
	size_t extra;

	switch (BTF_INFO_KIND(type->info)) {
	case BTF_KIND_INT:
		extra = sizeof(u32);
		break;
	case BTF_KIND_PTR:
	case BTF_KIND_FWD:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_FUNC:
	case BTF_KIND_FLOAT:
	case BTF_KIND_TYPE_TAG:
		extra = 0;
		break;
	case BTF_KIND_ARRAY:
		extra = sizeof(struct btf_array);
		break;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		extra = sizeof(struct btf_member) * BTF_INFO_VLEN(type->info);
		break;
	case BTF_KIND_ENUM:
		extra = sizeof(struct btf_enum) * BTF_INFO_VLEN(type->info);
		break;
	case BTF_KIND_FUNC_PROTO:
		extra = sizeof(struct btf_param) * BTF_INFO_VLEN(type->info);
		break;
	case BTF_KIND_VAR:
		extra = sizeof(struct btf_var);
		break;
	case BTF_KIND_DATASEC:
		extra = sizeof(struct btf_var_secinfo) * BTF_INFO_VLEN(type->info);
		break;
	case BTF_KIND_DECL_TAG:
		extra = sizeof(struct btf_decl_tag);
		break;
	case BTF_KIND_ENUM64:
		extra = sizeof(struct btf_enum64) * BTF_INFO_VLEN(type->info);
		break;
	default:
		return 0;
	}

	return sizeof(*type) + extra;
}

static bool btf_raw_tracepoint_func(const char *name)
{
	return str_has_prefix(name, "__probestub_") ||
	       str_has_prefix(name, "__traceiter_");
}

static int __init btf_vmlinux_init_container_view(size_t size)
{
	const struct btf_header *header = (const void *)__start_BTF;
	const char *strings;
	size_t type_start, type_end, string_start, string_end;
	size_t offset;
	void *view;

	if (size < sizeof(*header) || header->magic != BTF_MAGIC ||
	    header->version != BTF_VERSION || header->hdr_len < sizeof(*header) ||
	    check_add_overflow((size_t)header->hdr_len,
			       (size_t)header->type_off, &type_start) ||
	    check_add_overflow(type_start, (size_t)header->type_len, &type_end) ||
	    check_add_overflow((size_t)header->hdr_len,
			       (size_t)header->str_off, &string_start) ||
	    check_add_overflow(string_start, (size_t)header->str_len, &string_end) ||
	    type_end > size || string_end > size)
		return -EINVAL;

	view = vzalloc(PAGE_ALIGN(size));
	if (!view)
		return -ENOMEM;
	memcpy(view, __start_BTF, size);
	strings = __start_BTF + string_start;

	for (offset = type_start; offset < type_end; ) {
		const struct btf_type *type = (const void *)(__start_BTF + offset);
		struct btf_type *projected_type = view + offset;
		size_t type_size;
		const char *name;

		if (type_end - offset < sizeof(*type))
			goto invalid;
		type_size = btf_raw_type_size(type);
		if (!type_size || type_size > type_end - offset)
			goto invalid;

		if (BTF_INFO_KIND(type->info) == BTF_KIND_FUNC &&
		    type->name_off < header->str_len) {
			name = strings + type->name_off;
			if (!memchr(name, '\0', header->str_len - type->name_off))
				goto invalid;
			if (btf_raw_tracepoint_func(name) &&
			    !bpf_token_allow_container_tracing_symbol_discovery(name))
				projected_type->name_off = 0;
		}

		offset += type_size;
	}

	btf_vmlinux_container_view = view;
	return 0;

invalid:
	vfree(view);
	return -EINVAL;
}

static ssize_t btf_sysfs_vmlinux_read(struct file *file, struct kobject *kobj,
				      const struct bin_attribute *attr,
				      char *buf, loff_t off, size_t count)
{
	const void *source = attr->private;

	if (bpf_token_current_restrict_tracing_symbols()) {
		if (!btf_vmlinux_container_view)
			return -EACCES;
		source = btf_vmlinux_container_view;
	}

	memcpy(buf, source + off, count);
	return count;
}

static int btf_sysfs_vmlinux_mmap(struct file *filp, struct kobject *kobj,
				  const struct bin_attribute *attr,
				  struct vm_area_struct *vma)
{
	unsigned long pages = PAGE_ALIGN(attr->size) >> PAGE_SHIFT;
	size_t vm_size = vma->vm_end - vma->vm_start;
	phys_addr_t addr = __pa_symbol(__start_BTF);
	unsigned long pfn = addr >> PAGE_SHIFT;

	if (attr->private != __start_BTF || !PAGE_ALIGNED(addr))
		return -EINVAL;

	if (vma->vm_pgoff)
		return -EINVAL;

	if (vma->vm_flags & (VM_WRITE | VM_EXEC | VM_MAYSHARE))
		return -EACCES;

	if (bpf_token_current_restrict_tracing_symbols()) {
		if (!btf_vmlinux_container_view)
			return -EACCES;
		if (vm_size > PAGE_ALIGN(attr->size))
			return -EINVAL;

		vm_flags_mod(vma, VM_DONTDUMP, VM_MAYEXEC | VM_MAYWRITE);
		return remap_vmalloc_range(vma, btf_vmlinux_container_view, 0);
	}

	if (pfn + pages < pfn)
		return -EINVAL;

	if ((vm_size >> PAGE_SHIFT) > pages)
		return -EINVAL;

	vm_flags_mod(vma, VM_DONTDUMP, VM_MAYEXEC | VM_MAYWRITE);
	return remap_pfn_range(vma, vma->vm_start, pfn, vm_size, vma->vm_page_prot);
}

static struct bin_attribute bin_attr_btf_vmlinux __ro_after_init = {
	.attr = { .name = "vmlinux", .mode = 0444, },
	.read = btf_sysfs_vmlinux_read,
	.mmap = btf_sysfs_vmlinux_mmap,
};

struct kobject *btf_kobj;

static int __init btf_vmlinux_init(void)
{
	bin_attr_btf_vmlinux.private = __start_BTF;
	bin_attr_btf_vmlinux.size = __stop_BTF - __start_BTF;

	if (bin_attr_btf_vmlinux.size == 0)
		return 0;

	btf_vmlinux_init_container_view(bin_attr_btf_vmlinux.size);

	btf_kobj = kobject_create_and_add("btf", kernel_kobj);
	if (!btf_kobj)
		return -ENOMEM;

	return sysfs_create_bin_file(btf_kobj, &bin_attr_btf_vmlinux);
}

subsys_initcall(btf_vmlinux_init);
