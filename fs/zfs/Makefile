include Kbuild

INSTALL_MOD_DIR ?= extra
INSTALL_MOD_PATH ?= $(DESTDIR)

all: modules
distclean maintainer-clean: clean
install: modules_install data_install
uninstall: modules_uninstall data_uninstall
check:

.PHONY: all distclean maintainer-clean install uninstall check distdir \
	modules modules-Linux modules-FreeBSD modules-unknown \
	clean clean-Linux clean-FreeBSD \
	modules_install modules_install-Linux modules_install-FreeBSD \
	data_install data_install-Linux data_install-FreeBSD \
	modules_uninstall modules_uninstall-Linux modules_uninstall-FreeBSD \
	data_uninstall data_uninstall-Linux data_uninstall-FreeBSD \
	cppcheck cppcheck-Linux cppcheck-FreeBSD

# For FreeBSD, use debug options from ./configure if not overridden.
export WITH_DEBUG ?= true
export WITH_INVARIANTS ?= 

# Filter out options that FreeBSD make doesn't understand
getflags = ( \
set -- \
  $(filter-out --%,$(firstword $(MFLAGS))) \
  $(filter -I%,$(MFLAGS)) \
  $(filter -j%,$(MFLAGS)); \
fmakeflags=""; \
while getopts :deiI:j:knqrstw flag; do \
  case $$flag in \
    \?) :;; \
    :) if [ $$OPTARG = "j" ]; then \
	 ncpus=$$(sysctl -n kern.smp.cpus 2>/dev/null || :); \
	 if [ -n "$$ncpus" ]; then fmakeflags="$$fmakeflags -j$$ncpus"; fi; \
       fi;; \
    d) fmakeflags="$$fmakeflags -dA";; \
    *) fmakeflags="$$fmakeflags -$$flag$$OPTARG";; \
  esac; \
done; \
echo $$fmakeflags \
)
FMAKEFLAGS = -C /root/zfs/module -f Makefile.bsd $(shell $(getflags))

ifneq (/root/zfs/module,/root/zfs/module)
FMAKEFLAGS += MAKEOBJDIR=/root/zfs/module
endif

FMAKE = env -u MAKEFLAGS make $(FMAKEFLAGS)

modules-Linux:
	mkdir -p $(sort $(dir $(spl-objs) $(spl-)))
	mkdir -p $(sort $(dir $(zfs-objs) $(zfs-)))
	$(MAKE) -C /root/linux $(if ,CC=) \
		$(if ,LD=) $(if ,LLVM=) \
		M="$$PWD"  CONFIG_ZFS=m modules

modules-FreeBSD:
	+$(FMAKE)

modules-unknown:
	@true

modules: modules-Linux

clean-Linux:
	@# Only cleanup the kernel build directories when CONFIG_KERNEL
	@# is defined.  This indicates that kernel modules should be built.
#	$(MAKE) -C /root/linux M="$$PWD"  clean

	$(RM) NONE Module.markers
	find . -name '*.ur-safe' -type f -delete

clean-FreeBSD:
	+$(FMAKE) clean

clean: clean-Linux

.PHONY: modules_uninstall-Linux-legacy
modules_uninstall-Linux-legacy:
	$(RM) -r $(addprefix $(KMODDIR)/$(INSTALL_MOD_DIR)/,spl/ avl/ icp/ lua/ nvpair/ unicode/ zcommon/ zfs/ zstd/)

KMODDIR := $(INSTALL_MOD_PATH)/lib/modules/6.8.9+
modules_install-Linux: modules_uninstall-Linux-legacy
	@# Install the kernel modules
	$(MAKE) -C /root/linux M="$$PWD" modules_install \
		INSTALL_MOD_PATH=$(INSTALL_MOD_PATH) \
		INSTALL_MOD_DIR=$(INSTALL_MOD_DIR) \
		KERNELRELEASE=6.8.9+
	@# Remove extraneous build products when packaging
	if [ -n "$(DESTDIR)" ]; then \
		find $(KMODDIR) -name 'modules.*' -delete; \
	fi
	@# Debian ships tiny fake System.map files that are
	@# syntactically valid but just say
	@# "if you want system.map go install this package"
	@# Naturally, depmod is less than amused by this.
	@# So if we find it missing or with one of these present,
	@# we check for the alternate path for the System.map
	sysmap=$(INSTALL_MOD_PATH)/boot/System.map-6.8.9+; \
	{ [ -f "$$sysmap" ] && [ $$(wc -l < "$$sysmap") -ge 100 ]; } || \
		sysmap=$(INSTALL_MOD_PATH)/usr/lib/debug/boot/System.map-6.8.9+; \
	if [ -f $$sysmap ]; then \
		depmod -ae -F $$sysmap 6.8.9+; \
	fi

modules_install-FreeBSD:
	@# Install the kernel modules
	+$(FMAKE) install

modules_install: modules_install-Linux

data_install-Linux:
	@mkdir -p $(DESTDIR)//usr/local/src/zfs-2.2.99/6.8.9+
	cp ../zfs.release ../zfs_config.h NONE $(DESTDIR)//usr/local/src/zfs-2.2.99/6.8.9+

data_install-FreeBSD:
	@

data_install: data_install-Linux

modules_uninstall-Linux: modules_uninstall-Linux-legacy
	@# Uninstall the kernel modules
	$(RM) $(addprefix $(KMODDIR)/$(INSTALL_MOD_DIR)/,zfs.ko spl.ko)

modules_uninstall-FreeBSD:
	@false

modules_uninstall: modules_uninstall-Linux

data_uninstall-Linux:
	$(RM) $(addprefix $(DESTDIR)//usr/local/src/zfs-2.2.99/6.8.9+/,zfs.release zfs_config.h NONE)

data_uninstall-FreeBSD:
	@

data_uninstall: data_uninstall-Linux

cppcheck-Linux:
	@printf "skipping cppcheck because cppcheck is not installed\n" -j64 --std=c99 --quiet --force --error-exitcode=2 \
		--inline-suppr \
		--suppress=unmatchedSuppression \
		--suppress=noValidConfiguration \
		--enable=warning,information -D_KERNEL \
		--include=/root/linux/include/generated/autoconf.h \
		--include=../zfs_config.h \
		--config-exclude=/root/linux/include \
		-i zstd/lib \
		-I /root/linux/include \
		-I ../include/os/linux/kernel \
		-I ../include/os/linux/spl \
		-I ../include/os/linux/zfs \
		-I ../include \
		avl icp lua nvpair unicode zcommon zfs zstd os/linux

cppcheck-FreeBSD:
	@true

cppcheck: cppcheck-Linux

distdir:
	cd . && find . -name '*.[chS]' -exec sh -c 'for f; do mkdir -p $$distdir/$${f%/*}; cp ./$$f $$distdir/$$f; done' _ {} +
	cp ./Makefile.bsd $$distdir/Makefile.bsd

gen-zstd-symbols:
	for obj in $(addprefix zstd/,$(ZSTD_UPSTREAM_OBJS)); do echo; echo "/* $${obj#zstd/}: */"; objdump -t $$obj | awk '$$2 == "g" && !/ zfs_/ {print "#define\t" $$6 " zfs_" $$6}' | sort; done >> zstd/include/zstd_compat_wrapper.h

check-zstd-symbols:
	objdump -t $(addprefix zstd/,$(ZSTD_UPSTREAM_OBJS)) | awk '/file format/ {print}  $$2 == "g" && (!/ zfs_/ && !/ __pfx_zfs_/) {++ret; print}  END {exit ret}'
