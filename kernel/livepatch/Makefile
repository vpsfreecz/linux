# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_LIVEPATCH) += livepatch.o

livepatch-objs := core.o patch.o shadow.o state.o transition.o
livepatch-$(CONFIG_X86_64) += vpsadminos_rhashtable.o
