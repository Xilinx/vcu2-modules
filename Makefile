SRC := $(shell pwd)

ifeq ($(O),)
	include $(KERNEL_SRC)/.config
else
	include $(O)/.config
endif

obj-m	+= al_riscv/
obj-m	+= al5r/

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) O=$(O) modules

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules_install

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f Module.markers Module.symvers modules.order modules.builtin
	rm -f */*.ko */*.mod.c */.*.mod.c */.*.cmd */*.o
	rm -f */modules.order */modules.builtin
	rm -rf .tmp_versions Modules.symvers