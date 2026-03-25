KDIR ?= /lib/modules/$(shell uname -r)/build

default: modules

modules:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules

modules_install:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules_install

clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) clean
