# Allegro Linux Drivers

## Summary

This repository contains the source code of al_codec and al5r drivers.

The al_codec driver is used by the soft codec repository and other control
software to access services provided by riscv firmware located inside hw ip.

The al5r driver is used by the soft_codec repository and other control software
to access an hw ip with direct registers access. It implements a read / write
registers interface and make it possible to handle interrupts in userspace.

## Building

To build drivers you need a linux kernel build tree. Give location of
kernel build tree using KDIR environment variable.
It you are cross-compiling then define ARCH and CROSS_COMPILE environment
variable.

```
$ ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- KDIR=linux-headers-dir make
```

Compiled kernel modules are located in allegro/al_codec.ko and al5r/al5r.ko

## Using on a board with riscv fw

Copy decoder or/and encoder fw with correct name in board /lib/firmware directory.
Copy al_codec.ko on your board and insert it.
Decoder firmware must be located in /lib/firmware/ald3xx.fw file.
Encoder firmware must be located in /lib/firmware/ale2xx.fw file.

```
$ insmod al_codec.ko
```

## Device Tree Bindings for al_codec

You can change configure some of the behavior of driver using device tree
bindings.
See the device-tree-bindings-al_codec.txt file for more information about available
bindings.

## Using on a board without riscv fw

Copy al5r.ko on your board and insert it.

```
$ insmod al5r.ko
```

## Device Tree Bindings for al5r

You can change configure some of the behavior of driver using device tree
bindings.
See the device-tree-bindings-al5r.txt file for more information about available
bindings.
