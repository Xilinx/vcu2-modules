# Allegro Linux Drivers

## Summary

This repository contains the source code of ale2_riscv(encoder), ald3_riscv(decoder) drivers.

The alXX_riscv drivers are used by the soft codec repository and other control
software to access services provided by riscv firmware located inside hw ip.

## Building

To build drivers you need a linux kernel build tree. Give location of
kernel build tree using KDIR environment variable.
It you are cross-compiling then define ARCH and CROSS_COMPILE environment
variable.

```
$ ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- KDIR=linux-headers-dir make
```

Compiled kernel modules are located in al_riscv/ale2_riscv.ko and al_riscv/ald3_riscv.ko .

## Using on a board with riscv fw

Copy decoder and/or encoder fw with correct name in board /lib/firmware directory.
Copy ale2_riscv.ko and/or ald3_riscv.ko to your board and insert it.
Decoder firmware must be located in /lib/firmware/ald3xx.fw file.
Encoder firmware must be located in /lib/firmware/ale2xx.fw file.

```
$ insmod ale2_riscv.ko
$ insmod ald3_riscv.ko
```

## Device Tree Bindings for ald3_riscv and ale2_riscv

You can change configure some of the behavior of driver using device tree
bindings.
See the device-tree-bindings-alXX_riscv.txt file for more information about available
bindings.
