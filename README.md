# Allegro Linux Drivers

## Summary

This repository contains the source code of al\_codec driver.

The al\_codec driver is used by the soft codec repository and other control
software to access services provided by riscv firmware located inside hw ip.

## Building

To build al\_codec driver you need a linux kernel build tree. Give location of
kernel build tree using KDIR environment variable.
It you are cross-compiling then define ARCH and CROSS\_COMPILE environment
variable.

```
$ ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- KDIR=linux-headers-dir make
```

Compiled kernel module is located in al\_riscv/al\_codec.ko

## Using on a board

Copy decoder or/and encoder fw with correct name in board /lib/firmware directory.
Copy al\_codec.ko on your board and insert it.
Decoder firmware must be located in /lib/firmware/ald3xx.fw file.
Encoder firmware must be located in /lib/firmware/ale2xx.fw file.

```
$ insmod al_codec.ko
```

## Device Tree Bindings

You can change configure some of the behavior of driver using device tree
bindings.
See the device-tree-bindings.txt file for more information about available
bindings.
