# leaix #
An AMD am799x (PCnet/Lance) Ethernet driver for AIX PS/2 1.3.  Ported from NetBSD 1.1.

This driver is **experimental**; it has been used a bit in a virtualized environment with VirtualBox 5.2.x, and has had NO TESTING OTHERWISE. See LICENSE.

## Building and Installation ##

Build with `make`, install with `make install`.

This driver is known to build with the Metaware compiler for AIX PS/2, and with GCC 2.7.2.3.
If you have GCC, to build with it instead, edit the `Makefile` and uncomment the line starting with `CC=gcc`.

Note that the headers on the system I've built this on have been modified (fixed up here and there over the course of a couple of weeks). The stock headers on AIX 1.x are a bit sketchy (note the presence of `-Wno-comment` already); you may need to take out the `-Werror` or even more serious actions to get through the build on freshly installed AIX headers.

## Usage ##

Once you are up and running on a kernel that includes the driver, you should see an indication in the boot console output available from `dmesg` whether a card was detected, and it should be available to `ifconfig` as `eth0`, and can be manually configured as usual:

```
ifconfig eth0 inet 10.0.2.15 netmask 0xffffff00
ifconfig eth0
route add net default 192.168.2.2 10
echo nameserver 8.8.8.8 < /etc/resolv.conf
```

Enable tons of debug messages by setting the `DEBUG` flag on the interface with:
```
ifconfig eth0 debug
```
Messages will appear on the console -- lots of messages. You should probably make sure you have an alternate means of running commands on the system (X11, serial console) before enabling debug messages.
