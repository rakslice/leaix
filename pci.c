#include <sys/types.h>
#include <stdio.h>

#include "aix_io.h"

#include "pci.h"

/* Minimal PCI type 2 polling functionality
 * to get going in VirtualBox
 *
 * Most functions courtesy of osdev wiki */


/* Set this to 1 for some more output */
#define DEBUG_PCI 0

/* Range of PCI bus and slots to scan */
/* In principle these should both be 255;
   I've lowered them so we time out faster
   when there's no card */
#define HIGHEST_BUS 7
#define HIGHEST_SLOT 15

uint16_t pci_config_read_w_internal(uint8_t bus, uint8_t slot, 
    uint8_t func, uint8_t offset);


#ifndef USE_OS_LONG_IO

/** Inline assembly versions of 32-bit port I/O, since
 *  there are none documented in the AIX PS/2 TR
 */

static inline void sysOutLong(uint16_t port, uint32_t val) { 
	asm volatile ( "outl %0, %1" : : "a"(val), "Nd"(port) );
}

static inline uint32_t sysInLong(uint16_t port) {
	uint32_t ret;
	asm volatile ( "inl %1, %0"
			: "=a"(ret)
			: "Nd"(port) );
	return ret;
}

#else

/** On the other hand, the kernel obviously has 32-bit port I/O
 *  functions at the usual symbols and they seem to work
 */

uint32_t inl(uint16_t pos);
void outl(uint16_t pos, uint32_t val);
#define sysOutLong outl
#define sysInLong inl

#endif

uint16_t pci_config_read(pci_address_t addr, uint8_t offset) {
	return pci_config_read_w_internal(addr.bus, addr.slot, addr.func, offset);
}

integrate uint32_t pci_conf_addr(pci_address_t addr, uint8_t offset) {

    uint32_t lbus  = (uint32_t)addr.bus;
    uint32_t lslot = (uint32_t)addr.slot;
    uint32_t lfunc = (uint32_t)addr.func;

    return (uint32_t)((lbus << 16) | (lslot << 11) |
              (lfunc << 8) | (offset & 0xfc) | ((uint32_t)0x80000000));
	
}

uint32_t pci_config_read_dword(pci_address_t addr, uint8_t offset) {
	uint32_t address = pci_conf_addr(addr, offset);
	sysOutLong(0xCF8, address); 
	return sysInLong(0xCFC);	
}

void pci_config_write_dword(pci_address_t addr, uint8_t offset,
	 uint32_t value) {
	uint32_t address = pci_conf_addr(addr, offset);
	sysOutLong(0xCF8, address);
	sysOutLong(0xCFC, value);
}

uint16_t pci_config_read_w_internal(uint8_t bus, uint8_t slot, 
    uint8_t func, uint8_t offset) {
	
    uint32_t address;
    uint32_t lbus  = (uint32_t)bus;
    uint32_t lslot = (uint32_t)slot;
    uint32_t lfunc = (uint32_t)func;
    uint16_t tmp = 0;
 
    /* create configuration address as per Figure 1 */
    address = (uint32_t)((lbus << 16) | (lslot << 11) |
              (lfunc << 8) | (offset & 0xfc) | ((uint32_t)0x80000000));
 
    /* write out the address */
    sysOutLong(0xCF8, address); 
    /* read in the data */
    /* (offset & 2) * 8) = 0 will choose the first word of the 32 bits register */
    tmp = (uint16_t)(( sysInLong(0xCFC) >> ((offset & 2) * 8)) & 0xffff);
    return (tmp);
}


pci_id_t build_pci_id(uint16_t vendor, uint16_t device) {
	return (((uint32_t) vendor) << 16) | device;
}

pci_address_t make_pci_address_t(uint8_t bus, uint8_t slot, uint8_t func) {
	pci_address_t out;
	out.bus = bus;
	out.slot = slot;
	out.func = func;
	return out;
}

pci_address_t find_first_pci_dev(pci_id_t * id_list) {
	uint16_t vendor, device;
	uint8_t bus;
	uint8_t slot;
	pci_id_t pci_id;
	pci_id_t * cur;

	printf("Looking for PCI devices\n");
	for (bus = 0; ; bus++) {
		for (slot = 0; ; slot++) {
			vendor = pci_config_read_w_internal(bus, slot, 0, 0);
#if DEBUG_PCI
			printf("    bus %d slot %d: vendor 0x%04x   \r", bus, slot, vendor);
#endif
			if (vendor != 0xffff) {
				device = pci_config_read_w_internal(bus, slot, 0, 2);
				if (device != 0xffff) {
					pci_id = build_pci_id(vendor, device);
					for (cur = id_list; *cur != 0; cur++) {
						if (*cur == pci_id) {
							printf("    bus %d slot %d: vendor 0x%04x device 0x%04x\n", bus, slot, vendor, device);
				return make_pci_address_t(bus, slot, 0);
						}
					}
#if DEBUG_PCI
					printf("    bus %d slot %d: vendor 0x%04x device 0x%04x\n", bus, slot, vendor, device);
#endif
				}
			}
			if (slot == HIGHEST_SLOT) break;
		}
		if (bus == HIGHEST_BUS) break;
	}
	return make_pci_address_t(0xff, 0xff, 0xff);
}

BOOL pci_not_found(pci_address_t addr) {
	return (addr.bus == 0xff) && (addr.slot == 0xff) && (addr.func = 0xff);
}
