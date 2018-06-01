#ifndef __LE_PCI_H__
#define __LE_PCI_H__

#include <sys/types.h>

#include "add_types.h"

typedef long pci_id_t;

struct pci_address {
	uint8_t bus;
	uint8_t slot;
	uint8_t func;
};
typedef struct pci_address pci_address_t;
typedef int BOOL;

pci_address_t find_first_pci_dev(pci_id_t * id_list);
BOOL pci_not_found(pci_address_t addr);

uint16_t pci_config_read(pci_address_t addr, uint8_t offset);

uint32_t pci_config_read_dword(pci_address_t addr, uint8_t offset);
void pci_config_write_dword(pci_address_t addr, uint8_t offset,
	uint32_t value);

#define PCI_COMMAND_MASTER_ENABLE 4
#define PCI_COMMAND_IO_ENABLE     1

#define PCI_INTERRUPT_REG 0x3c

#define	PCI_MAP_IO_ADDRESS_MASK			0xfffffffe

#endif

