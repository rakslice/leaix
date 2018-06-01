
#ifndef _AIX_IO_H_
#define _AIX_IO_H_

#include <sys/types.h>
#include <sys/buf.h>
#include <sys/i386/dmaralloc.h>

/** This file declares some of the AIX APIS
 * for communicating with adapter cards and
 * other things as necessary */

/**** Documented adapter card I/O interfaces *****/

/* See AIX PS/2 Technical Reference C 6.1.5 */

/* 1. Port I/O */

/* Return a 16-bit word from the specified I/O port. */
/* int? */ 
unsigned short ioin (int port);

/* Return an 8-bit byte from the specified  */
/* int? */ 
unsigned char ioinb (int port);

/* Output a 16-bit word to the specified I/O port */
/* int? */ 
void ioout (int port, unsigned short val);

/* Output an 8-bit byte to the specified I/O port */
/* int? */ 
void iooutb (int port, unsigned char val);

/* 2. Memory-mapped I/O */

/* To use the following macros, first do: 
  #include <sys/i386/mmu386.h>
*/

/* Get a kernel virtual address for a physical address.
   Set vaddr to NULL before calling. 
   After the call the address will be in vaddr. *
/* Macro: MAPIN(caddr_t vaddr, paddr_t paddr, int bcnt); */

/* Get a kernel virtual address for a phsyical address
   that we are only going to use write (for the adapter to
   read) but do not need read access to */
/* Macro: MAPIN_RO(caddr_t vaddr, paddr_t paddr, int bcnt); */

/* missing decls for the internals of those */
int mapin(paddr_t paddr, int bcnt);

/* 3. DMA */

/* The dmaralloc structure (<sys/i386/dmaralloc.h>) is used as a parameter 
   of the DMA functions
*/


/* Allocate a DMA arbitration level and channel.

Set the values in the struct before calling.
This returns FALSE if the requested DMA was busy and could not be allocated -
but pass your callback function in dma_availfunc and it will be called
back when DMA may be idle so you can retry the dmachanalloc call
*/
int dmachanalloc(struct dmaralloc *ptr);


/* Setup a DMA transfer. 

physaddr is the phsyical system memory address to transfer data to or from
func is the direction to transfer:
  B_READ - read from the adapter and write into system memory
  B_WRITE - read from system memory and write into the adapter
dmarp is the struct for the successfully allocated dma channel
ioaddr is the I/O address to program to the DMA controller, typically 0 
count is the number of bytes to transfer (must be a multiple of xfersize)
xfersize is the bus size in bytes (1 or 2 for 8-bit or 16-bit DMA)
*/

/* int? */ void dmasetup(paddr_t physaddr, long func, unsigned short count, 
                    struct dmaralloc *dmarp, int ioaddr, int xfersize);

/* Return the number of bytes that have not been transferred after a DMA
   transfer.  Call before freeing the channel.
*/
unsigned short dmaresid(struct dmaralloc *ptr);


/* Free the dma channel */
/* int? */ void dmachanfree(struct dmaralloc *ptr);

/* Interrupts */

int intrattach(int (*func)(), int level, int splmask);


/* ******** Additional things ******* */

/* timer related stuff */

int delayticks(int ticks); /* tick is based on kernel internal timing cycle */

/* memory operations */

int bcopy(caddr_t from, caddr_t to, int count);
int bzero(caddr_t buf, int count);

#endif
