/*	$NetBSD: am7990.c,v 1.3 1995/07/24 04:34:51 mycroft Exp $	*/


/*
Ported to AIX by rakslice
*/

#define DEBUG_OUTPUT 0

/*-
 * Copyright (c) 1995 Charles M. Hannum.  All rights reserved.
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Ralph Campbell and Rick Macklem.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)if_le.c	8.2 (Berkeley) 11/16/93
 */

#include <sys/ioctl.h>
#include <sys/errno.h>

#include "../../../am7990_adds.h"

/* rak: some NetBSD -> AIX defines */
#define MINCLBYTES mincluster

/* rak: some notes: 
   
   NetBSD puts IFF_OACTIVE in the flags to indicate that the device's
   output queue is full; this appears to be bookkeeping.
   Does a check for this correspond to the QFULL macro?
*/

#include <sys/netisr.h>

#ifdef INET
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#endif

#ifdef NS
#include <netns/ns.h>
#include <netns/ns_if.h>
#endif

#if defined(CCITT) && defined(LLC)
#include <sys/socketvar.h>
#include <netccitt/x25.h>
extern llc_ctlinput(), cons_rtrequest();
#endif

#if NBPFILTER > 0
#include <net/bpf.h>
#include <net/bpfdesc.h>
#endif

#ifdef LEDEBUG
void recv_print __P((struct le_softc *, int));
void xmit_print __P((struct le_softc *, int));
#endif

#include "pci.h"

pci_id_t ids_of_interest[] = {
        0x10222000,
        0x10222001,
        0
};

int leaixinit(dev_t dev);
int leaixoutput(struct ifnet *ifp, struct mbuf *m0, struct sockaddr *dst);

#ifdef __GNUC__
#define DEBUGMSG(sc, ARGS...) do { if (sc->sc_debug) { \
	printf("leaix %s%d: " \
		, sc->sc_arpcom.ac_if.if_name \
		, sc->sc_arpcom.ac_if.if_unit \
	); \
	printf(##ARGS); \
	printf("\n"); \
} } while(0) 
#define DEBUGMSG2 DEBUGMSG
#define DEBUGMSG3 DEBUGMSG
#define DEBUGMSG4 DEBUGMSG
#else
#define DEBUGMSG2(sc, x) do { if (sc->sc_debug) { printf("leaix: %s%d " , sc->sc_arpcom.ac_if.if_name , sc->sc_arpcom.ac_if.if_unit ); printf(x); printf("\n"); } } while(0) 
#define DEBUGMSG3(sc, x, y) do { if (sc->sc_debug) { printf("leaix: %s%d " , sc->sc_arpcom.ac_if.if_name , sc->sc_arpcom.ac_if.if_unit ); printf(x, y); printf("\n"); } } while(0) 
#define DEBUGMSG4(sc, x, y, z) do { if (sc->sc_debug) { printf("leaix: %s%d " , sc->sc_arpcom.ac_if.if_name , sc->sc_arpcom.ac_if.if_unit ); printf(x, y, z); printf("\n"); } } while(0) 
#endif


void
leconfig(sc)
	struct le_softc *sc;
{
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	int mem;

	/* Make sure the chip is stopped. */
	lestop(sc);

	/* Initialize ifnet structure. */
	ifp->if_name = "eth";
	ifp->if_unit = sc->sc_dev.dv_unit;
	ifp->if_output = leaixoutput;
	ifp->if_init = leaixinit;
	ifp->if_ioctl = leioctl;
	ifp->if_watchdog = lewatchdog;
	ifp->if_flags =
	    IFF_BROADCAST | /* IFF_SIMPLEX | */ IFF_NOTRAILERS /* | IFF_MULTICAST */;
	ifp->if_flags |= IFF_ETHERNET;
	ifp->if_mtu = ETHERMTU;

	/* Attach the interface. */
	if_attach(ifp);

#if NBPFILTER > 0
	bpfattach(&ifp->if_bpf, ifp, DLT_EN10MB, sizeof(struct ether_header));
#endif

	switch (sc->sc_memsize) {
	case 8192:
		sc->sc_nrbuf = 4;
		sc->sc_ntbuf = 1;
		break;
	case 16384:
		sc->sc_nrbuf = 8;
		sc->sc_ntbuf = 2;
		break;
	case 32768:
		sc->sc_nrbuf = 16;
		sc->sc_ntbuf = 4;
		break;
	case 65536:
		sc->sc_nrbuf = 32;
		sc->sc_ntbuf = 8;
		break;
	default:
		panic("leconfig: weird memory size");
	}

	printf("leaix %s%d: address %s, %d receive buffers, "
		"%d transmit buffers\n",
            ifp->if_name,
            ifp->if_unit,
	    ether_sprintf(sc->sc_arpcom.ac_enaddr),
	    sc->sc_nrbuf, sc->sc_ntbuf);

	mem = 0;
	sc->sc_initaddr = mem;
	mem += sizeof(struct leinit);
#if DEBUG_OUTPUT
	printf("mem after leinit %d\n", mem);
#endif
	sc->sc_rmdaddr = mem;
	mem += sizeof(struct lermd) * sc->sc_nrbuf;
#if DEBUG_OUTPUT
	printf( "after lermd %d\n", mem);
#endif
	sc->sc_tmdaddr = mem;
	mem += sizeof(struct letmd) * sc->sc_ntbuf;
#if DEBUG_OUTPUT
	printf( "after letmd %d\n", mem);
#endif
	sc->sc_rbufaddr = mem;
	mem += LEBLEN * sc->sc_nrbuf;
#if DEBUG_OUTPUT
	printf( "after nrbuf %d\n", mem);
#endif
	sc->sc_tbufaddr = mem;
	mem += LEBLEN * sc->sc_ntbuf;
#if DEBUG_OUTPUT
	printf( "after ntbuf %d\n", mem);
#endif
#ifdef notyet
	if (mem > ...)
		panic(...);
#endif
}

void
lereset(sc)
	struct le_softc *sc;
{
	int s;

	s = splimp();
	leinit(sc);
	splx(s);
}


int 
lewatchdog(unit)
	short unit; 
{
	struct le_softc *sc = LE_SOFTC(unit);

	/* log(LOG_ERR, "%s: device timeout\n", sc->sc_dev.dv_xname); */
	printf("%s: device timeout\n", sc->sc_dev.dv_xname);
	
	++sc->sc_arpcom.ac_if.if_oerrors;

	lereset(sc);
	return NULL;
}

/*
 * Set up the contents of the kernel memory buffer
 *  - initialization block and the descriptor rings.
 */
void
lememinit(sc)
	register struct le_softc *sc;
{
#if NBPFILTER > 0
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
#endif
	u_long a;
	int bix;
	struct leinit init;
	struct lermd rmd;
	struct letmd tmd;

	DEBUGMSG4(sc, "tmd is %d bytes, rmd is %d bytes", 
		sizeof(tmd), sizeof(rmd));

	bzero((caddr_t) &init, sizeof(init));
	bzero((caddr_t) &rmd, sizeof(rmd));
	bzero((caddr_t) &tmd, sizeof(tmd));

#if NBPFILTER > 0
	if (ifp->if_flags & IFF_PROMISC)
		init.init_mode = LE_MODE_NORMAL | LE_MODE_PROM;
	else
#endif
		init.init_mode = LE_MODE_NORMAL;
	init.init_padr[0] =
	    (sc->sc_arpcom.ac_enaddr[1] << 8) | sc->sc_arpcom.ac_enaddr[0];
	init.init_padr[1] =
	    (sc->sc_arpcom.ac_enaddr[3] << 8) | sc->sc_arpcom.ac_enaddr[2];
	init.init_padr[2] =
	    (sc->sc_arpcom.ac_enaddr[5] << 8) | sc->sc_arpcom.ac_enaddr[4];
	lesetladrf(&sc->sc_arpcom, init.init_ladrf);

	sc->sc_last_rd = 0;
	sc->sc_first_td = sc->sc_last_td = sc->sc_no_td = 0;

	a = sc->sc_addr + LE_RMDADDR(sc, 0);
	init.init_rdra = a;
	init.init_rlen = (a >> 16) | ((ffs(sc->sc_nrbuf) - 1) << 13);

	a = sc->sc_addr + LE_TMDADDR(sc, 0);
	init.init_tdra = a;
	init.init_tlen = (a >> 16) | ((ffs(sc->sc_ntbuf) - 1) << 13);

	(*sc->sc_copytodesc)(sc, &init, LE_INITADDR(sc), sizeof(init));

	/*
	 * Set up receive ring descriptors.
	 */
	for (bix = 0; bix < sc->sc_nrbuf; bix++) {
		a = sc->sc_addr + LE_RBUFADDR(sc, bix);
                DEBUGMSG4(sc, "setting rx ring %d at 0x%08lx", bix, a);
		rmd.rmd0 = a;
		rmd.rmd1_hadr = a >> 16;
		rmd.rmd1_bits = LE_R1_OWN;
		rmd.rmd2 = -LEBLEN | LE_XMD2_ONES;
		rmd.rmd3 = 0;
		(*sc->sc_copytodesc)(sc, &rmd, LE_RMDADDR(sc, bix),
		    sizeof(rmd));
	}

	/*
	 * Set up transmit ring descriptors.
	 */
	for (bix = 0; bix < sc->sc_ntbuf; bix++) {
		a = sc->sc_addr + LE_TBUFADDR(sc, bix);
                DEBUGMSG4(sc, "setting tx ring %d at 0x%08lx", bix, a);
		tmd.tmd0 = a;
		tmd.tmd1_hadr = a >> 16;
		tmd.tmd1_bits = 0;
		tmd.tmd2 = 0 | LE_XMD2_ONES;
		tmd.tmd3 = 0;
		(*sc->sc_copytodesc)(sc, &tmd, LE_TMDADDR(sc, bix),
		    sizeof(tmd));
	}
}

void
lestop(sc)
	struct le_softc *sc;
{

	lewrcsr(sc, LE_CSR0, LE_C0_STOP);
}

int
leaixinit(dev_t dev)
{
        struct le_softc *sc;
	struct isa_attach_args *ia;
	int devnum;
	pci_address_t pciaddr;

	printf("\n");
	printf("AMD PCnet driver     github.com/rakslice/leaix\n");
	printf("version 0.0.1 - experimental - use at own risk\n");

	devnum = 0;

	sc = LE_SOFTC(devnum);
 	ia = ISA_ATTACH_ARGS(devnum);

	ia->ia_iobase = 0;
	ia->ia_iosize = 0;
	ia->ia_irq = 0;
	ia->ia_drq = 0;
	ia->ia_maddr = 0;
	ia->ia_msize = 0;
	ia->ia_aux = 0;

	sc->sc_dev.dv_xname = "leaix";

	LE_BUSY(devnum) = 0;

	pciaddr = find_first_pci_dev(ids_of_interest);

	if (pci_not_found(pciaddr)) {
		printf("leaix: card not found");
		return 1;
	} else {
		uint32_t conf;
		uint32_t new_iobase;
		uint32_t reg;
		uint8_t pin;
		uint8_t line;

#if DEBUG_OUTPUT
		printf("Enable io and bus mastering\n");
#endif
		conf = pci_config_read_dword(pciaddr, 0x4);
		conf &= 0xffff0000;
		conf |= PCI_COMMAND_MASTER_ENABLE | PCI_COMMAND_IO_ENABLE;
		pci_config_write_dword(pciaddr, 0x4, conf); 
#if DEBUG_OUTPUT
		printf("PCI status-conf is now %08lx\n", 
			pci_config_read_dword(pciaddr, 0x4));
#endif

		reg = pci_config_read_dword(pciaddr, PCI_INTERRUPT_REG);
		pin = (reg >> 8) & 0xff;
		line = reg & 0xff;
#if DEBUG_OUTPUT
		printf("int pin %d line %d\n", pin, line);
#endif

		if (line == 2) {
#if DEBUG_OUTPUT
			printf("2 to 9\n");
#endif
			line = 9;
		}

		ia->ia_irq = line;
		
		new_iobase = pci_config_read_dword(pciaddr, 0x10) 
			& PCI_MAP_IO_ADDRESS_MASK;
#if DEBUG_OUTPUT
                printf("PCI derived iobase is 0x%08lx\n", new_iobase);
#endif
		ia->ia_iobase = new_iobase;
#if DEBUG_OUTPUT
		printf("Using io=0x%04x irq=%d\n", ia->ia_iobase, ia->ia_irq);
#endif
	}

#if DEBUG_OUTPUT
	printf("usec per tick %d\n", usec_per_tick);
	printf("leprobe\n");
#endif
        leprobe(sc, ia);
#if DEBUG_OUTPUT
	printf("leattach\n");
#endif
	leattach((struct device *)sc, ia); /* struct le_softc starts 
                                              with a struct device */
	return 0;
}

#define ITERATIONS_PER_USEC 80

void delayloop(int usec) {
	int i;
	for (i = ITERATIONS_PER_USEC * usec; i > 0; i--);
}

/*
 * Initialization of interface; set up initialization block
 * and transmit/receive descriptor rings.
 */
void
leinit(register struct le_softc *sc)
{
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	register int timo;
	u_long a;

#if DEBUG_OUTPUT
	printf("leaix: leinit\n");
#endif

	lewrcsr(sc, LE_CSR0, LE_C0_STOP);
	LE_DELAY(100);

	/* Set the correct byte swapping mode, etc. */
	lewrcsr(sc, LE_CSR3, sc->sc_conf3);

#if DEBUG_OUTPUT
	printf("leaix: lememinit\n");
#endif

	/* Set up LANCE init block. */
	lememinit(sc);

#if DEBUG_OUTPUT
	printf("leaix: physical memory address is 0x%08lx\n", sc->sc_addr); 
#endif

	/* Give LANCE the physical address of its init block. */
	a = sc->sc_addr + LE_INITADDR(sc);
	lewrcsr(sc, LE_CSR1, a);
	lewrcsr(sc, LE_CSR2, a >> 16);

	/* Try to initialize the LANCE. */
	LE_DELAY(100);
	lewrcsr(sc, LE_CSR0, LE_C0_INIT);

	/* Wait for initialization to finish. */
	for (timo = 100000; timo; timo--)
		if (lerdcsr(sc, LE_CSR0) & LE_C0_IDON)
			break;

	if (lerdcsr(sc, LE_CSR0) & LE_C0_IDON) {
		/* Start the LANCE. */
		lewrcsr(sc, LE_CSR0, LE_C0_INEA | LE_C0_STRT | LE_C0_IDON);
		ifp->if_flags |= IFF_RUNNING;
		LE_BUSY(ifp->if_unit) = 0; /* ifp->if_flags &= ~IFF_OACTIVE; */
		ifp->if_timer = 0;
		lestart(ifp);
	} else
		printf("%s: card failed to initialize\n", sc->sc_dev.dv_xname);
}

/*
 * Routine to copy from mbuf chain to transmit buffer in
 * network buffer memory.
 */
integrate int
leput(sc, boff, m)
	struct le_softc *sc;
	int boff;
	register struct mbuf *m;
{
	register struct mbuf *n;
	register int len, tlen = 0;

	for (; m; m = n) {
		len = m->m_len;
		if (len == 0) {
			MFREE(m, n);
			continue;
		}
		(*sc->sc_copytobuf)(sc, mtod(m, caddr_t), boff, len);
		boff += len;
		tlen += len;
		MFREE(m, n);
	}
	if (tlen < LEMINSIZE) {
		(*sc->sc_zerobuf)(sc, boff, LEMINSIZE - tlen);
		tlen = LEMINSIZE;
	}
	return (tlen);
}

struct mbuf *leget(char *addr, int totlen, struct ifnet *ifp);

/*
   rak: this is based on the sample dd_input in Technical Reference C 4.7.1
*/
/* void process_inbound_packet(struct ifnet *ifp, struct arpcom *arper,
	int packet_type, register int data_len, register char *addr_of_data,
	char *all_data) { */

void process_inbound_packet(struct le_softc *sc, struct ifnet *ifp,
                            struct arpcom *arper, int packet_type,
                            struct mbuf *m) {
     /* spl_t s; */ 
     int tmp;
     char * ptmp;

     /* things that the caller needs to have done: */ 
     /* - clear the interrupt */ 
     /* - let the adapter know that these receive buffers are free */ 
     /* - Pass the packet type in, set the interface
        pointer to if, and the arpcom struct to arper. */

     switch (packet_type) { 
          case LANTYPE_IP: 
               if (m == NULL) {
                    DEBUGMSG2(sc, "inbound packet is IP but mbuf null"); 
                    break; 
               }
               if (IF_QFULL(&ipintrq)) { 
                    DEBUGMSG2(sc, "inbound packet is IP but queue full"
                                  " so dropping"); 
                    IF_DROP(&ipintrq); 
                    m_freem(m); 
                    break; 
               } 
               DEBUGMSG2(sc, "inbound packet is IP; getting queued for stack");
               /* queue our mbufs up for the network stack */
               IF_ENQUEUE(&ipintrq, m); 
               /* schedule a visit from the network stack */
               schednetisr(NETISR_IP); 
               break; 
          case LANTYPE_ARP:
               DEBUGMSG2(sc, "inb pkt is ARP; feeding it into the arpmachine");
	       if (sc->sc_debug) {
               		printf("leaix: start of data going to arpinput:\n");
	       		ptmp = mtod(m, char *);
               		for (tmp = 0; tmp < 16; tmp++) {
				printf("%02x ", ptmp[tmp] & 0xff);
               		}
	       		printf("\n");
	       }
               tmp = arpinput(arper, m); 
               DEBUGMSG3(sc, "arpinput returned %d", tmp);
               break; 
          default:
               DEBUGMSG3(sc, "inb pkt is unk eth_type %x; dropping",
                 packet_type);
               m_freem(m);
               break;
     } 
} 

/* sample code continues */
struct mbuf * 
leget(register char *addr, register int totlen, struct ifnet *ifp) {

      register int len; 
      register struct mbuf *m; 
      struct mbuf *top = NULL, **mp = &top; 
      u_char *mcp; 

      while (totlen > 0) { 
           MGET(m, M_DONTWAIT, MT_DATA); 
           if (m == NULL) 
                goto bad; 
           len = totlen; 

           if (ifp != NULL)
                len += sizeof(ifp); 
           if (len >= MINCLBYTES) { 
                MCLGET(m); 
                if (m->m_len == CLBYTES) 
                     m->m_len = len = MIN(CLBYTES, len); 
                else 
                     m->m_len = len = MIN(MLEN, len); 
           } else { 
                m->m_len = len = MIN(MLEN, len); 
                m->m_off = MMINOFF; 
           } 
 
           mcp = mtod(m, u_char *); 
           if (ifp != NULL) { 
                *(mtod(m, struct ifnet **)) = ifp; 
                mcp += sizeof(ifp); 
                len -= sizeof(ifp); 
                ifp = NULL; 
           } 
	   /* FIXME: the char type compatibility maybe on purpose... */
           bcopy((caddr_t) addr, (caddr_t) mcp, len); 
           addr += len; 
           *mp = m; 
           mp = &m->m_next; 
           totlen -= len; 
      } 
      return top; 
bad: 
      m_freem(top); 
      return NULL; 
}  

/*
 * Pass a packet to the higher levels.
 */
integrate void
leread(sc, boff, len)
	register struct le_softc *sc;
	int boff, len;
{
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	struct mbuf *m;

        struct ether_header * eh;

	if (len <= sizeof(struct ether_header) ||
	    len > ETHERMTU + sizeof(struct ether_header)) {
		printf("%s: invalid packet size %d; dropping\n",
		    sc->sc_dev.dv_xname, len);
		ifp->if_ierrors++;
		return;
	}

        eh = (struct ether_header *)( ((caddr_t)sc->sc_mem) + boff);

	/* Pull packet off interface. */
        DEBUGMSG3(sc, "frame size seen by leread: %d bytes", len);

	switch (ntohs(eh->eth_type)) {
	default:
		DEBUGMSG3(sc, "Unknown eth_type 0x%04x in leread", 
			ntohs(eh->eth_type));
			/* no break */
	case LANTYPE_IP:
	case LANTYPE_ARP:
		/* this version of the leget call only passes the payload: */
		m = leget(((caddr_t)sc->sc_mem) + boff + sizeof(struct ether_header),
	              len - sizeof(struct ether_header),
	              &sc->sc_arpcom.ac_if);
		break;
#if 0
		/* this verison of the leget call passes the whole packet: */
		m = leget(((caddr_t)sc->sc_mem) + boff,
	              len,
	              &sc->sc_arpcom.ac_if);
		break;
#endif
	}
	if (m == 0) {
		ifp->if_ierrors++;
		return;
	}

	ifp->if_ipackets++;

#if NBPFILTER > 0
	/*
	 * Check if there's a BPF listener on this interface.
	 * If so, hand off the raw packet to BPF.
	 */
	if (ifp->if_bpf) {
		bpf_mtap(ifp->if_bpf, m);

		/*
		 * Note that the interface cannot be in promiscuous mode if
		 * there are no BPF listeners.  And if we are in promiscuous
		 * mode, we have to check if this packet is really ours.
		 */
		if ((ifp->if_flags & IFF_PROMISC) != 0 &&
		    (eh->eth_dhost[0] & 1) == 0 && /* !mcast and !bcast */
		    bcmp(eh->eth_dhost, sc->sc_arpcom.ac_enaddr,
			    sizeof(eh->eth_dhost)) != 0) {
			m_freem(m);
			return;
		}
	}
#endif

	process_inbound_packet(sc, ifp, &sc->sc_arpcom, ntohs(eh->eth_type),
		m);
}

integrate void
lerint(sc)
	struct le_softc *sc;
{
	register int bix;
	int rp;
	struct lermd rmd;

	bix = sc->sc_last_rd;

	/* Process all buffers with valid data. */
	for (;;) {
		rp = LE_RMDADDR(sc, bix);
		(*sc->sc_copyfromdesc)(sc, &rmd, rp, sizeof(rmd));

		if (rmd.rmd1_bits & LE_R1_OWN)
			break;

		if (rmd.rmd1_bits & LE_R1_ERR) {
			if (rmd.rmd1_bits & LE_R1_ENP) {
				if ((rmd.rmd1_bits & LE_R1_OFLO) == 0) {
					if (rmd.rmd1_bits & LE_R1_FRAM)
						printf("%s: framing error\n",
						    sc->sc_dev.dv_xname);
					if (rmd.rmd1_bits & LE_R1_CRC)
						printf("%s: crc mismatch\n",
						    sc->sc_dev.dv_xname);
				}
			} else {
				if (rmd.rmd1_bits & LE_R1_OFLO)
					printf("%s: overflow\n",
					    sc->sc_dev.dv_xname);
			}
			if (rmd.rmd1_bits & LE_R1_BUFF)
				printf("%s: receive buffer error\n",
				    sc->sc_dev.dv_xname);
		} else if ((rmd.rmd1_bits & (LE_R1_STP | LE_R1_ENP)) !=
		    (LE_R1_STP | LE_R1_ENP)) {
			printf("%s: dropping chained buffer\n",
			    sc->sc_dev.dv_xname);
		} else {
#ifdef LEDEBUG
			if (sc->sc_debug)
				recv_print(sc, sc->sc_last_rd);
#endif
			leread(sc, LE_RBUFADDR(sc, bix), (int)rmd.rmd3 - 4);
		}

		rmd.rmd1_bits = LE_R1_OWN;
		rmd.rmd2 = -LEBLEN | LE_XMD2_ONES;
		rmd.rmd3 = 0;
		(*sc->sc_copytodesc)(sc, &rmd, rp, sizeof(rmd));

#ifdef LEDEBUG
		if (sc->sc_debug)
			printf("sc->sc_last_rd = %x, rmd = 0 %x 1b %x 1h %x 2 %x 3 %x\n",
			    sc->sc_last_rd, rmd.rmd0, rmd.rmd1_bits, 
				rmd.rmd1_hadr, rmd.rmd2, rmd.rmd3);
#endif

		if (++bix == sc->sc_nrbuf)
			bix = 0;
	}

	sc->sc_last_rd = bix;
}

integrate void
letint(sc)
	register struct le_softc *sc;
{
	register struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	register int bix;
	struct letmd tmd;

	bix = sc->sc_first_td;

	for (;;) {
		if (sc->sc_no_td <= 0)
			break;

#ifdef LEDEBUG
		if (sc->sc_debug)
			printf("trans tmd = 0 %x 1b %x 1h %x 2 %x 3 %x\n",
				tmd.tmd0, tmd.tmd1_bits, 
				tmd.tmd1_hadr, tmd.tmd2, tmd.tmd3);
#endif

		(*sc->sc_copyfromdesc)(sc, &tmd, LE_TMDADDR(sc, bix),
		    sizeof(tmd));

		if (tmd.tmd1_bits & LE_T1_OWN)
			break;

		LE_BUSY(ifp->if_unit) = 0; /* ifp->if_flags &= ~IFF_OACTIVE; */

		if (tmd.tmd1_bits & LE_T1_ERR) {
			if (tmd.tmd3 & LE_T3_BUFF)
				printf("%s: transmit buffer error\n", sc->sc_dev.dv_xname);
			else if (tmd.tmd3 & LE_T3_UFLO)
				printf("%s: underflow\n", sc->sc_dev.dv_xname);
			if (tmd.tmd3 & (LE_T3_BUFF | LE_T3_UFLO)) {
				lereset(sc);
				return;
			}
			if (tmd.tmd3 & LE_T3_LCAR)
				printf("%s: lost carrier\n", sc->sc_dev.dv_xname);
			if (tmd.tmd3 & LE_T3_LCOL)
				ifp->if_collisions++;
			if (tmd.tmd3 & LE_T3_RTRY) {
				printf("%s: excessive collisions, tdr %d\n",
				    sc->sc_dev.dv_xname, tmd.tmd3 & LE_T3_TDR_MASK);
				ifp->if_collisions += 16;
			}
			ifp->if_oerrors++;
		} else {
			if (tmd.tmd1_bits & LE_T1_ONE)
				ifp->if_collisions++;
			else if (tmd.tmd1_bits & LE_T1_MORE)
				/* Real number is unknown. */
				ifp->if_collisions += 2;
			ifp->if_opackets++;
		}

		if (++bix == sc->sc_ntbuf)
			bix = 0;

		--sc->sc_no_td;
	}

	sc->sc_first_td = bix;

	lestart(ifp);

	if (sc->sc_no_td == 0)
		ifp->if_timer = 0;
}

/*
 * Controller interrupt.
 */

int leintr_unit(int unit);

int 
leintr() {

	/* rak: FIXME: Distinguish interrupts for different devices so
	 *             multiple devices won't go O(n^2) interrupt checks */
	int i;
	int ret = 0;

	for (i = 0; i < NUM_INTERFACES; i++) {
		ret |= leintr_unit(i);
	}
	return ret;
}


int
leintr_unit(int unit)
{
	register struct le_softc *sc = LE_SOFTC(unit);

	register u_int16_t isr;

	isr = lerdcsr(sc, LE_CSR0);
#ifdef LEDEBUG
	if (sc->sc_debug)
		printf("%s: leintr entering with isr=%04x\n",
		    sc->sc_dev.dv_xname, isr);
#endif
	if ((isr & LE_C0_INTR) == 0)
		return (0);

	lewrcsr(sc, LE_CSR0,
	    isr & (LE_C0_INEA | LE_C0_BABL | LE_C0_MISS | LE_C0_MERR |
		   LE_C0_RINT | LE_C0_TINT | LE_C0_IDON));
	if (isr & LE_C0_ERR) {
		if (isr & LE_C0_BABL) {
			printf("%s: babble\n", sc->sc_dev.dv_xname);
			sc->sc_arpcom.ac_if.if_oerrors++;
		}
#if 0
		if (isr & LE_C0_CERR) {
			printf("%s: collision error\n", sc->sc_dev.dv_xname);
			sc->sc_arpcom.ac_if.if_collisions++;
		}
#endif
		if (isr & LE_C0_MISS)
			sc->sc_arpcom.ac_if.if_ierrors++;
		if (isr & LE_C0_MERR) {
			printf("%s: memory error\n", sc->sc_dev.dv_xname);
			lereset(sc);
			return (1);
		}
	}

	if ((isr & LE_C0_RXON) == 0) {
		printf("%s: receiver disabled\n", sc->sc_dev.dv_xname);
		sc->sc_arpcom.ac_if.if_ierrors++;
		lereset(sc);
		return (1);
	}
	if ((isr & LE_C0_TXON) == 0) {
		printf("%s: transmitter disabled\n", sc->sc_dev.dv_xname);
		sc->sc_arpcom.ac_if.if_oerrors++;
		lereset(sc);
		return (1);
	}

	if (isr & LE_C0_RINT)
		lerint(sc);
	if (isr & LE_C0_TINT)
		letint(sc);

	return (1);
}

struct sockaddr_in *inet_addr_for_iface(struct ifnet *ifp) {
	struct ifaddr *a;
	struct sockaddr * out;
	for (a=ifp->if_addrlist; a != NULL; a = a->ifa_next) {
		if (a->ifa_addr.sa_family == AF_INET) {
			out = &a->ifa_addr;
			return (struct sockaddr_in *) out;
		}
	}
	return NULL;
}

/** the output method hook that sets up the mbuf */
int
leaixoutput(struct ifnet *ifp, struct mbuf *m0, struct sockaddr *dst) {
        /* register struct lan_llc_header *lh;  */
        register off; 
        /* struct lan_arp *ah; */
        struct mbuf *m = m0; 
	/* rak: looks like eth arpresolve just wants a straight uchar 
                array */
	/* struct sockaddr sa;
	struct sockaddr *sap = &sa; */
	unsigned char dest_eth[LAN_ADDR_SIZE];
	unsigned short ethertype = htons(LANTYPE_IP);
        struct in_addr idst;
	struct le_softc *sc;
        int error, usetrailers; 
        /* short snap_type; */
        int hdr_len;
        /* struct ie2_llc_hdr *llcp; */
        /* struct ie5_mac_hdr *macp; */
        unsigned char *macp;
        spl_t s;
	int i;
	struct sockaddr_in * replace_src_entry = NULL;
	

	sc = LE_SOFTC(ifp->if_unit);

	DEBUGMSG2( sc, "leaixoutput" ); 
	
        /* Make sure that the net is up and running */ 
        if ((ifp->if_flags & (IFF_UP|IFF_RUNNING)) != (IFF_UP|IFF_RUNNING)) { 
            DEBUGMSG2( sc, "can't output bc iface is not up and running");
            error = ENETDOWN; 
            goto bad; 
        } 
 
        /* Figure out the MAC destination address */ 
        switch (dst->sa_family) { 
        case AF_INET: 
            DEBUGMSG2(sc, "dest address is an AF_INET");
            idst = ((struct sockaddr_in *) dst)->sin_addr; 
            DEBUGMSG2(sc, "doing arpresolve");
            if (!arpresolve(&sc->sc_arpcom,m,&idst,dest_eth,&usetrailers)) {
                DEBUGMSG2(sc, "arpresolve returned 0; dest address needs an arp lookup");
                return 0; 
            }
            DEBUGMSG2(sc, "arp complete; we can assemble the frame to send");
            off = ntohs((u_short)mtod(m, struct ip *)->ip_len) - m->m_len; 
            if (usetrailers && off > 0 && (off & 0x1ff) == 0 && 
                m->m_off >= MMINOFF + 2 * sizeof (u_short)) { 
                ethertype = ETHERTYPE_TRAIL + (off>>9); 
                m->m_off -= 2 * sizeof (u_short); 
                m->m_len += 2 * sizeof (u_short); 
                *mtod(m, u_short *) = htons((u_short)LANTYPE_IP); 
                *(mtod(m, u_short *) + 1) = htons((u_short)m->m_len); 
                goto gottrailertype; 
            } 
            off = 0; 
            goto gottype; 
 
        case AF_UNSPEC:
            DEBUGMSG2(sc, "dest is AF_UNSPEC; rdy to send eth dest");
            /* debug(TOKENDBG, ("tk_ipc_output: AF_UNSPEC\n"));  */
	    /* rak: since the eth implementation of this needs the
	            dest eth proper, we need to get it out of the
                    sockaddr */
            printf("leaix: lestart unspec dest addr");
            for (i = 0; i < 14; i++) {
                 printf(":%02x", dst->sa_data[i] & 0xff);
            }
            printf("\n");
            bcopy(
		(caddr_t) dst->sa_data,
		(caddr_t) dest_eth, 
		LAN_ADDR_SIZE);

            goto gottype; 
        case AF_ARP:
            DEBUGMSG2(sc, "dest sockaddr is AF_ARP; dest assumed to be bcast addr");
            DEBUGMSG2(sc, "leaix: arp dest sockaddr sa_data");
	    if (sc->sc_debug) {
                 for (i = 0; i < 14; i++) {
                      printf(":%02x", dst->sa_data[i] & 0xff);
                 }
                 printf("\n");
	    }
            ethertype = htons(LANTYPE_ARP);
            if (ifp->if_flags & IFF_BROADCAST) {
	    	for (i = 0; i < LAN_ADDR_SIZE; i++) {
                	dest_eth[i] = 0xff;
                }
            }
	    goto gottype;
        default: 
            DEBUGMSG3(sc, "address family %d unsupported", dst->sa_family & 0xffff); 
            error = EAFNOSUPPORT; 
        return 0; 
        } 
 
    gottrailertype: 
 
        /* 
         * Packet to be sent as trailer: move first packet 
         * (control information) to end of chain. 
         */ 
        while (m->m_next) 
            m = m->m_next; 
        m->m_next = m0; 
        m = m0->m_next; 
        m0->m_next = 0; 
        m0 = m; 


    gottype: 
        /* 
         * Add local net header. 
         * 
         * Calculate the hdr length,
         * 
	 * Ethernet II: 2x macs + 2 byte ethertype */
	hdr_len = 2 * LAN_ADDR_SIZE + 2;

        /* 
         * Find enough room for the headers. 
         */ 
        if ( (m0->m_off > MMAXOFF) || (MMINOFF + hdr_len > m0->m_off) ) { 
            m = m_get(M_DONTWAIT, MT_HEADER); 
            if (m == 0) { 
                error = ENOBUFS; 
                goto bad ; 
            } 
            m->m_next = m0; 
            m0 = m ; 
            m0->m_off = MMINOFF; 
            m0->m_len = hdr_len ; 
        } else { 
            m0->m_off -= hdr_len ; 
            m0->m_len += hdr_len ; 
        }


        /* 
         * Fill in the dest mac
         */ 
        macp = mtod(m, unsigned char *); 
        bcopy( (caddr_t)dest_eth, (caddr_t)macp, LAN_ADDR_SIZE ) ; 

	/* source mac */
	bcopy( (caddr_t)(sc->sc_arpcom.ac_lanaddr), 
               (caddr_t)(macp + LAN_ADDR_SIZE),
               LAN_ADDR_SIZE );

	/* ethertype */
	bcopy( (caddr_t)(&ethertype), (caddr_t)(macp + 2 * LAN_ADDR_SIZE), 2);

	if (dst->sa_family == AF_ARP) {
		struct arphdr *ah = (struct arphdr *)(macp + 0xe);
		switch (ntohs(ah->ar_op)) {
		case ARPOP_REQUEST:
			/* ah->ar_hrd = htons(ARPHRD_ETHER); */
			if (replace_src_entry != NULL) {
				/* need to fill body sender IP addr */
				bcopy( (caddr_t) &(replace_src_entry->sin_addr),
                       			(caddr_t)(macp + 0x1c),
                       			4);
			}
                        /* we also should normalize the unusual test addr */
                        /* for (i = 0; i < LAN_ADDR_SIZE; i++)
				macp[0x20 + i] = 0x00; */
			break;
		}
	}
 
        s = splimp(); 
        if (IF_QFULL(&ifp->if_snd)) { 
            IF_DROP(&ifp->if_snd); 
            error = ENOBUFS; 
            splx(s); 
            goto qfull; 
        }
	DEBUGMSG2(sc, "enqueue mbuf for output"); 
        IF_ENQUEUE(&ifp->if_snd, m); 
        /* tk_ipc_ostart(ifp); */
	lestart(ifp);
        splx(s); 
        return 0; 
    qfull: 
        m0 = m; 
    bad: 
        m_freem(m0); 
        return error; 
}


/*
 * Setup output on interface.
 * Get another datagram to send off of the interface queue, and map it to the
 * interface before starting the output.
 * Called only at splimp or interrupt level.
 */
void
lestart(ifp)
	register struct ifnet *ifp;
{
	register struct le_softc *sc = LE_SOFTC(ifp->if_unit);
	register int bix;
	register struct mbuf *m;
	struct letmd tmd;
	int rp;
	int len;
	spl_t s;

	DEBUGMSG2(sc, "lestart");

        /* FIXME also return if the device is running but its queue is full */
	if ((ifp->if_flags & (IFF_RUNNING /*| IFF_OACTIVE*/)) != IFF_RUNNING) {
		DEBUGMSG2(sc, "lestart no IF_RUNNING early exit");
		return;
	}
	if (LE_BUSY(ifp->if_unit)) {
		DEBUGMSG2(sc, "lestart LE_BUSY early exit");
		return;
	}

	bix = sc->sc_last_td;

	for (;;) {
		DEBUGMSG2(sc, "fetching existing tmd from desc");
		rp = LE_TMDADDR(sc, bix);
		(*sc->sc_copyfromdesc)(sc, &tmd, rp, sizeof(tmd));

		if (tmd.tmd1_bits & LE_T1_OWN) {
			LE_BUSY(ifp->if_unit) = 1; /* ifp->if_flags |= IFF_OACTIVE; */
			printf("missing buffer, no_td = %d, last_td = %d\n",
			    sc->sc_no_td, sc->sc_last_td);
		}

		DEBUGMSG2(sc, "dequeue mbuf - attempting");
		s = splimp();
		IF_DEQUEUE(&ifp->if_snd, m);
		splx(s);
		if (m == 0) {
			DEBUGMSG2(sc, "dequeue failed bc queue is empty");
			break;
		}

		DEBUGMSG3(sc, "dequeued mbuf, it has %d bytes", m->m_len);

#if NBPFILTER > 0
		/*
		 * If BPF is listening on this interface, let it see the packet
		 * before we commit it to the wire.
		 */
		if (ifp->if_bpf)
			bpf_mtap(ifp->if_bpf, m);
#endif

		/*
		 * Copy the mbuf chain into the transmit buffer.
		 */
		DEBUGMSG2(sc, "putting mbuf chain into the transmit buffer");
		len = leput(sc, LE_TBUFADDR(sc, bix), m);

#ifdef LEDEBUG
		if (len > ETHERMTU + sizeof(struct ether_header))
			printf("packet length %d\n", len);
#endif
		DEBUGMSG2(sc, "set ifp->if_timer call for 20s");
		ifp->if_timer = 20;

		/*
		 * Init transmit registers, and set transmit start flag.
		 */
		DEBUGMSG2(sc, "init tx regs and set tx start flag");
		tmd.tmd1_bits = LE_T1_OWN | LE_T1_STP | LE_T1_ENP;
		tmd.tmd2 = -len | LE_XMD2_ONES;
		tmd.tmd3 = 0;

		DEBUGMSG2(sc, "copytodesc");
		(*sc->sc_copytodesc)(sc, &tmd, rp, sizeof(tmd));

#ifdef LEDEBUG
		if (sc->sc_debug)
			xmit_print(sc, sc->sc_last_td);
#endif

		lewrcsr(sc, LE_CSR0, LE_C0_INEA | LE_C0_TDMD); 
		/* lewrcsr(sc, LE_CSR0, LE_C0_TDMD); */

		/* rak: attempting bogus read to prod vbox check */
		/* lerdcsr(sc, LE_CSR0); */

		if (++bix == sc->sc_ntbuf)
			bix = 0;

		if (++sc->sc_no_td == sc->sc_ntbuf) {
			LE_BUSY(ifp->if_unit) = 1; /* ifp->if_flags |= IFF_OACTIVE; */
			break;
		}

	}

	sc->sc_last_td = bix;
	DEBUGMSG2(sc, "leaix: FIXME lestart: check m_freem\n");
}

struct in_addr * ifaddr_inaddr_pointer(struct ifaddr * ifa) {
	struct sockaddr * sa = &ifa->ifa_addr;
	struct sockaddr_in * sai;
	if (sa->sa_family != AF_INET) {
		return NULL;
	} else {
		sai = (struct sockaddr_in *) sa;
		return &sai->sin_addr;
	}
}

/*
 * Process an ioctl request.
 */
int
leioctl(ifp, cmd, data)
	register struct ifnet *ifp;
	u_long cmd;
	caddr_t data;
{
	struct le_softc *sc = LE_SOFTC(ifp->if_unit);
	struct ifaddr *ifa = (struct ifaddr *)data;
	/*
	struct ifreq *ifr = (struct ifreq *)data;
	*/
	int s, error = 0;

	s = splimp();

#if DEBUG_OUTPUT
	printf("leaix: ioctl if %s cmd %ld\n", ifp->if_name, cmd);
#endif
	switch (cmd) {

	case ALT_SIOCSIFADDR:
#if DEBUG_OUTPUT
		printf("leaix: SIOCSIFADDR\n");
#endif
		ifp->if_flags |= IFF_UP;

		switch (ifa->ifa_addr.sa_family) {
#ifdef INET
		case AF_INET:
			 leinit(sc); 
                        /* XXX anything required to init arp? */
			/* arp_ifinit(&sc->sc_arpcom, ifa); */
                        bcopy((caddr_t)ifaddr_inaddr_pointer(ifa),
                              (caddr_t)&sc->sc_arpcom.ac_ipaddr,
                              sizeof(struct in_addr));
                        arpwhohas(&sc->sc_arpcom, &sc->sc_arpcom.ac_ipaddr);
			break;
#endif
#ifdef NS
		case AF_NS:
		    {
			register struct ns_addr *ina = &IA_SNS(ifa)->sns_addr;

			if (ns_nullhost(*ina))
				ina->x_host =
				    *(union ns_host *)(sc->sc_arpcom.ac_enaddr);
			else
				bcopy(ina->x_host.c_host,
				    sc->sc_arpcom.ac_enaddr,
				    sizeof(sc->sc_arpcom.ac_enaddr));
			/* Set new address. */
			/* FIXME this does nothing */
                        leinit(sc);
			break;
		    }
#endif
		default:
			leinit(sc);
			break;
		}
		break;

#if defined(CCITT) && defined(LLC)
	case ALT_SIOCSIFCONF_X25:
		ifp->if_flags |= IFF_UP;
		ifa->ifa_rtrequest = (void (*)())cons_rtrequest; /* XXX */
		error = x25_llcglue(PRC_IFUP, ifa->ifa_addr);
		if (error == 0)
			leinit(sc);
		break;
#endif /* CCITT && LLC */

	case ALT_SIOCSIFFLAGS:
#if DEBUG_OUTPUT
		printf("leaix: SIOCSIFFLAGS\n");
#endif
		if ((ifp->if_flags & IFF_UP) == 0 &&
		    (ifp->if_flags & IFF_RUNNING) != 0) {
			/*
			 * If interface is marked down and it is running, then
			 * stop it.
			 */
			lestop(sc);
			ifp->if_flags &= ~IFF_RUNNING;
		} else if ((ifp->if_flags & IFF_UP) != 0 &&
		    	   (ifp->if_flags & IFF_RUNNING) == 0) {
			/*
			 * If interface is marked up and it is stopped, then
			 * start it.
			 */
			leinit(sc);
		} else {
			/*
			 * Reset the interface to pick up changes in any other
			 * flags that affect hardware registers.
			 */
			/*lestop(sc);*/
			leinit(sc);
		}
#ifdef LEDEBUG
		if (ifp->if_flags & IFF_DEBUG)
			sc->sc_debug = 1;
		else
			sc->sc_debug = 0;
#if DEBUG_OUTPUT
		printf("leaix: set debug %d\n", sc->sc_debug); 
#endif
#endif
		break;

        /* rak: Some network cards have the ability to filter
                based on MAC address themselves so the driver doesn't
                even get called for traffic that it doesn't care about.
                Interesting traffic is traffic for certain addresses:
                   - This station's address
                   - The broadcast address
                   - The destination multicast addresses for
                     any multicast groups we are interested in
                Because the multicast groups are installation specific,
                and interest in them could change over time, the filtering 
                needs to use a configurable list of them.

                AIX doesn't support multicast so we'll just ignore these
                commands for now.
        */

        /*
	case ALT_SIOCADDMULTI:
	case ALT_SIOCDELMULTI:
		error = (cmd == ALT_SIOCADDMULTI) ?
		    ether_addmulti(ifr, &sc->sc_arpcom) :
		    ether_delmulti(ifr, &sc->sc_arpcom);

		if (error == ENETRESET) { */
			/*
			 * Multicast list has changed; set the hardware filter
			 * accordingly.
			 */
		/*	lereset(sc);
			error = 0;
		}
		break; */

	default:
		printf("leaix: unknown ioctl\n");
		error = EINVAL;
		break;
	}

	splx(s);
	return (error);
}

#ifdef LEDEBUG

#define DUMP_PACKET 1

#if DUMP_PACKET
#define DEBUG_BUF_LIMIT 1600
#endif

void
recv_print(sc, no)
	struct le_softc *sc;
	int no;
{
	struct lermd rmd;
	u_int16_t len;
	struct ether_header eh;
#if DUMP_PACKET
	unsigned char debug_buf[DEBUG_BUF_LIMIT];
#endif

	(*sc->sc_copyfromdesc)(sc, &rmd, LE_RMDADDR(sc, no), sizeof(rmd));
	len = rmd.rmd3;
	printf("%s: receive buffer %d, len = %d\n", sc->sc_dev.dv_xname, no,
	    len);
	printf("%s: status %04x\n", sc->sc_dev.dv_xname, lerdcsr(sc, LE_CSR0));
	printf("%s: ladr %04x, hadr %02x, flags %02x, bcnt %04x, mcnt %04x\n",
	    sc->sc_dev.dv_xname,
	    rmd.rmd0, rmd.rmd1_hadr, rmd.rmd1_bits, rmd.rmd2, rmd.rmd3);
	if (len >= sizeof(eh)) {
		(*sc->sc_copyfrombuf)(sc, &eh, LE_RBUFADDR(sc, no), sizeof(eh));
		printf(": dst %s", ether_sprintf(eh.eth_dhost));
		printf(" src %s type %04x\n", ether_sprintf(eh.eth_shost),
		    ntohs(eh.eth_type));
	}
#if DUMP_PACKET
	if (len < DEBUG_BUF_LIMIT) {
		int i;
		printf("leaix: rx packet data (len %d): ", len);
		(*sc->sc_copyfrombuf)(sc, debug_buf, LE_RBUFADDR(sc, no), len);
		for (i = 0; i < len; i++) {
			if (i % 16 == 0) { printf("\n%06x ", i); }
			printf("%02x ", debug_buf[i] & 0xff);
		}
		printf("\n");
	}
#endif

}


void
xmit_print(sc, no)
	struct le_softc *sc;
	int no;
{
	struct letmd tmd;
	u_int16_t len;
	struct ether_header eh;
#if DUMP_PACKET
	unsigned char debug_buf[DEBUG_BUF_LIMIT];
#endif

	(*sc->sc_copyfromdesc)(sc, &tmd, LE_TMDADDR(sc, no), sizeof(tmd));
	len = -tmd.tmd2;
	printf("%s: transmit buffer %d, len = %d\n", sc->sc_dev.dv_xname, no,
	    len);
	printf("%s: status %04x\n", sc->sc_dev.dv_xname, lerdcsr(sc, LE_CSR0));
	printf("%s: ladr %04x, hadr %02x, flags %02x, bcnt %04x, mcnt %04x\n",
	    sc->sc_dev.dv_xname,
	    tmd.tmd0, tmd.tmd1_hadr, tmd.tmd1_bits, tmd.tmd2, tmd.tmd3);
	if (len >= sizeof(eh)) {
		(*sc->sc_copyfrombuf)(sc, &eh, LE_TBUFADDR(sc, no), sizeof(eh));
		printf(": dst %s", ether_sprintf(eh.eth_dhost));
		printf(" src %s type %04x\n", ether_sprintf(eh.eth_shost),
		    ntohs(eh.eth_type));
	}
#if DUMP_PACKET
	if (len < DEBUG_BUF_LIMIT) {
		int i;
		printf("leaix: tx packet data (len %d): ", len);
		(*sc->sc_copyfrombuf)(sc, debug_buf, LE_TBUFADDR(sc, no), len);
		for (i = 0; i < len; i++) {
			if (i % 16 == 0) { printf("\n%06x ", i); }
			printf("%02x ", debug_buf[i] & 0xff);
		}
		printf("\n");
	}
#endif
}
#endif /* LEDEBUG */

/*
 * Set up the logical address filter.
 */
void
lesetladrf(ac, af)
	struct arpcom *ac;
	u_int16_t *af;
{
        /* rak: AIX 1.x doesn't have multicast support, so all the multicast
           parts of this are just going to be skipped */

	struct ifnet *ifp = &ac->ac_if;
	/*
	struct ether_multi *enm;
	register u_char *cp, c;
	register u_int32_t crc;
	register int i, len;
	*/

	/* struct ether_multistep step; */

	/*
	 * Set up multicast address filter by passing all multicast addresses
	 * through a crc generator, and then using the high order 6 bits as an
	 * index into the 64 bit logical address filter.  The high order bit
	 * selects the word, while the rest of the bits select the bit within
	 * the word.
	 */

	if (ifp->if_flags & IFF_PROMISC)
		goto allmulti;

	af[0] = af[1] = af[2] = af[3] = 0x0000;
#if 0
	ETHER_FIRST_MULTI(step, ac, enm);
	while (enm != NULL) {
		if (bcmp(enm->enm_addrlo, enm->enm_addrhi,
		    sizeof(enm->enm_addrlo)) != 0) { 
			/*
			 * We must listen to a range of multicast addresses.
			 * For now, just accept all multicasts, rather than
			 * trying to set only those filter bits needed to match
			 * the range.  (At this time, the only use of address
			 * ranges is for IP multicast routing, for which the
			 * range is big enough to require all bits set.)
			 */
			goto allmulti;
		}

		cp = enm->enm_addrlo;
		crc = 0xffffffff;
		for (len = sizeof(enm->enm_addrlo); --len >= 0;) {
			c = *cp++;
			for (i = 8; --i >= 0;) {
				if ((crc & 0x01) ^ (c & 0x01)) {
					crc >>= 1;
					crc ^= 0xedb88320;
				} else
					crc >>= 1;
				c >>= 1;
			}
		} 
		/* Just want the 6 most significant bits. */ 
		crc >>= 26;

		/* Set the corresponding bit in the filter. */
		af[crc >> 4] |= 1 << (crc & 0xf);

		ETHER_NEXT_MULTI(step, enm);
	}
	ifp->if_flags &= ~IFF_ALLMULTI;
#endif
	return;

allmulti:
#if 0
	ifp->if_flags |= IFF_ALLMULTI;
#endif
	af[0] = af[1] = af[2] = af[3] = 0xffff; 
}


#if 0	/* USE OF THE FOLLOWING IS MACHINE-SPECIFIC */
/*
 * Routines for accessing the transmit and receive buffers. Unfortunately,
 * CPU addressing of these buffers is done in one of 3 ways:
 * - contiguous (for the 3max and turbochannel option card)
 * - gap2, which means shorts (2 bytes) interspersed with short (2 byte)
 *   spaces (for the pmax)
 * - gap16, which means 16bytes interspersed with 16byte spaces
 *   for buffers which must begin on a 32byte boundary (for 3min and maxine)
 * The buffer offset is the logical byte offset, assuming contiguous storage.
 */
void
copytodesc_contig(sc, from, boff, len)
	struct le_softc *sc;
	caddr_t from;
	int boff, len;
{
	volatile caddr_t buf = sc->sc_mem;

	/*
	 * Just call bcopy() to do the work.
	 */
	bcopy(from, buf + boff, len);
}

void
copyfromdesc_contig(sc, to, boff, len)
	struct le_softc *sc;
	caddr_t to;
	int boff, len;
{
	volatile caddr_t buf = sc->sc_mem;

	/*
	 * Just call bcopy() to do the work.
	 */
	bcopy(buf + boff, to, len);
}

void
copytobuf_contig(sc, from, boff, len)
	struct le_softc *sc;
	caddr_t from;
	int boff, len;
{
	volatile caddr_t buf = sc->sc_mem;

	/*
	 * Just call bcopy() to do the work.
	 */
	bcopy(from, buf + boff, len);
}

void
copyfrombuf_contig(sc, to, boff, len)
	struct le_softc *sc;
	caddr_t to;
	int boff, len;
{
	volatile caddr_t buf = sc->sc_mem;

	/*
	 * Just call bcopy() to do the work.
	 */
	bcopy(buf + boff, to, len);
}

void
zerobuf_contig(sc, boff, len)
	struct le_softc *sc;
	int boff, len;
{
	volatile caddr_t buf = sc->sc_mem;

	/*
	 * Just let bzero() do the work
	 */
	bzero(buf + boff, len);
}

/*
 * For the pmax the buffer consists of shorts (2 bytes) interspersed with
 * short (2 byte) spaces and must be accessed with halfword load/stores.
 * (don't worry about doing an extra byte)
 */
void
copytobuf_gap2(sc, from, boff, len)
	struct le_softc *sc;
	register caddr_t from;
	int boff;
	register int len;
{
	volatile caddr_t buf = sc->sc_mem;
	register volatile u_short *bptr;
	register int xfer;

	if (boff & 0x1) {
		/* handle unaligned first byte */
		bptr = ((volatile u_short *)buf) + (boff - 1);
		*bptr = (*from++ << 8) | (*bptr & 0xff);
		bptr += 2;
		len--;
	} else
		bptr = ((volatile u_short *)buf) + boff;
	if ((unsigned)from & 0x1) {
		while (len > 1) {
			*bptr = (from[1] << 8) | (from[0] & 0xff);
			bptr += 2;
			from += 2;
			len -= 2;
		}
	} else {
		/* optimize for aligned transfers */
		xfer = (int)((unsigned)len & ~0x1);
		CopyToBuffer((u_short *)from, bptr, xfer);
		bptr += xfer;
		from += xfer;
		len -= xfer;
	}
	if (len == 1)
		*bptr = (u_short)*from;
}

void
copyfrombuf_gap2(sc, to, boff, len)
	struct le_softc *sc;
	register caddr_t to;
	int boff, len;
{
	volatile caddr_t buf = sc->sc_mem;
	register volatile u_short *bptr;
	register u_short tmp;
	register int xfer;

	if (boff & 0x1) {
		/* handle unaligned first byte */
		bptr = ((volatile u_short *)buf) + (boff - 1);
		*to++ = (*bptr >> 8) & 0xff;
		bptr += 2;
		len--;
	} else
		bptr = ((volatile u_short *)buf) + boff;
	if ((unsigned)to & 0x1) {
		while (len > 1) {
			tmp = *bptr;
			*to++ = tmp & 0xff;
			*to++ = (tmp >> 8) & 0xff;
			bptr += 2;
			len -= 2;
		}
	} else {
		/* optimize for aligned transfers */
		xfer = (int)((unsigned)len & ~0x1);
		CopyFromBuffer(bptr, to, xfer);
		bptr += xfer;
		to += xfer;
		len -= xfer;
	}
	if (len == 1)
		*to = *bptr & 0xff;
}

void
zerobuf_gap2(sc, boff, len)
	struct le_softc *sc;
	int boff, len;
{
	volatile caddr_t buf = sc->sc_mem;
	register volatile u_short *bptr;

	if ((unsigned)boff & 0x1) {
		bptr = ((volatile u_short *)buf) + (boff - 1);
		*bptr &= 0xff;
		bptr += 2;
		len--;
	} else
		bptr = ((volatile u_short *)buf) + boff;
	while (len > 0) {
		*bptr = 0;
		bptr += 2;
		len -= 2;
	}
}

/*
 * For the 3min and maxine, the buffers are in main memory filled in with
 * 16byte blocks interspersed with 16byte spaces.
 */
void
copytobuf_gap16(sc, from, boff, len)
	struct le_softc *sc;
	register caddr_t from;
	int boff;
	register int len;
{
	volatile caddr_t buf = sc->sc_mem;
	register caddr_t bptr;
	register int xfer;

	bptr = buf + ((boff << 1) & ~0x1f);
	boff &= 0xf;
	xfer = min(len, 16 - boff);
	while (len > 0) {
		bcopy(from, bptr + boff, xfer);
		from += xfer;
		bptr += 32;
		boff = 0;
		len -= xfer;
		xfer = min(len, 16);
	}
}

void
copyfrombuf_gap16(sc, to, boff, len)
	struct le_softc *sc;
	register caddr_t to;
	int boff, len;
{
	volatile caddr_t buf = sc->sc_mem;
	register caddr_t bptr;
	register int xfer;

	bptr = buf + ((boff << 1) & ~0x1f);
	boff &= 0xf;
	xfer = min(len, 16 - boff);
	while (len > 0) {
		bcopy(bptr + boff, to, xfer);
		to += xfer;
		bptr += 32;
		boff = 0;
		len -= xfer;
		xfer = min(len, 16);
	}
}

void
zerobuf_gap16(sc, boff, len)
	struct le_softc *sc;
	int boff, len;
{
	volatile caddr_t buf = sc->sc_mem;
	register caddr_t bptr;
	register int xfer;

	bptr = buf + ((boff << 1) & ~0x1f);
	boff &= 0xf;
	xfer = min(len, 16 - boff);
	while (len > 0) {
		bzero(bptr + boff, xfer);
		bptr += 32;
		boff = 0;
		len -= xfer;
		xfer = min(len, 16);
	}
}
#endif

#include "pci.c"
