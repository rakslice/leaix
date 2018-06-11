#ifndef _AM7990_ADDS_H_
#define _AM7990_ADDS_H_

/* Additional definitions for am7990.c */

#define ETHERNETMTU 1500

#include <types.h>
#include <sys/socket.h>
#include <sys/in.h>
#include <sys/if.h>
#include <sys/if_ieee802.h>

#define ac_enaddr ac_lanaddr

/* there's no struct device on this platform. however, we could make one 
to store basic bookkeeping information that we need */

struct device {
	short dv_unit;
	char * dv_xname;
};

#if NISA >= 1
struct isa_attach_args {
	int	ia_iobase;		/* base i/o address */
	int	ia_iosize;		/* span of ports used */
	int	ia_irq;			/* interrupt request */
	int	ia_drq;			/* DMA request */
	int	ia_maddr;		/* physical i/o mem addr */
	u_int	ia_msize;		/* size of i/o memory */
	void	*ia_aux;		/* driver specific */
};

/* ISA interrupt sharing types */
typedef enum {
	ISA_IST_NONE = 0,	/* not yet assigned */
	ISA_IST_PULSE,		/* pulsed */
	ISA_IST_EDGE,		/* edge-triggered */
	ISA_IST_LEVEL		/* level-triggered */
} isa_intrtype;

/* ISA interrupt levels; system interrupt levels for ISA bus use */
typedef enum {
	ISA_IPL_NONE,		/* block only the interrupt's IRQ*/
	ISA_IPL_BIO,		/* block I/O interrupts */
	ISA_IPL_NET,		/* network */
	ISA_IPL_TTY,		/* terminal */
	ISA_IPL_CLOCK,		/* clock */
} isa_intrlevel;
#endif

/* The ioctl cmd constant macros expect silly preprocessor
behaviour and break break under gcc. Here are replacements */

#ifdef KERNEL
#define _ALT_IOW(x,y,t)     ((x<<8)|(y))
#define _ALT_IOWR(x,y,t)     ((x<<8)|(y))
#endif
#define ALT_SIOCSIFADDR    _ALT_IOW('i', 12, struct ifreq)  /* set ifnet address */
#define ALT_SIOCGIFADDR    _ALT_IOWR('i',13, struct ifreq)  /* get ifnet address */
#define ALT_SIOCSIFDSTADDR _ALT_IOW('i', 14, struct ifreq)  /* set p-p address */
#define ALT_SIOCGIFDSTADDR _ALT_IOWR('i',15, struct ifreq)  /* get p-p address */
#define ALT_SIOCSIFFLAGS   _ALT_IOW('i', 16, struct ifreq)  /* set ifnet flags */
#define ALT_SIOCGIFFLAGS   _ALT_IOWR('i',17, struct ifreq)  /* get ifnet flags */
#define ALT_SIOCGIFBRDADDR _ALT_IOWR('i',18, struct ifreq)  /* get broadcast addr */
#define ALT_SIOCSIFBRDADDR _ALT_IOW('i',19, struct ifreq)   /* set broadcast addr */
#define ALT_SIOCGIFCONF    _ALT_IOWR('i',20, struct ifconf) /* get ifnet list */
#define ALT_SIOCGIFNETMASK _ALT_IOWR('i',21, struct ifreq)  /* get net addr mask */
#define ALT_SIOCSIFNETMASK _ALT_IOW('i',22, struct ifreq)   /* set net addr mask */
#define ALT_SIOCGIFMETRIC  _ALT_IOWR('i',23, struct ifreq)  /* get IF metric */
#define ALT_SIOCSIFMETRIC  _ALT_IOW('i',24, struct ifreq)   /* set IF metric */
#define ALT_SIOCGIFMTU     _ALT_IOWR('i',25, struct ifreq)  /* get IF mtu */
#define ALT_SIOCSIFMTU     _ALT_IOW('i',26, struct ifreq)   /* set IF mtu */
#define ALT_SIOCGIFREMMTU  _ALT_IOWR('i',27, struct ifreq)  /* get IF remmtu */
#define ALT_SIOCSIFREMMTU  _ALT_IOW('i',28, struct ifreq)   /* set IF remmtu */

#define outb iooutb

#define DRQUNK -1

#define kvtop KVTOP
paddr_t kvtophys (caddr_t cptr);

/** some missing defines */

int if_attach(struct ifnet *);
int panic(char *s);
char * ether_sprintf(u_char * ap);

int mclput(struct mbuf *m);
void m_freem(struct mbuf *m);
void m_adj(struct mbuf *m, int len);

int arpresolve(register struct arpcom *ac,
	struct mbuf *m,
	register struct in_addr *destip,
	register unsigned char *desten,
	int *usetrailers);

/* this is the manual def, but why would we have an mbuf at the point? */
int arpinput (struct arpcom *ac, struct mbuf *m); 

int arpwhohas(register struct arpcom *ac, struct in_addr *addr);

int schedrtcintr(int handle);


void delayloop(int usec);
#endif
