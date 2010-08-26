/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was automatically generated from a Linux kernel header
 ***   of the same name, to make information necessary for userspace to
 ***   call into the kernel available to libc.  It contains only constants,
 ***   structures, and macros generated from the original header, and thus,
 ***   contains no copyrightable information.
 ***
 ****************************************************************************
 ****************************************************************************/
#ifndef __ASM_SH_IOCTLS_H
#define __ASM_SH_IOCTLS_H

#include <asm/ioctl.h>

#define FIOCLEX _IO('f', 1)
#define FIONCLEX _IO('f', 2)
#define FIOASYNC _IOW('f', 125, int)
#define FIONBIO _IOW('f', 126, int)
#define FIONREAD _IOR('f', 127, int)
#define TIOCINQ FIONREAD
#define FIOQSIZE _IOR('f', 128, loff_t)

#define TCGETS 0x5401
#define TCSETS 0x5402
#define TCSETSW 0x5403
#define TCSETSF 0x5404

#define TCGETA 0x80127417  
#define TCSETA 0x40127418  
#define TCSETAW 0x40127419  
#define TCSETAF 0x4012741C  

#define TCSBRK _IO('t', 29)
#define TCXONC _IO('t', 30)
#define TCFLSH _IO('t', 31)

#define TIOCSWINSZ 0x40087467  
#define TIOCGWINSZ 0x80087468  
#define TIOCSTART _IO('t', 110)  
#define TIOCSTOP _IO('t', 111)  
#define TIOCOUTQ _IOR('t', 115, int)  

#define TIOCSPGRP _IOW('t', 118, int)
#define TIOCGPGRP _IOR('t', 119, int)

#define TIOCEXCL _IO('T', 12)  
#define TIOCNXCL _IO('T', 13)  
#define TIOCSCTTY _IO('T', 14)  

#define TIOCSTI _IOW('T', 18, char)  
#define TIOCMGET _IOR('T', 21, unsigned int)  
#define TIOCMBIS _IOW('T', 22, unsigned int)  
#define TIOCMBIC _IOW('T', 23, unsigned int)  
#define TIOCMSET _IOW('T', 24, unsigned int)  
#define TIOCM_LE 0x001
#define TIOCM_DTR 0x002
#define TIOCM_RTS 0x004
#define TIOCM_ST 0x008
#define TIOCM_SR 0x010
#define TIOCM_CTS 0x020
#define TIOCM_CAR 0x040
#define TIOCM_RNG 0x080
#define TIOCM_DSR 0x100
#define TIOCM_CD TIOCM_CAR
#define TIOCM_RI TIOCM_RNG

#define TIOCGSOFTCAR _IOR('T', 25, unsigned int)  
#define TIOCSSOFTCAR _IOW('T', 26, unsigned int)  
#define TIOCLINUX _IOW('T', 28, char)  
#define TIOCCONS _IO('T', 29)  
#define TIOCGSERIAL 0x803C541E  
#define TIOCSSERIAL 0x403C541F  
#define TIOCPKT _IOW('T', 32, int)  
#define TIOCPKT_DATA 0
#define TIOCPKT_FLUSHREAD 1
#define TIOCPKT_FLUSHWRITE 2
#define TIOCPKT_STOP 4
#define TIOCPKT_START 8
#define TIOCPKT_NOSTOP 16
#define TIOCPKT_DOSTOP 32

#define TIOCNOTTY _IO('T', 34)  
#define TIOCSETD _IOW('T', 35, int)  
#define TIOCGETD _IOR('T', 36, int)  
#define TCSBRKP _IOW('T', 37, int)    
#define TIOCSBRK _IO('T', 39)    
#define TIOCCBRK _IO('T', 40)    
#define TIOCGSID _IOR('T', 41, pid_t)    
#define TCGETS2 _IOR('T', 42, struct termios2)
#define TCSETS2 _IOW('T', 43, struct termios2)
#define TCSETSW2 _IOW('T', 44, struct termios2)
#define TCSETSF2 _IOW('T', 45, struct termios2)
#define TIOCGPTN _IOR('T',0x30, unsigned int)  
#define TIOCSPTLCK _IOW('T',0x31, int)  

#define TIOCSERCONFIG _IO('T', 83)  
#define TIOCSERGWILD _IOR('T', 84, int)  
#define TIOCSERSWILD _IOW('T', 85, int)  
#define TIOCGLCKTRMIOS 0x5456
#define TIOCSLCKTRMIOS 0x5457
#define TIOCSERGSTRUCT 0x80d85458    
#define TIOCSERGETLSR _IOR('T', 89, unsigned int)    

#define TIOCSER_TEMT 0x01  
#define TIOCSERGETMULTI 0x80A8545A    
#define TIOCSERSETMULTI 0x40A8545B    

#define TIOCMIWAIT _IO('T', 92)    
#define TIOCGICOUNT 0x545D  

#endif
