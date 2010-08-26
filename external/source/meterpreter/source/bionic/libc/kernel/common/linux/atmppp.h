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
#ifndef _LINUX_ATMPPP_H
#define _LINUX_ATMPPP_H

#include <linux/atm.h>

#define PPPOATM_ENCAPS_AUTODETECT (0)
#define PPPOATM_ENCAPS_VC (1)
#define PPPOATM_ENCAPS_LLC (2)

struct atm_backend_ppp {
 atm_backend_t backend_num;
 int encaps;
};

#endif
