# $FreeBSD: src/lib/msun/alpha/Makefile.inc,v 1.2 2005/03/07 04:53:35 das Exp $

ARCH_SRCS = s_copysign.S s_copysignf.S
LDBL_PREC = 53

# XXX Comment from NetBSD/Alpha:
# XXX LINT SIGFPEs in e_exp.c's strtod().  FP underflow/denorm software
# handling is broken (doesn't exist!) on the Alpha port.
# Stock gcc 2.7.2.1 doesn't understand these options.
#CFLAGS += -mtrap-precision=i -mfp-trap-mode=su
