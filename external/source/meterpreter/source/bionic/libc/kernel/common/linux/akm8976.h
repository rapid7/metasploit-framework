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
#ifndef AKM8976_H
#define AKM8976_H

#include <linux/ioctl.h>

#define AKECS_MODE_MEASURE 0x00  

#define AKECS_MODE_PFFD 0x01  
#define AKECS_MODE_E2P_READ 0x02  
#define AKECS_MODE_POWERDOWN 0x03  

#define AKECS_MODE_MEASURE_SNG 0x10  
#define AKECS_MODE_MEASURE_SEQ 0x11  

#define CSPEC_AINT 0x01  
#define CSPEC_SNG_NUM 0x01  
#define CSPEC_SEQ_NUM 0x02  
#define CSPEC_SFRQ_32 0x00  
#define CSPEC_SFRQ_64 0x01  
#define CSPEC_MCS 0x07  
#define CSPEC_MKS 0x01  
#define CSPEC_INTEN 0x01  

#define RBUFF_SIZE 31  
#define MAX_CALI_SIZE 0x1000U  

#define AKECS_REG_ST 0xC0
#define AKECS_REG_TMPS 0xC1
#define AKECS_REG_MS1 0xE0
#define AKECS_REG_MS2 0xE1
#define AKECS_REG_MS3 0xE2

#define AKMIO 0xA1

#define ECS_IOCTL_INIT _IO(AKMIO, 0x01)
#define ECS_IOCTL_WRITE _IOW(AKMIO, 0x02, char[5])
#define ECS_IOCTL_READ _IOWR(AKMIO, 0x03, char[5])
#define ECS_IOCTL_RESET _IO(AKMIO, 0x04)
#define ECS_IOCTL_INT_STATUS _IO(AKMIO, 0x05)
#define ECS_IOCTL_FFD_STATUS _IO(AKMIO, 0x06)
#define ECS_IOCTL_SET_MODE _IOW(AKMIO, 0x07, short)
#define ECS_IOCTL_GETDATA _IOR(AKMIO, 0x08, char[RBUFF_SIZE+1])
#define ECS_IOCTL_GET_NUMFRQ _IOR(AKMIO, 0x09, char[2])
#define ECS_IOCTL_SET_PERST _IO(AKMIO, 0x0A)
#define ECS_IOCTL_SET_G0RST _IO(AKMIO, 0x0B)
#define ECS_IOCTL_SET_YPR _IOW(AKMIO, 0x0C, short[12])
#define ECS_IOCTL_GET_OPEN_STATUS _IOR(AKMIO, 0x0D, int)
#define ECS_IOCTL_GET_CLOSE_STATUS _IOR(AKMIO, 0x0E, int)
#define ECS_IOCTL_GET_CALI_DATA _IOR(AKMIO, 0x0F, char[MAX_CALI_SIZE])
#define ECS_IOCTL_GET_DELAY _IOR(AKMIO, 0x30, short)

#define ECS_IOCTL_APP_SET_MODE _IOW(AKMIO, 0x10, short)
#define ECS_IOCTL_APP_SET_MFLAG _IOW(AKMIO, 0x11, short)
#define ECS_IOCTL_APP_GET_MFLAG _IOW(AKMIO, 0x12, short)
#define ECS_IOCTL_APP_SET_AFLAG _IOW(AKMIO, 0x13, short)
#define ECS_IOCTL_APP_GET_AFLAG _IOR(AKMIO, 0x14, short)
#define ECS_IOCTL_APP_SET_TFLAG _IOR(AKMIO, 0x15, short)
#define ECS_IOCTL_APP_GET_TFLAG _IOR(AKMIO, 0x16, short)
#define ECS_IOCTL_APP_RESET_PEDOMETER _IO(AKMIO, 0x17)
#define ECS_IOCTL_APP_SET_DELAY _IOW(AKMIO, 0x18, short)
#define ECS_IOCTL_APP_GET_DELAY ECS_IOCTL_GET_DELAY
#define ECS_IOCTL_APP_SET_MVFLAG _IOW(AKMIO, 0x19, short)  
#define ECS_IOCTL_APP_GET_MVFLAG _IOR(AKMIO, 0x1A, short)  

#define ECS_IOCTL_SET_STEP_CNT _IOW(AKMIO, 0x20, short)

#define ECS_RST 146  
#define ECS_CLK_ON 155  
#define ECS_INTR 161  

struct akm8976_platform_data {
 int reset;
 int clk_on;
 int intr;
};

#endif

