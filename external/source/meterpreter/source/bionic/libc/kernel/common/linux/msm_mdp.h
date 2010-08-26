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
#ifndef _MSM_MDP_H_
#define _MSM_MDP_H_

#include <linux/types.h>

#define MSMFB_IOCTL_MAGIC 'm'
#define MSMFB_GRP_DISP _IOW(MSMFB_IOCTL_MAGIC, 1, unsigned int)
#define MSMFB_BLIT _IOW(MSMFB_IOCTL_MAGIC, 2, unsigned int)

enum {
 MDP_RGB_565,
 MDP_XRGB_8888,
 MDP_Y_CBCR_H2V2,
 MDP_ARGB_8888,
 MDP_RGB_888,
 MDP_Y_CRCB_H2V2,
 MDP_YCRYCB_H2V1,
 MDP_Y_CRCB_H2V1,
 MDP_Y_CBCR_H2V1,
 MDP_RGBA_8888,
 MDP_BGRA_8888,
 MDP_RGBX_8888,
 MDP_IMGTYPE_LIMIT
};

enum {
 PMEM_IMG,
 FB_IMG,
};

#define MDP_ROT_NOP 0
#define MDP_FLIP_LR 0x1
#define MDP_FLIP_UD 0x2
#define MDP_ROT_90 0x4
#define MDP_ROT_180 (MDP_FLIP_UD|MDP_FLIP_LR)
#define MDP_ROT_270 (MDP_ROT_90|MDP_FLIP_UD|MDP_FLIP_LR)
#define MDP_DITHER 0x8
#define MDP_BLUR 0x10
#define MDP_BLEND_FG_PREMULT 0x20000

#define MDP_TRANSP_NOP 0xffffffff
#define MDP_ALPHA_NOP 0xff

struct mdp_rect {
 uint32_t x;
 uint32_t y;
 uint32_t w;
 uint32_t h;
};

struct mdp_img {
 uint32_t width;
 uint32_t height;
 uint32_t format;
 uint32_t offset;
 int memory_id;
};

struct mdp_blit_req {
 struct mdp_img src;
 struct mdp_img dst;
 struct mdp_rect src_rect;
 struct mdp_rect dst_rect;
 uint32_t alpha;
 uint32_t transp_mask;
 uint32_t flags;
};

struct mdp_blit_req_list {
 uint32_t count;
 struct mdp_blit_req req[];
};

#endif

