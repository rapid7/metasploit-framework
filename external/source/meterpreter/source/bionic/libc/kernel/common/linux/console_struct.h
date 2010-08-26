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
#include <linux/wait.h>
#include <linux/vt.h>

struct vt_struct;

#define NPAR 16

struct vc_data {
 unsigned short vc_num;
 unsigned int vc_cols;
 unsigned int vc_rows;
 unsigned int vc_size_row;
 unsigned int vc_scan_lines;
 unsigned long vc_origin;
 unsigned long vc_scr_end;
 unsigned long vc_visible_origin;
 unsigned int vc_top, vc_bottom;
 const struct consw *vc_sw;
 unsigned short *vc_screenbuf;
 unsigned int vc_screenbuf_size;
 unsigned char vc_mode;

 unsigned char vc_attr;
 unsigned char vc_def_color;
 unsigned char vc_color;
 unsigned char vc_s_color;
 unsigned char vc_ulcolor;
 unsigned char vc_halfcolor;

 unsigned int vc_cursor_type;
 unsigned short vc_complement_mask;
 unsigned short vc_s_complement_mask;
 unsigned int vc_x, vc_y;
 unsigned int vc_saved_x, vc_saved_y;
 unsigned long vc_pos;

 unsigned short vc_hi_font_mask;
 struct console_font vc_font;
 unsigned short vc_video_erase_char;

 unsigned int vc_state;
 unsigned int vc_npar,vc_par[NPAR];
 struct tty_struct *vc_tty;

 struct vt_mode vt_mode;
 int vt_pid;
 int vt_newvt;
 wait_queue_head_t paste_wait;

 unsigned int vc_charset : 1;
 unsigned int vc_s_charset : 1;
 unsigned int vc_disp_ctrl : 1;
 unsigned int vc_toggle_meta : 1;
 unsigned int vc_decscnm : 1;
 unsigned int vc_decom : 1;
 unsigned int vc_decawm : 1;
 unsigned int vc_deccm : 1;
 unsigned int vc_decim : 1;
 unsigned int vc_deccolm : 1;

 unsigned int vc_intensity : 2;
 unsigned int vc_underline : 1;
 unsigned int vc_blink : 1;
 unsigned int vc_reverse : 1;
 unsigned int vc_s_intensity : 2;
 unsigned int vc_s_underline : 1;
 unsigned int vc_s_blink : 1;
 unsigned int vc_s_reverse : 1;

 unsigned int vc_ques : 1;
 unsigned int vc_need_wrap : 1;
 unsigned int vc_can_do_color : 1;
 unsigned int vc_report_mouse : 2;
 unsigned int vc_kmalloced : 1;
 unsigned char vc_utf : 1;
 unsigned char vc_utf_count;
 int vc_utf_char;
 unsigned int vc_tab_stop[8];
 unsigned char vc_palette[16*3];
 unsigned short * vc_translate;
 unsigned char vc_G0_charset;
 unsigned char vc_G1_charset;
 unsigned char vc_saved_G0;
 unsigned char vc_saved_G1;
 unsigned int vc_bell_pitch;
 unsigned int vc_bell_duration;
 struct vc_data **vc_display_fg;
 unsigned long vc_uni_pagedir;
 unsigned long *vc_uni_pagedir_loc;

};

struct vc {
 struct vc_data *d;

};

#define CUR_DEF 0
#define CUR_NONE 1
#define CUR_UNDERLINE 2
#define CUR_LOWER_THIRD 3
#define CUR_LOWER_HALF 4
#define CUR_TWO_THIRDS 5
#define CUR_BLOCK 6
#define CUR_HWMASK 0x0f
#define CUR_SWMASK 0xfff0

#define CUR_DEFAULT CUR_UNDERLINE

#define CON_IS_VISIBLE(conp) (*conp->vc_display_fg == conp)
