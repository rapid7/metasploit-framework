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
#ifndef _HIL_H_
#define _HIL_H_

#include <asm/types.h>

#define HIL_CLOCK 8MHZ
#define HIL_EK1_CLOCK 30HZ
#define HIL_EK2_CLOCK 60HZ

#define HIL_TIMEOUT_DEV 5  
#define HIL_TIMEOUT_DEVS 10  
#define HIL_TIMEOUT_NORESP 10  
#define HIL_TIMEOUT_DEVS_DATA 16  
#define HIL_TIMEOUT_SELFTEST 200  

#define HIL_WIRE_PACKET_LEN 15
enum hil_wire_bitpos {
 HIL_WIRE_START = 0,
 HIL_WIRE_ADDR2,
 HIL_WIRE_ADDR1,
 HIL_WIRE_ADDR0,
 HIL_WIRE_COMMAND,
 HIL_WIRE_DATA7,
 HIL_WIRE_DATA6,
 HIL_WIRE_DATA5,
 HIL_WIRE_DATA4,
 HIL_WIRE_DATA3,
 HIL_WIRE_DATA2,
 HIL_WIRE_DATA1,
 HIL_WIRE_DATA0,
 HIL_WIRE_PARITY,
 HIL_WIRE_STOP
};

enum hil_pkt_bitpos {
 HIL_PKT_CMD = 0x00000800,
 HIL_PKT_ADDR2 = 0x00000400,
 HIL_PKT_ADDR1 = 0x00000200,
 HIL_PKT_ADDR0 = 0x00000100,
 HIL_PKT_ADDR_MASK = 0x00000700,
 HIL_PKT_ADDR_SHIFT = 8,
 HIL_PKT_DATA7 = 0x00000080,
 HIL_PKT_DATA6 = 0x00000040,
 HIL_PKT_DATA5 = 0x00000020,
 HIL_PKT_DATA4 = 0x00000010,
 HIL_PKT_DATA3 = 0x00000008,
 HIL_PKT_DATA2 = 0x00000004,
 HIL_PKT_DATA1 = 0x00000002,
 HIL_PKT_DATA0 = 0x00000001,
 HIL_PKT_DATA_MASK = 0x000000FF,
 HIL_PKT_DATA_SHIFT = 0
};

enum hil_error_bitpos {
 HIL_ERR_OB = 0x00000800,
 HIL_ERR_INT = 0x00010000,
 HIL_ERR_NMI = 0x00020000,
 HIL_ERR_LERR = 0x00040000,
 HIL_ERR_PERR = 0x01000000,
 HIL_ERR_FERR = 0x02000000,
 HIL_ERR_FOF = 0x04000000
};

enum hil_control_bitpos {
 HIL_CTRL_TEST = 0x00010000,
 HIL_CTRL_IPF = 0x00040000,
 HIL_CTRL_APE = 0x02000000
};

#define HIL_DO_ALTER_CTRL 0x40000000  
#define HIL_CTRL_ONLY 0xc0000000  

typedef u32 hil_packet;

enum hil_command {
 HIL_CMD_IFC = 0x00,
 HIL_CMD_EPT = 0x01,
 HIL_CMD_ELB = 0x02,
 HIL_CMD_IDD = 0x03,
 HIL_CMD_DSR = 0x04,
 HIL_CMD_PST = 0x05,
 HIL_CMD_RRG = 0x06,
 HIL_CMD_WRG = 0x07,
 HIL_CMD_ACF = 0x08,
 HIL_CMDID_ACF = 0x07,
 HIL_CMD_POL = 0x10,
 HIL_CMDCT_POL = 0x0f,
 HIL_CMD_RPL = 0x20,
 HIL_CMDCT_RPL = 0x0f,
 HIL_CMD_RNM = 0x30,
 HIL_CMD_RST = 0x31,
 HIL_CMD_EXD = 0x32,
 HIL_CMD_RSC = 0x33,

 HIL_CMD_DKA = 0x3d,
 HIL_CMD_EK1 = 0x3e,
 HIL_CMD_EK2 = 0x3f,
 HIL_CMD_PR1 = 0x40,
 HIL_CMD_PR2 = 0x41,
 HIL_CMD_PR3 = 0x42,
 HIL_CMD_PR4 = 0x43,
 HIL_CMD_PR5 = 0x44,
 HIL_CMD_PR6 = 0x45,
 HIL_CMD_PR7 = 0x46,
 HIL_CMD_PRM = 0x47,
 HIL_CMD_AK1 = 0x48,
 HIL_CMD_AK2 = 0x49,
 HIL_CMD_AK3 = 0x4a,
 HIL_CMD_AK4 = 0x4b,
 HIL_CMD_AK5 = 0x4c,
 HIL_CMD_AK6 = 0x4d,
 HIL_CMD_AK7 = 0x4e,
 HIL_CMD_ACK = 0x4f,

 HIL_CMD_RIO = 0xfa,
 HIL_CMD_SHR = 0xfb,
 HIL_CMD_TER = 0xfc,
 HIL_CMD_CAE = 0xfd,
 HIL_CMD_DHR = 0xfe,

};

#define HIL_IDD_DID_TYPE_MASK 0xe0  
#define HIL_IDD_DID_TYPE_KB_INTEGRAL 0xa0  
#define HIL_IDD_DID_TYPE_KB_ITF 0xc0  
#define HIL_IDD_DID_TYPE_KB_RSVD 0xe0  
#define HIL_IDD_DID_TYPE_KB_LANG_MASK 0x1f  
#define HIL_IDD_DID_KBLANG_USE_ESD 0x00  
#define HIL_IDD_DID_TYPE_ABS 0x80  
#define HIL_IDD_DID_ABS_RSVD1_MASK 0xf8  
#define HIL_IDD_DID_ABS_RSVD1 0x98
#define HIL_IDD_DID_ABS_TABLET_MASK 0xf8  
#define HIL_IDD_DID_ABS_TABLET 0x90
#define HIL_IDD_DID_ABS_TSCREEN_MASK 0xfc  
#define HIL_IDD_DID_ABS_TSCREEN 0x8c
#define HIL_IDD_DID_ABS_RSVD2_MASK 0xfc  
#define HIL_IDD_DID_ABS_RSVD2 0x88
#define HIL_IDD_DID_ABS_RSVD3_MASK 0xfc  
#define HIL_IDD_DID_ABS_RSVD3 0x80
#define HIL_IDD_DID_TYPE_REL 0x60  
#define HIL_IDD_DID_REL_RSVD1_MASK 0xf0  
#define HIL_IDD_DID_REL_RSVD1 0x70
#define HIL_IDD_DID_REL_RSVD2_MASK 0xfc  
#define HIL_IDD_DID_REL_RSVD2 0x6c
#define HIL_IDD_DID_REL_MOUSE_MASK 0xfc  
#define HIL_IDD_DID_REL_MOUSE 0x68
#define HIL_IDD_DID_REL_QUAD_MASK 0xf8  
#define HIL_IDD_DID_REL_QUAD 0x60
#define HIL_IDD_DID_TYPE_CHAR 0x40  
#define HIL_IDD_DID_CHAR_BARCODE_MASK 0xfc  
#define HIL_IDD_DID_CHAR_BARCODE 0x5c
#define HIL_IDD_DID_CHAR_RSVD1_MASK 0xfc  
#define HIL_IDD_DID_CHAR_RSVD1 0x58
#define HIL_IDD_DID_CHAR_RSVD2_MASK 0xf8  
#define HIL_IDD_DID_CHAR_RSVD2 0x50
#define HIL_IDD_DID_CHAR_RSVD3_MASK 0xf0  
#define HIL_IDD_DID_CHAR_RSVD3 0x40
#define HIL_IDD_DID_TYPE_OTHER 0x20  
#define HIL_IDD_DID_OTHER_RSVD1_MASK 0xf0  
#define HIL_IDD_DID_OTHER_RSVD1 0x30
#define HIL_IDD_DID_OTHER_BARCODE_MASK 0xfc  
#define HIL_IDD_DID_OTHER_BARCODE 0x2c
#define HIL_IDD_DID_OTHER_RSVD2_MASK 0xfc  
#define HIL_IDD_DID_OTHER_RSVD2 0x28
#define HIL_IDD_DID_OTHER_RSVD3_MASK 0xf8  
#define HIL_IDD_DID_OTHER_RSVD3 0x20
#define HIL_IDD_DID_TYPE_KEYPAD 0x00  

#define HIL_IDD_HEADER_AXSET_MASK 0x03  
#define HIL_IDD_HEADER_RSC 0x04  
#define HIL_IDD_HEADER_EXD 0x08  
#define HIL_IDD_HEADER_IOD 0x10  
#define HIL_IDD_HEADER_16BIT 0x20  
#define HIL_IDD_HEADER_ABS 0x40  
#define HIL_IDD_HEADER_2X_AXIS 0x80  

#define HIL_IDD_IOD_NBUTTON_MASK 0x07  
#define HIL_IDD_IOD_PROXIMITY 0x08  
#define HIL_IDD_IOD_PROMPT_MASK 0x70  
#define HIL_IDD_IOD_PROMPT_SHIFT 4
#define HIL_IDD_IOD_PROMPT 0x80  

#define HIL_IDD_NUM_AXES_PER_SET(header_packet)  ((header_packet) & HIL_IDD_HEADER_AXSET_MASK)

#define HIL_IDD_NUM_AXSETS(header_packet)  (2 - !((header_packet) & HIL_IDD_HEADER_2X_AXIS))

#define HIL_IDD_LEN(header_packet)  ((4 - !(header_packet & HIL_IDD_HEADER_IOD) -   2 * !(HIL_IDD_NUM_AXES_PER_SET(header_packet))) +   2 * HIL_IDD_NUM_AXES_PER_SET(header_packet) *   !!((header_packet) & HIL_IDD_HEADER_ABS))

#define HIL_IDD_AXIS_COUNTS_PER_M(header_ptr)  (!(HIL_IDD_NUM_AXSETS(*(header_ptr))) ? -1 :  (((*(header_ptr + 1) & HIL_PKT_DATA_MASK) +   ((*(header_ptr + 2) & HIL_PKT_DATA_MASK)) << 8)  * ((*(header_ptr) & HIL_IDD_HEADER_16BIT) ? 100 : 1)))

#define HIL_IDD_AXIS_MAX(header_ptr, __axnum)  ((!(*(header_ptr) & HIL_IDD_HEADER_ABS) ||   (HIL_IDD_NUM_AXES_PER_SET(*(header_ptr)) <= __axnum)) ? 0 :   ((HIL_PKT_DATA_MASK & *((header_ptr) + 3 + 2 * __axnum)) +   ((HIL_PKT_DATA_MASK & *((header_ptr) + 4 + 2 * __axnum)) << 8)))

#define HIL_IDD_IOD(header_ptr)  (*(header_ptr + HIL_IDD_LEN((*header_ptr)) - 1))

#define HIL_IDD_HAS_GEN_PROMPT(header_ptr)  ((*header_ptr & HIL_IDD_HEADER_IOD) &&   (HIL_IDD_IOD(header_ptr) & HIL_IDD_IOD_PROMPT))

#define HIL_IDD_HAS_GEN_PROXIMITY(header_ptr)  ((*header_ptr & HIL_IDD_HEADER_IOD) &&   (HIL_IDD_IOD(header_ptr) & HIL_IDD_IOD_PROXIMITY))

#define HIL_IDD_NUM_BUTTONS(header_ptr)  ((*header_ptr & HIL_IDD_HEADER_IOD) ?   (HIL_IDD_IOD(header_ptr) & HIL_IDD_IOD_NBUTTON_MASK) : 0)

#define HIL_IDD_NUM_PROMPTS(header_ptr)  ((*header_ptr & HIL_IDD_HEADER_IOD) ?   ((HIL_IDD_IOD(header_ptr) & HIL_IDD_IOD_NPROMPT_MASK)   >> HIL_IDD_IOD_PROMPT_SHIFT) : 0)

#define HIL_EXD_HEADER_WRG 0x03  
#define HIL_EXD_HEADER_WRG_TYPE1 0x01  
#define HIL_EXD_HEADER_WRG_TYPE2 0x02  
#define HIL_EXD_HEADER_RRG 0x04  
#define HIL_EXD_HEADER_RNM 0x10  
#define HIL_EXD_HEADER_RST 0x20  
#define HIL_EXD_HEADER_LOCALE 0x40  

#define HIL_EXD_NUM_RRG(header_ptr)  ((*header_ptr & HIL_EXD_HEADER_RRG) ?   (*(header_ptr + 1) & HIL_PKT_DATA_MASK) : 0)

#define HIL_EXD_NUM_WWG(header_ptr)  ((*header_ptr & HIL_EXD_HEADER_WRG) ?   (*(header_ptr + 2 - !(*header_ptr & HIL_EXD_HEADER_RRG)) &   HIL_PKT_DATA_MASK) : 0)

#define HIL_EXD_LEN(header_ptr)  (!!(*header_ptr & HIL_EXD_HEADER_RRG) +   !!(*header_ptr & HIL_EXD_HEADER_WRG) +   !!(*header_ptr & HIL_EXD_HEADER_LOCALE) +   2 * !!(*header_ptr & HIL_EXD_HEADER_WRG_TYPE2) + 1)

#define HIL_EXD_LOCALE(header_ptr)  (!(*header_ptr & HIL_EXD_HEADER_LOCALE) ? -1 :   (*(header_ptr + HIL_EXD_LEN(header_ptr) - 1) & HIL_PKT_DATA_MASK))

#define HIL_EXD_WRG_TYPE2_LEN(header_ptr)  (!(*header_ptr & HIL_EXD_HEADER_WRG_TYPE2) ? -1 :   (*(header_ptr + HIL_EXD_LEN(header_ptr) - 2 -   !!(*header_ptr & HIL_EXD_HEADER_LOCALE)) & HIL_PKT_DATA_MASK) +   ((*(header_ptr + HIL_EXD_LEN(header_ptr) - 1 -   !!(*header_ptr & HIL_EXD_HEADER_LOCALE)) & HIL_PKT_DATA_MASK) << 8))

#define HIL_LOCALE_MAX 0x1f

#define HIL_LOCALE_MAP  "",    "",    "",    "swiss.french",    "portuguese",    "arabic",    "hebrew",    "english.canadian",    "turkish",    "greek",    "thai",    "italian",    "korean",    "dutch",    "swedish",    "german",    "chinese",    "chinese",    "swiss.french",    "spanish",    "swiss.german",    "flemish",    "finnish",    "english.uk",    "french.canadian",    "swiss.german",    "norwegian",    "french",    "danish",    "japanese",    "spanish",   "english.us"    

#define HIL_KEYCODES_SET1_TBLSIZE 128
#define HIL_KEYCODES_SET1   KEY_5, KEY_RESERVED, KEY_RIGHTALT, KEY_LEFTALT,   KEY_RIGHTSHIFT, KEY_LEFTSHIFT, KEY_LEFTCTRL, KEY_SYSRQ,   KEY_KP4, KEY_KP8, KEY_KP5, KEY_KP9,   KEY_KP6, KEY_KP7, KEY_KPCOMMA, KEY_KPENTER,   KEY_KP1, KEY_KPSLASH, KEY_KP2, KEY_KPPLUS,   KEY_KP3, KEY_KPASTERISK, KEY_KP0, KEY_KPMINUS,   KEY_B, KEY_V, KEY_C, KEY_X,   KEY_Z, KEY_RESERVED, KEY_RESERVED, KEY_ESC,   KEY_6, KEY_F10, KEY_3, KEY_F11,   KEY_KPDOT, KEY_F9, KEY_TAB  , KEY_F12,   KEY_H, KEY_G, KEY_F, KEY_D,   KEY_S, KEY_A, KEY_RESERVED, KEY_CAPSLOCK,   KEY_U, KEY_Y, KEY_T, KEY_R,   KEY_E, KEY_W, KEY_Q, KEY_TAB,   KEY_7, KEY_6, KEY_5, KEY_4,   KEY_3, KEY_2, KEY_1, KEY_GRAVE,   KEY_F13, KEY_F14, KEY_F15, KEY_F16,   KEY_F17, KEY_F18, KEY_F19, KEY_F20,   KEY_MENU, KEY_F4, KEY_F3, KEY_F2,   KEY_F1, KEY_VOLUMEUP, KEY_STOP, KEY_SENDFILE,   KEY_SYSRQ, KEY_F5, KEY_F6, KEY_F7,   KEY_F8, KEY_VOLUMEDOWN, KEY_DEL_EOL, KEY_DEL_EOS,   KEY_8, KEY_9, KEY_0, KEY_MINUS,   KEY_EQUAL, KEY_BACKSPACE, KEY_INS_LINE, KEY_DEL_LINE,   KEY_I, KEY_O, KEY_P, KEY_LEFTBRACE,   KEY_RIGHTBRACE, KEY_BACKSLASH, KEY_INSERT, KEY_DELETE,   KEY_J, KEY_K, KEY_L, KEY_SEMICOLON,   KEY_APOSTROPHE, KEY_ENTER, KEY_HOME, KEY_PAGEUP,   KEY_M, KEY_COMMA, KEY_DOT, KEY_SLASH,   KEY_BACKSLASH, KEY_SELECT, KEY_102ND, KEY_PAGEDOWN,   KEY_N, KEY_SPACE, KEY_NEXT, KEY_RESERVED,   KEY_LEFT, KEY_DOWN, KEY_UP, KEY_RIGHT

#define HIL_KEYCODES_SET3_TBLSIZE 128
#define HIL_KEYCODES_SET3   KEY_RESERVED, KEY_ESC, KEY_1, KEY_2,   KEY_3, KEY_4, KEY_5, KEY_6,   KEY_7, KEY_8, KEY_9, KEY_0,   KEY_MINUS, KEY_EQUAL, KEY_BACKSPACE, KEY_TAB,   KEY_Q, KEY_W, KEY_E, KEY_R,   KEY_T, KEY_Y, KEY_U, KEY_I,   KEY_O, KEY_P, KEY_LEFTBRACE, KEY_RIGHTBRACE,   KEY_ENTER, KEY_LEFTCTRL, KEY_A, KEY_S,   KEY_D, KEY_F, KEY_G, KEY_H,   KEY_J, KEY_K, KEY_L, KEY_SEMICOLON,   KEY_APOSTROPHE,KEY_GRAVE, KEY_LEFTSHIFT, KEY_BACKSLASH,   KEY_Z, KEY_X, KEY_C, KEY_V,   KEY_B, KEY_N, KEY_M, KEY_COMMA,   KEY_DOT, KEY_SLASH, KEY_RIGHTSHIFT, KEY_KPASTERISK,   KEY_LEFTALT, KEY_SPACE, KEY_CAPSLOCK, KEY_F1,   KEY_F2, KEY_F3, KEY_F4, KEY_F5,   KEY_F6, KEY_F7, KEY_F8, KEY_F9,   KEY_F10, KEY_NUMLOCK, KEY_SCROLLLOCK, KEY_KP7,   KEY_KP8, KEY_KP9, KEY_KPMINUS, KEY_KP4,   KEY_KP5, KEY_KP6, KEY_KPPLUS, KEY_KP1,   KEY_KP2, KEY_KP3, KEY_KP0, KEY_KPDOT,   KEY_SYSRQ, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED,   KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED,   KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED,   KEY_UP, KEY_LEFT, KEY_DOWN, KEY_RIGHT,   KEY_HOME, KEY_PAGEUP, KEY_END, KEY_PAGEDOWN,   KEY_INSERT, KEY_DELETE, KEY_102ND, KEY_RESERVED,   KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED,   KEY_F1, KEY_F2, KEY_F3, KEY_F4,   KEY_F5, KEY_F6, KEY_F7, KEY_F8,   KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED,   KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED

#define HIL_POL_NUM_AXES_MASK 0x03  
#define HIL_POL_CTS 0x04  
#define HIL_POL_STATUS_PENDING 0x08  
#define HIL_POL_CHARTYPE_MASK 0x70  
#define HIL_POL_CHARTYPE_NONE 0x00  
#define HIL_POL_CHARTYPE_RSVD1 0x10  
#define HIL_POL_CHARTYPE_ASCII 0x20  
#define HIL_POL_CHARTYPE_BINARY 0x30  
#define HIL_POL_CHARTYPE_SET1 0x40  
#define HIL_POL_CHARTYPE_RSVD2 0x50  
#define HIL_POL_CHARTYPE_SET2 0x60  
#define HIL_POL_CHARTYPE_SET3 0x70  
#define HIL_POL_AXIS_ALT 0x80  

#endif
