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
#ifndef _QIC117_H
#define _QIC117_H

typedef enum {
 QIC_NO_COMMAND = 0,
 QIC_RESET = 1,
 QIC_REPORT_NEXT_BIT = 2,
 QIC_PAUSE = 3,
 QIC_MICRO_STEP_PAUSE = 4,
 QIC_ALTERNATE_TIMEOUT = 5,
 QIC_REPORT_DRIVE_STATUS = 6,
 QIC_REPORT_ERROR_CODE = 7,
 QIC_REPORT_DRIVE_CONFIGURATION = 8,
 QIC_REPORT_ROM_VERSION = 9,
 QIC_LOGICAL_FORWARD = 10,
 QIC_PHYSICAL_REVERSE = 11,
 QIC_PHYSICAL_FORWARD = 12,
 QIC_SEEK_HEAD_TO_TRACK = 13,
 QIC_SEEK_LOAD_POINT = 14,
 QIC_ENTER_FORMAT_MODE = 15,
 QIC_WRITE_REFERENCE_BURST = 16,
 QIC_ENTER_VERIFY_MODE = 17,
 QIC_STOP_TAPE = 18,

 QIC_MICRO_STEP_HEAD_UP = 21,
 QIC_MICRO_STEP_HEAD_DOWN = 22,
 QIC_SOFT_SELECT = 23,
 QIC_SOFT_DESELECT = 24,
 QIC_SKIP_REVERSE = 25,
 QIC_SKIP_FORWARD = 26,
 QIC_SELECT_RATE = 27,

 QIC_ENTER_DIAGNOSTIC_1 = 28,
 QIC_ENTER_DIAGNOSTIC_2 = 29,
 QIC_ENTER_PRIMARY_MODE = 30,

 QIC_REPORT_VENDOR_ID = 32,
 QIC_REPORT_TAPE_STATUS = 33,
 QIC_SKIP_EXTENDED_REVERSE = 34,
 QIC_SKIP_EXTENDED_FORWARD = 35,
 QIC_CALIBRATE_TAPE_LENGTH = 36,
 QIC_REPORT_FORMAT_SEGMENTS = 37,
 QIC_SET_FORMAT_SEGMENTS = 38,

 QIC_PHANTOM_SELECT = 46,
 QIC_PHANTOM_DESELECT = 47
} qic117_cmd_t;

typedef enum {
 discretional = 0, required, ccs1, ccs2
} qic_compatibility;

typedef enum {
 unused, mode, motion, report
} command_types;

struct qic117_command_table {
 char *name;
 __u8 mask;
 __u8 state;
 __u8 cmd_type;
 __u8 non_intr;
 __u8 level;
};

#define QIC117_COMMANDS {         {NULL, 0x00, 0x00, mode, 0, discretional},   {"soft reset", 0x00, 0x00, motion, 1, required},   {"report next bit", 0x00, 0x00, report, 0, required},   {"pause", 0x36, 0x24, motion, 1, required},   {"micro step pause", 0x36, 0x24, motion, 1, required},   {"alternate command timeout", 0x00, 0x00, mode, 0, required},   {"report drive status", 0x00, 0x00, report, 0, required},   {"report error code", 0x01, 0x01, report, 0, required},   {"report drive configuration",0x00, 0x00, report, 0, required},   {"report rom version", 0x00, 0x00, report, 0, required},   {"logical forward", 0x37, 0x25, motion, 0, required},   {"physical reverse", 0x17, 0x05, motion, 0, required},   {"physical forward", 0x17, 0x05, motion, 0, required},   {"seek head to track", 0x37, 0x25, motion, 0, required},   {"seek load point", 0x17, 0x05, motion, 1, required},   {"enter format mode", 0x1f, 0x05, mode, 0, required},   {"write reference burst", 0x1f, 0x05, motion, 1, required},   {"enter verify mode", 0x37, 0x25, mode, 0, required},   {"stop tape", 0x00, 0x00, motion, 1, required},   {"reserved (19)", 0x00, 0x00, unused, 0, discretional},   {"reserved (20)", 0x00, 0x00, unused, 0, discretional},   {"micro step head up", 0x02, 0x00, motion, 0, required},   {"micro step head down", 0x02, 0x00, motion, 0, required},   {"soft select", 0x00, 0x00, mode, 0, discretional},   {"soft deselect", 0x00, 0x00, mode, 0, discretional},   {"skip segments reverse", 0x36, 0x24, motion, 1, required},   {"skip segments forward", 0x36, 0x24, motion, 1, required},   {"select rate or format", 0x03, 0x01, mode, 0, required  },   {"enter diag mode 1", 0x00, 0x00, mode, 0, discretional},   {"enter diag mode 2", 0x00, 0x00, mode, 0, discretional},   {"enter primary mode", 0x00, 0x00, mode, 0, required},   {"vendor unique (31)", 0x00, 0x00, unused, 0, discretional},   {"report vendor id", 0x00, 0x00, report, 0, required},   {"report tape status", 0x04, 0x04, report, 0, ccs1},   {"skip extended reverse", 0x36, 0x24, motion, 1, ccs1},   {"skip extended forward", 0x36, 0x24, motion, 1, ccs1},   {"calibrate tape length", 0x17, 0x05, motion, 1, ccs2},   {"report format segments", 0x17, 0x05, report, 0, ccs2},   {"set format segments", 0x17, 0x05, mode, 0, ccs2},   {"reserved (39)", 0x00, 0x00, unused, 0, discretional},   {"vendor unique (40)", 0x00, 0x00, unused, 0, discretional},   {"vendor unique (41)", 0x00, 0x00, unused, 0, discretional},   {"vendor unique (42)", 0x00, 0x00, unused, 0, discretional},   {"vendor unique (43)", 0x00, 0x00, unused, 0, discretional},   {"vendor unique (44)", 0x00, 0x00, unused, 0, discretional},   {"vendor unique (45)", 0x00, 0x00, unused, 0, discretional},   {"phantom select", 0x00, 0x00, mode, 0, discretional},   {"phantom deselect", 0x00, 0x00, mode, 0, discretional}, }

#define QIC_STATUS_READY 0x01  
#define QIC_STATUS_ERROR 0x02  
#define QIC_STATUS_CARTRIDGE_PRESENT 0x04  
#define QIC_STATUS_WRITE_PROTECT 0x08  
#define QIC_STATUS_NEW_CARTRIDGE 0x10  
#define QIC_STATUS_REFERENCED 0x20  
#define QIC_STATUS_AT_BOT 0x40  
#define QIC_STATUS_AT_EOT 0x80  

#define QIC_CONFIG_RATE_MASK 0x18
#define QIC_CONFIG_RATE_SHIFT 3
#define QIC_CONFIG_RATE_250 0
#define QIC_CONFIG_RATE_500 2
#define QIC_CONFIG_RATE_1000 3
#define QIC_CONFIG_RATE_2000 1
#define QIC_CONFIG_RATE_4000 0  

#define QIC_CONFIG_LONG 0x40  
#define QIC_CONFIG_80 0x80  

#define QIC_TAPE_STD_MASK 0x0f
#define QIC_TAPE_QIC40 0x01
#define QIC_TAPE_QIC80 0x02
#define QIC_TAPE_QIC3020 0x03
#define QIC_TAPE_QIC3010 0x04

#define QIC_TAPE_LEN_MASK 0x70
#define QIC_TAPE_205FT 0x10
#define QIC_TAPE_307FT 0x20
#define QIC_TAPE_VARIABLE 0x30
#define QIC_TAPE_1100FT 0x40
#define QIC_TAPE_FLEX 0x60

#define QIC_TAPE_WIDE 0x80

#define QIC_TOP_TAPE_LEN 1500

typedef struct {
 char *message;
 unsigned int fatal:1;
} ftape_error;

#define QIC117_ERRORS {    { "No error", 0, },    { "Command Received while Drive Not Ready", 0, },    { "Cartridge Not Present or Removed", 1, },    { "Motor Speed Error (not within 1%)", 1, },    { "Motor Speed Fault (jammed, or gross speed error", 1, },    { "Cartridge Write Protected", 1, },    { "Undefined or Reserved Command Code", 1, },    { "Illegal Track Address Specified for Seek", 1, },    { "Illegal Command in Report Subcontext", 0, },    { "Illegal Entry into a Diagnostic Mode", 1, },    { "Broken Tape Detected (based on hole sensor)", 1, },    { "Warning--Read Gain Setting Error", 1, },    { "Command Received While Error Status Pending (obs)", 1, },    { "Command Received While New Cartridge Pending", 1, },    { "Command Illegal or Undefined in Primary Mode", 1, },    { "Command Illegal or Undefined in Format Mode", 1, },    { "Command Illegal or Undefined in Verify Mode", 1, },    { "Logical Forward Not at Logical BOT or no Format Segments in Format Mode", 1, },    { "Logical EOT Before All Segments generated", 1, },    { "Command Illegal When Cartridge Not Referenced", 1, },    { "Self-Diagnostic Failed (cannot be cleared)", 1, },    { "Warning EEPROM Not Initialized, Defaults Set", 1, },    { "EEPROM Corrupted or Hardware Failure", 1, },    { "Motion Time-out Error", 1, },    { "Data Segment Too Long -- Logical Forward or Pause", 1, },    { "Transmit Overrun (obs)", 1, },    { "Power On Reset Occurred", 0, },    { "Software Reset Occurred", 0, },    { "Diagnostic Mode 1 Error", 1, },    { "Diagnostic Mode 2 Error", 1, },    { "Command Received During Non-Interruptible Process", 1, },    { "Rate or Format Selection Error", 1, },    { "Illegal Command While in High Speed Mode", 1, },    { "Illegal Seek Segment Value", 1, },    { "Invalid Media", 1, },    { "Head Positioning Failure", 1, },    { "Write Reference Burst Failure", 1, },    { "Prom Code Missing", 1, },    { "Invalid Format", 1, },    { "EOT/BOT System Failure", 1, },    { "Prom A Checksum Error", 1, },    { "Drive Wakeup Reset Occurred", 1, },    { "Prom B Checksum Error", 1, },    { "Illegal Entry into Format Mode", 1, }, }

#endif
