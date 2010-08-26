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
#ifndef _LINUX_HDSMART_H
#define _LINUX_HDSMART_H

#define OFFLINE_FULL_SCAN 0
#define SHORT_SELF_TEST 1
#define EXTEND_SELF_TEST 2
#define SHORT_CAPTIVE_SELF_TEST 129
#define EXTEND_CAPTIVE_SELF_TEST 130

typedef struct ata_smart_attribute_s {
 unsigned char id;
 unsigned short status_flag;
 unsigned char normalized;
 unsigned char worse_normal;
 unsigned char raw[6];
 unsigned char reserv;
} __attribute__ ((packed)) ata_smart_attribute_t;

typedef struct ata_smart_values_s {
 unsigned short revnumber;
 ata_smart_attribute_t vendor_attributes [30];
 unsigned char offline_data_collection_status;
 unsigned char self_test_exec_status;
 unsigned short total_time_to_complete_off_line;
 unsigned char vendor_specific_366;
 unsigned char offline_data_collection_capability;
 unsigned short smart_capability;
 unsigned char errorlog_capability;
 unsigned char vendor_specific_371;
 unsigned char short_test_completion_time;
 unsigned char extend_test_completion_time;
 unsigned char reserved_374_385 [12];
 unsigned char vendor_specific_386_509 [125];
 unsigned char chksum;
} __attribute__ ((packed)) ata_smart_values_t;

typedef struct ata_smart_threshold_entry_s {
 unsigned char id;
 unsigned char normalized_threshold;
 unsigned char reserved[10];
} __attribute__ ((packed)) ata_smart_threshold_entry_t;

typedef struct ata_smart_thresholds_s {
 unsigned short revnumber;
 ata_smart_threshold_entry_t thres_entries[30];
 unsigned char reserved[149];
 unsigned char chksum;
} __attribute__ ((packed)) ata_smart_thresholds_t;

typedef struct ata_smart_errorlog_command_struct_s {
 unsigned char devicecontrolreg;
 unsigned char featuresreg;
 unsigned char sector_count;
 unsigned char sector_number;
 unsigned char cylinder_low;
 unsigned char cylinder_high;
 unsigned char drive_head;
 unsigned char commandreg;
 unsigned int timestamp;
} __attribute__ ((packed)) ata_smart_errorlog_command_struct_t;

typedef struct ata_smart_errorlog_error_struct_s {
 unsigned char error_condition;
 unsigned char extended_error[14];
 unsigned char state;
 unsigned short timestamp;
} __attribute__ ((packed)) ata_smart_errorlog_error_struct_t;

typedef struct ata_smart_errorlog_struct_s {
 ata_smart_errorlog_command_struct_t commands[6];
 ata_smart_errorlog_error_struct_t error_struct;
} __attribute__ ((packed)) ata_smart_errorlog_struct_t;

typedef struct ata_smart_errorlog_s {
 unsigned char revnumber;
 unsigned char error_log_pointer;
 ata_smart_errorlog_struct_t errorlog_struct[5];
 unsigned short ata_error_count;
 unsigned short non_fatal_count;
 unsigned short drive_timeout_count;
 unsigned char reserved[53];
 unsigned char chksum;
} __attribute__ ((packed)) ata_smart_errorlog_t;

typedef struct ata_smart_selftestlog_struct_s {
 unsigned char selftestnumber;
 unsigned char selfteststatus;
 unsigned short timestamp;
 unsigned char selftestfailurecheckpoint;
 unsigned int lbafirstfailure;
 unsigned char vendorspecific[15];
} __attribute__ ((packed)) ata_smart_selftestlog_struct_t;

typedef struct ata_smart_selftestlog_s {
 unsigned short revnumber;
 ata_smart_selftestlog_struct_t selftest_struct[21];
 unsigned char vendorspecific[2];
 unsigned char mostrecenttest;
 unsigned char resevered[2];
 unsigned char chksum;
} __attribute__ ((packed)) ata_smart_selftestlog_t;

#endif
