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
#undef VOYAGER_DEBUG
#undef VOYAGER_CAT_DEBUG

#ifdef VOYAGER_DEBUG
#define VDEBUG(x) printk x
#else
#define VDEBUG(x)
#endif

#define VOYAGER_LEVEL5_AND_ABOVE 0x3435
#define VOYAGER_LEVEL4 0x3360

#define VOYAGER_DINO 0x43

#define VOYAGER_MC_SETUP 0x96

#define VOYAGER_CAT_CONFIG_PORT 0x97
#define VOYAGER_CAT_DESELECT 0xff
#define VOYAGER_SSPB_RELOCATION_PORT 0x98

#define VOYAGER_CAT_IRCYC 0x01

#define VOYAGER_CAT_DRCYC 0x02

#define VOYAGER_CAT_RUN 0x0F

#define VOYAGER_CAT_END 0x80

#define VOYAGER_CAT_HOLD 0x90

#define VOYAGER_CAT_STEP 0xE0

#define VOYAGER_CAT_CLEMSON 0xFF

#define VOYAGER_CAT_HEADER 0x7F

#define VOYAGER_MIN_MODULE 0x10
#define VOYAGER_MAX_MODULE 0x1f

#define VOYAGER_ASIC_ID_REG 0x00
#define VOYAGER_ASIC_TYPE_REG 0x01

#define VOYAGER_AUTO_INC_REG 0x02
#define VOYAGER_AUTO_INC 0x04
#define VOYAGER_NO_AUTO_INC 0xfb
#define VOYAGER_SUBADDRDATA 0x03
#define VOYAGER_SCANPATH 0x05
#define VOYAGER_CONNECT_ASIC 0x01
#define VOYAGER_DISCONNECT_ASIC 0xfe
#define VOYAGER_SUBADDRLO 0x06
#define VOYAGER_SUBADDRHI 0x07
#define VOYAGER_SUBMODSELECT 0x08
#define VOYAGER_SUBMODPRESENT 0x09

#define VOYAGER_SUBADDR_LO 0xff
#define VOYAGER_SUBADDR_HI 0xffff

#define VOYAGER_MAX_SCAN_PATH 0x100

#define VOYAGER_MAX_REG_SIZE 4

#define VOYAGER_MAX_MODULES 16

#define VOYAGER_MAX_ASICS_PER_MODULE 7

#define VOYAGER_CAT_ID 0
#define VOYAGER_PSI 0x1a

#define VOYAGER_READ_CONFIG 0x1
#define VOYAGER_WRITE_CONFIG 0x2
#define VOYAGER_BYPASS 0xff

typedef struct voyager_asic
{
 __u8 asic_addr;
 __u8 asic_type;
 __u8 asic_id;
 __u8 jtag_id[4];
 __u8 asic_location;
 __u8 bit_location;
 __u8 ireg_length;
 __u16 subaddr;
 struct voyager_asic *next;
} voyager_asic_t;

typedef struct voyager_module {
 __u8 module_addr;
 __u8 scan_path_connected;
 __u16 ee_size;
 __u16 num_asics;
 __u16 inst_bits;
 __u16 largest_reg;
 __u16 smallest_reg;
 voyager_asic_t *asic;
 struct voyager_module *submodule;
 struct voyager_module *next;
} voyager_module_t;

typedef struct voyager_eeprom_hdr {
 __u8 module_id[4];
 __u8 version_id;
 __u8 config_id;
 __u16 boundry_id;
 __u16 ee_size;
 __u8 assembly[11];
 __u8 assembly_rev;
 __u8 tracer[4];
 __u16 assembly_cksum;
 __u16 power_consump;
 __u16 num_asics;
 __u16 bist_time;
 __u16 err_log_offset;
 __u16 scan_path_offset;
 __u16 cct_offset;
 __u16 log_length;
 __u16 xsum_end;
 __u8 reserved[4];
 __u8 sflag;
 __u8 part_number[13];
 __u8 version[10];
 __u8 signature[8];
 __u16 eeprom_chksum;
 __u32 data_stamp_offset;
 __u8 eflag ;
} __attribute__((packed)) voyager_eprom_hdr_t;

#define VOYAGER_EPROM_SIZE_OFFSET ((__u16)(&(((voyager_eprom_hdr_t *)0)->ee_size)))
#define VOYAGER_XSUM_END_OFFSET 0x2a

typedef struct voyager_sp_table {
 __u8 asic_id;
 __u8 bypass_flag;
 __u16 asic_data_offset;
 __u16 config_data_offset;
} __attribute__((packed)) voyager_sp_table_t;

typedef struct voyager_jtag_table {
 __u8 icode[4];
 __u8 runbist[4];
 __u8 intest[4];
 __u8 samp_preld[4];
 __u8 ireg_len;
} __attribute__((packed)) voyager_jtt_t;

typedef struct voyager_asic_data_table {
 __u8 jtag_id[4];
 __u16 length_bsr;
 __u16 length_bist_reg;
 __u32 bist_clk;
 __u16 subaddr_bits;
 __u16 seed_bits;
 __u16 sig_bits;
 __u16 jtag_offset;
} __attribute__((packed)) voyager_at_t;

#define VOYAGER_WCBIC0 0x41  
#define VOYAGER_WCBIC1 0x49  
#define VOYAGER_WCBIC2 0x51  
#define VOYAGER_WCBIC3 0x59  
#define VOYAGER_WCBIC4 0x61  
#define VOYAGER_WCBIC5 0x69  
#define VOYAGER_WCBIC6 0x71  
#define VOYAGER_WCBIC7 0x79  

#define VOYAGER_WCBIC_TOM_L 0x4
#define VOYAGER_WCBIC_TOM_H 0x5

#define VOYAGER_VMC1 0x81
#define VOYAGER_VMC2 0x91
#define VOYAGER_VMC3 0xa1
#define VOYAGER_VMC4 0xb1

#define VOYAGER_VMC_MEMORY_SETUP 0x9
#define VMC_Interleaving 0x01
#define VMC_4Way 0x02
#define VMC_EvenCacheLines 0x04
#define VMC_HighLine 0x08
#define VMC_Start0_Enable 0x20
#define VMC_Start1_Enable 0x40
#define VMC_Vremap 0x80
#define VOYAGER_VMC_BANK_DENSITY 0xa
#define VMC_BANK_EMPTY 0
#define VMC_BANK_4MB 1
#define VMC_BANK_16MB 2
#define VMC_BANK_64MB 3
#define VMC_BANK0_MASK 0x03
#define VMC_BANK1_MASK 0x0C
#define VMC_BANK2_MASK 0x30
#define VMC_BANK3_MASK 0xC0

#define VOYAGER_MMC_ASIC_ID 1

#define VOYAGER_MMC_MEMORY0_MODULE 0x14
#define VOYAGER_MMC_MEMORY1_MODULE 0x15

#define VOYAGER_MMA_ASIC_ID 2

#define VOYAGER_QUAD_BASEBOARD 1

#define VOYAGER_QUAD_QDATA0 1
#define VOYAGER_QUAD_QDATA1 2
#define VOYAGER_QUAD_QABC 3

#define VOYAGER_PROCESSOR_PRESENT_MASK 0x88a
#define VOYAGER_MEMORY_CLICKMAP 0xa23
#define VOYAGER_DUMP_LOCATION 0xb1a

#define VOYAGER_SUS_IN_CONTROL_PORT 0x3ff
#define VOYAGER_IN_CONTROL_FLAG 0x80

#define VOYAGER_PSI_STATUS_REG 0x08
#define PSI_DC_FAIL 0x01
#define PSI_MON 0x02
#define PSI_FAULT 0x04
#define PSI_ALARM 0x08
#define PSI_CURRENT 0x10
#define PSI_DVM 0x20
#define PSI_PSCFAULT 0x40
#define PSI_STAT_CHG 0x80

#define VOYAGER_PSI_SUPPLY_REG 0x8000

#define PSI_FAIL_DC 0x01
#define PSI_FAIL_AC 0x02
#define PSI_MON_INT 0x04
#define PSI_SWITCH_OFF 0x08
#define PSI_HX_OFF 0x10
#define PSI_SECURITY 0x20
#define PSI_CMOS_BATT_LOW 0x40
#define PSI_CMOS_BATT_FAIL 0x80

#define PSI_CLR_SWITCH_OFF 0x13
#define PSI_CLR_HX_OFF 0x14
#define PSI_CLR_CMOS_BATT_FAIL 0x17

#define VOYAGER_PSI_MASK 0x8001
#define PSI_MASK_MASK 0x10

#define VOYAGER_PSI_AC_FAIL_REG 0x8004
#define AC_FAIL_STAT_CHANGE 0x80

#define VOYAGER_PSI_GENERAL_REG 0x8007

#define PSI_SWITCH_ON 0x01
#define PSI_SWITCH_ENABLED 0x02
#define PSI_ALARM_ENABLED 0x08
#define PSI_SECURE_ENABLED 0x10
#define PSI_COLD_RESET 0x20
#define PSI_COLD_START 0x80

#define PSI_POWER_DOWN 0x10
#define PSI_SWITCH_DISABLE 0x01
#define PSI_SWITCH_ENABLE 0x11
#define PSI_CLEAR 0x12
#define PSI_ALARM_DISABLE 0x03
#define PSI_ALARM_ENABLE 0x13
#define PSI_CLEAR_COLD_RESET 0x05
#define PSI_SET_COLD_RESET 0x15
#define PSI_CLEAR_COLD_START 0x07
#define PSI_SET_COLD_START 0x17

struct voyager_bios_info {
 __u8 len;
 __u8 major;
 __u8 minor;
 __u8 debug;
 __u8 num_classes;
 __u8 class_1;
 __u8 class_2;
};

#define NUMBER_OF_MC_BUSSES 2
#define SLOTS_PER_MC_BUS 8
#define MAX_CPUS 16  
#define MAX_PROCESSOR_BOARDS 4  
#define MAX_CACHE_LEVELS 4  
#define MAX_SHARED_CPUS 4  
#define NUMBER_OF_POS_REGS 8

typedef struct {
 __u8 MC_Slot;
 __u8 POS_Values[NUMBER_OF_POS_REGS];
} __attribute__((packed)) MC_SlotInformation_t;

struct QuadDescription {
 __u8 Type;
 __u8 StructureVersion;
 __u32 CPI_BaseAddress;
 __u32 LARC_BankSize;
 __u32 LocalMemoryStateBits;
 __u8 Slot;
} __attribute__((packed));

struct ProcBoardInfo {
 __u8 Type;
 __u8 StructureVersion;
 __u8 NumberOfBoards;
 struct QuadDescription QuadData[MAX_PROCESSOR_BOARDS];
} __attribute__((packed));

struct CacheDescription {
 __u8 Level;
 __u32 TotalSize;
 __u16 LineSize;
 __u8 Associativity;
 __u8 CacheType;
 __u8 WriteType;
 __u8 Number_CPUs_SharedBy;
 __u8 Shared_CPUs_Hardware_IDs[MAX_SHARED_CPUS];

} __attribute__((packed));

struct CPU_Description {
 __u8 CPU_HardwareId;
 char *FRU_String;
 __u8 NumberOfCacheLevels;
 struct CacheDescription CacheLevelData[MAX_CACHE_LEVELS];
} __attribute__((packed));

struct CPU_Info {
 __u8 Type;
 __u8 StructureVersion;
 __u8 NumberOf_CPUs;
 struct CPU_Description CPU_Data[MAX_CPUS];
} __attribute__((packed));

typedef struct {
 __u8 Mailbox_SUS;
 __u8 Mailbox_OS;
 __u8 SUS_MailboxVersion;
 __u8 OS_MailboxVersion;
 __u32 OS_Flags;
 __u32 SUS_Flags;
 __u32 WatchDogPeriod;
 __u32 WatchDogCount;
 __u32 MemoryFor_SUS_ErrorLog;
 MC_SlotInformation_t MC_SlotInfo[NUMBER_OF_MC_BUSSES*SLOTS_PER_MC_BUS];

 struct ProcBoardInfo *BoardData;
 struct CPU_Info *CPU_Data;

} Voyager_KernelSUS_Mbox_t;

struct voyager_qic_cpi {

 struct {
 __u32 pad1[3];
 __u32 cpi;
 __u32 pad2[4];
 } qic_cpi[8];
};

struct voyager_status {
 __u32 power_fail:1;
 __u32 switch_off:1;
 __u32 request_from_kernel:1;
};

struct voyager_psi_regs {
 __u8 cat_id;
 __u8 cat_dev;
 __u8 cat_control;
 __u8 subaddr;
 __u8 dummy4;
 __u8 checkbit;
 __u8 subaddr_low;
 __u8 subaddr_high;
 __u8 intstatus;
 __u8 stat1;
 __u8 stat3;
 __u8 fault;
 __u8 tms;
 __u8 gen;
 __u8 sysconf;
 __u8 dummy15;
};

struct voyager_psi_subregs {
 __u8 supply;
 __u8 mask;
 __u8 present;
 __u8 DCfail;
 __u8 ACfail;
 __u8 fail;
 __u8 UPSfail;
 __u8 genstatus;
};

struct voyager_psi {
 struct voyager_psi_regs regs;
 struct voyager_psi_subregs subregs;
};

struct voyager_SUS {
#define VOYAGER_DUMP_BUTTON_NMI 0x1
#define VOYAGER_SUS_VALID 0x2
#define VOYAGER_SYSINT_COMPLETE 0x3
 __u8 SUS_mbox;
#define VOYAGER_NO_COMMAND 0x0
#define VOYAGER_IGNORE_DUMP 0x1
#define VOYAGER_DO_DUMP 0x2
#define VOYAGER_SYSINT_HANDSHAKE 0x3
#define VOYAGER_DO_MEM_DUMP 0x4
#define VOYAGER_SYSINT_WAS_RECOVERED 0x5
 __u8 kernel_mbox;
#define VOYAGER_MAILBOX_VERSION 0x10
 __u8 SUS_version;
 __u8 kernel_version;
#define VOYAGER_OS_HAS_SYSINT 0x1
#define VOYAGER_OS_IN_PROGRESS 0x2
#define VOYAGER_UPDATING_WDPERIOD 0x4
 __u32 kernel_flags;
#define VOYAGER_SUS_BOOTING 0x1
#define VOYAGER_SUS_IN_PROGRESS 0x2
 __u32 SUS_flags;
 __u32 watchdog_period;
 __u32 watchdog_count;
 __u32 SUS_errorlog;

};

#define VOYAGER_PSI_READ 0
#define VOYAGER_PSI_WRITE 1
#define VOYAGER_PSI_SUBREAD 2
#define VOYAGER_PSI_SUBWRITE 3

