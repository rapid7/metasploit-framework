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
#ifndef __LINUX_ATA_H__
#define __LINUX_ATA_H__

#include <linux/types.h>

#define ATA_DMA_BOUNDARY 0xffffUL
#define ATA_DMA_MASK 0xffffffffULL

enum {

 ATA_MAX_DEVICES = 2,
 ATA_MAX_PRD = 256,
 ATA_SECT_SIZE = 512,

 ATA_ID_WORDS = 256,
 ATA_ID_SERNO_OFS = 10,
 ATA_ID_FW_REV_OFS = 23,
 ATA_ID_PROD_OFS = 27,
 ATA_ID_OLD_PIO_MODES = 51,
 ATA_ID_FIELD_VALID = 53,
 ATA_ID_MWDMA_MODES = 63,
 ATA_ID_PIO_MODES = 64,
 ATA_ID_EIDE_DMA_MIN = 65,
 ATA_ID_EIDE_PIO = 67,
 ATA_ID_EIDE_PIO_IORDY = 68,
 ATA_ID_UDMA_MODES = 88,
 ATA_ID_MAJOR_VER = 80,
 ATA_ID_PIO4 = (1 << 1),

 ATA_PCI_CTL_OFS = 2,
 ATA_SERNO_LEN = 20,
 ATA_UDMA0 = (1 << 0),
 ATA_UDMA1 = ATA_UDMA0 | (1 << 1),
 ATA_UDMA2 = ATA_UDMA1 | (1 << 2),
 ATA_UDMA3 = ATA_UDMA2 | (1 << 3),
 ATA_UDMA4 = ATA_UDMA3 | (1 << 4),
 ATA_UDMA5 = ATA_UDMA4 | (1 << 5),
 ATA_UDMA6 = ATA_UDMA5 | (1 << 6),
 ATA_UDMA7 = ATA_UDMA6 | (1 << 7),

 ATA_UDMA_MASK_40C = ATA_UDMA2,

 ATA_PRD_SZ = 8,
 ATA_PRD_TBL_SZ = (ATA_MAX_PRD * ATA_PRD_SZ),
 ATA_PRD_EOT = (1 << 31),

 ATA_DMA_TABLE_OFS = 4,
 ATA_DMA_STATUS = 2,
 ATA_DMA_CMD = 0,
 ATA_DMA_WR = (1 << 3),
 ATA_DMA_START = (1 << 0),
 ATA_DMA_INTR = (1 << 2),
 ATA_DMA_ERR = (1 << 1),
 ATA_DMA_ACTIVE = (1 << 0),

 ATA_HOB = (1 << 7),
 ATA_NIEN = (1 << 1),
 ATA_LBA = (1 << 6),
 ATA_DEV1 = (1 << 4),
 ATA_DEVICE_OBS = (1 << 7) | (1 << 5),
 ATA_DEVCTL_OBS = (1 << 3),
 ATA_BUSY = (1 << 7),
 ATA_DRDY = (1 << 6),
 ATA_DF = (1 << 5),
 ATA_DRQ = (1 << 3),
 ATA_ERR = (1 << 0),
 ATA_SRST = (1 << 2),
 ATA_ICRC = (1 << 7),
 ATA_UNC = (1 << 6),
 ATA_IDNF = (1 << 4),
 ATA_ABORTED = (1 << 2),

 ATA_REG_DATA = 0x00,
 ATA_REG_ERR = 0x01,
 ATA_REG_NSECT = 0x02,
 ATA_REG_LBAL = 0x03,
 ATA_REG_LBAM = 0x04,
 ATA_REG_LBAH = 0x05,
 ATA_REG_DEVICE = 0x06,
 ATA_REG_STATUS = 0x07,

 ATA_REG_FEATURE = ATA_REG_ERR,
 ATA_REG_CMD = ATA_REG_STATUS,
 ATA_REG_BYTEL = ATA_REG_LBAM,
 ATA_REG_BYTEH = ATA_REG_LBAH,
 ATA_REG_DEVSEL = ATA_REG_DEVICE,
 ATA_REG_IRQ = ATA_REG_NSECT,

 ATA_CMD_CHK_POWER = 0xE5,
 ATA_CMD_STANDBY = 0xE2,
 ATA_CMD_IDLE = 0xE3,
 ATA_CMD_EDD = 0x90,
 ATA_CMD_FLUSH = 0xE7,
 ATA_CMD_FLUSH_EXT = 0xEA,
 ATA_CMD_ID_ATA = 0xEC,
 ATA_CMD_ID_ATAPI = 0xA1,
 ATA_CMD_READ = 0xC8,
 ATA_CMD_READ_EXT = 0x25,
 ATA_CMD_WRITE = 0xCA,
 ATA_CMD_WRITE_EXT = 0x35,
 ATA_CMD_WRITE_FUA_EXT = 0x3D,
 ATA_CMD_FPDMA_READ = 0x60,
 ATA_CMD_FPDMA_WRITE = 0x61,
 ATA_CMD_PIO_READ = 0x20,
 ATA_CMD_PIO_READ_EXT = 0x24,
 ATA_CMD_PIO_WRITE = 0x30,
 ATA_CMD_PIO_WRITE_EXT = 0x34,
 ATA_CMD_READ_MULTI = 0xC4,
 ATA_CMD_READ_MULTI_EXT = 0x29,
 ATA_CMD_WRITE_MULTI = 0xC5,
 ATA_CMD_WRITE_MULTI_EXT = 0x39,
 ATA_CMD_WRITE_MULTI_FUA_EXT = 0xCE,
 ATA_CMD_SET_FEATURES = 0xEF,
 ATA_CMD_PACKET = 0xA0,
 ATA_CMD_VERIFY = 0x40,
 ATA_CMD_VERIFY_EXT = 0x42,
 ATA_CMD_STANDBYNOW1 = 0xE0,
 ATA_CMD_IDLEIMMEDIATE = 0xE1,
 ATA_CMD_INIT_DEV_PARAMS = 0x91,
 ATA_CMD_READ_NATIVE_MAX = 0xF8,
 ATA_CMD_READ_NATIVE_MAX_EXT = 0x27,
 ATA_CMD_READ_LOG_EXT = 0x2f,

 ATA_LOG_SATA_NCQ = 0x10,

 SETFEATURES_XFER = 0x03,
 XFER_UDMA_7 = 0x47,
 XFER_UDMA_6 = 0x46,
 XFER_UDMA_5 = 0x45,
 XFER_UDMA_4 = 0x44,
 XFER_UDMA_3 = 0x43,
 XFER_UDMA_2 = 0x42,
 XFER_UDMA_1 = 0x41,
 XFER_UDMA_0 = 0x40,
 XFER_MW_DMA_2 = 0x22,
 XFER_MW_DMA_1 = 0x21,
 XFER_MW_DMA_0 = 0x20,
 XFER_SW_DMA_2 = 0x12,
 XFER_SW_DMA_1 = 0x11,
 XFER_SW_DMA_0 = 0x10,
 XFER_PIO_4 = 0x0C,
 XFER_PIO_3 = 0x0B,
 XFER_PIO_2 = 0x0A,
 XFER_PIO_1 = 0x09,
 XFER_PIO_0 = 0x08,
 XFER_PIO_SLOW = 0x00,

 SETFEATURES_WC_ON = 0x02,
 SETFEATURES_WC_OFF = 0x82,

 ATAPI_PKT_DMA = (1 << 0),
 ATAPI_DMADIR = (1 << 2),
 ATAPI_CDB_LEN = 16,

 ATA_CBL_NONE = 0,
 ATA_CBL_PATA40 = 1,
 ATA_CBL_PATA80 = 2,
 ATA_CBL_PATA_UNK = 3,
 ATA_CBL_SATA = 4,

 SCR_STATUS = 0,
 SCR_ERROR = 1,
 SCR_CONTROL = 2,
 SCR_ACTIVE = 3,
 SCR_NOTIFICATION = 4,

 SERR_DATA_RECOVERED = (1 << 0),
 SERR_COMM_RECOVERED = (1 << 1),
 SERR_DATA = (1 << 8),
 SERR_PERSISTENT = (1 << 9),
 SERR_PROTOCOL = (1 << 10),
 SERR_INTERNAL = (1 << 11),
 SERR_PHYRDY_CHG = (1 << 16),
 SERR_DEV_XCHG = (1 << 26),

 ATA_TFLAG_LBA48 = (1 << 0),
 ATA_TFLAG_ISADDR = (1 << 1),
 ATA_TFLAG_DEVICE = (1 << 2),
 ATA_TFLAG_WRITE = (1 << 3),
 ATA_TFLAG_LBA = (1 << 4),
 ATA_TFLAG_FUA = (1 << 5),
 ATA_TFLAG_POLLING = (1 << 6),
};

enum ata_tf_protocols {

 ATA_PROT_UNKNOWN,
 ATA_PROT_NODATA,
 ATA_PROT_PIO,
 ATA_PROT_DMA,
 ATA_PROT_NCQ,
 ATA_PROT_ATAPI,
 ATA_PROT_ATAPI_NODATA,
 ATA_PROT_ATAPI_DMA,
};

enum ata_ioctls {
 ATA_IOC_GET_IO32 = 0x309,
 ATA_IOC_SET_IO32 = 0x324,
};

struct ata_prd {
 u32 addr;
 u32 flags_len;
};

struct ata_taskfile {
 unsigned long flags;
 u8 protocol;

 u8 ctl;

 u8 hob_feature;
 u8 hob_nsect;
 u8 hob_lbal;
 u8 hob_lbam;
 u8 hob_lbah;

 u8 feature;
 u8 nsect;
 u8 lbal;
 u8 lbam;
 u8 lbah;

 u8 device;

 u8 command;
};

#define ata_id_is_ata(id) (((id)[0] & (1 << 15)) == 0)
#define ata_id_is_cfa(id) ((id)[0] == 0x848A)
#define ata_id_is_sata(id) ((id)[93] == 0)
#define ata_id_rahead_enabled(id) ((id)[85] & (1 << 6))
#define ata_id_wcache_enabled(id) ((id)[85] & (1 << 5))
#define ata_id_hpa_enabled(id) ((id)[85] & (1 << 10))
#define ata_id_has_fua(id) ((id)[84] & (1 << 6))
#define ata_id_has_flush(id) ((id)[83] & (1 << 12))
#define ata_id_has_flush_ext(id) ((id)[83] & (1 << 13))
#define ata_id_has_lba48(id) ((id)[83] & (1 << 10))
#define ata_id_has_hpa(id) ((id)[82] & (1 << 10))
#define ata_id_has_wcache(id) ((id)[82] & (1 << 5))
#define ata_id_has_pm(id) ((id)[82] & (1 << 3))
#define ata_id_has_lba(id) ((id)[49] & (1 << 9))
#define ata_id_has_dma(id) ((id)[49] & (1 << 8))
#define ata_id_has_ncq(id) ((id)[76] & (1 << 8))
#define ata_id_queue_depth(id) (((id)[75] & 0x1f) + 1)
#define ata_id_removeable(id) ((id)[0] & (1 << 7))
#define ata_id_has_dword_io(id) ((id)[50] & (1 << 0))
#define ata_id_u32(id,n)   (((u32) (id)[(n) + 1] << 16) | ((u32) (id)[(n)]))
#define ata_id_u64(id,n)   ( ((u64) (id)[(n) + 3] << 48) |   ((u64) (id)[(n) + 2] << 32) |   ((u64) (id)[(n) + 1] << 16) |   ((u64) (id)[(n) + 0]) )

#define ata_id_cdb_intr(id) (((id)[0] & 0x60) == 0x20)

#endif
