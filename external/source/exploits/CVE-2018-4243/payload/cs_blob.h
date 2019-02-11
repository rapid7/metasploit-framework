//from: xnu osfmk/kern/cs_blobs.h

typedef struct __attribute__((packed)) {
    uint32_t magic;                    /* magic number (CSMAGIC_CODEDIRECTORY) */
    uint32_t length;                /* total length of CodeDirectory blob */
    uint32_t version;                /* compatibility version */
    uint32_t flags;                    /* setup and mode flags */
    uint32_t hashOffset;            /* offset of hash slot element at index zero */
    uint32_t identOffset;            /* offset of identifier string */
    uint32_t nSpecialSlots;            /* number of special hash slots */
    uint32_t nCodeSlots;            /* number of ordinary (code) hash slots */
    uint32_t codeLimit;                /* limit to main image signature range */
    uint8_t hashSize;                /* size of each hash in bytes */
    uint8_t hashType;                /* type of hash (cdHashType* constants) */
    uint8_t platform;                /* platform identifier; zero if not platform binary */
    uint8_t    pageSize;                /* log2(page size in bytes); 0 => infinite */
    uint32_t spare2;                /* unused (must be zero) */
    
    char end_earliest[0];
    
    /* Version 0x20100 */
    uint32_t scatterOffset;            /* offset of optional scatter vector */
    char end_withScatter[0];
    
    /* Version 0x20200 */
    uint32_t teamOffset;            /* offset of optional team identifier */
    char end_withTeam[0];
    
    /* Version 0x20300 */
    uint32_t spare3;                /* unused (must be zero) */
    uint64_t codeLimit64;            /* limit to main image signature range, 64 bits */
    char end_withCodeLimit64[0];
    
    /* Version 0x20400 */
    uint64_t execSegBase;            /* offset of executable segment */
    uint64_t execSegLimit;            /* limit of executable segment */
    uint64_t execSegFlags;            /* executable segment flags */
    char end_withExecSeg[0];
} CodeDirectory;

typedef struct __attribute__((packed)) {
    uint32_t type;                    /* type of entry */
    uint32_t offset;                /* offset of entry */
} CS_BlobIndex;

typedef struct __attribute__((packed)) {
    uint32_t magic;                    /* magic number */
    uint32_t length;                /* total length of SuperBlob */
    uint32_t count;                    /* number of index entries following */
    CS_BlobIndex index[];            /* (count) entries */
    /* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob;

/*
 * Magic numbers used by Code Signing
 */
enum {
    CSMAGIC_REQUIREMENT = 0xfade0c00,        /* single Requirement blob */
    CSMAGIC_REQUIREMENTS = 0xfade0c01,        /* Requirements vector (internal requirements) */
    CSMAGIC_CODEDIRECTORY = 0xfade0c02,        /* CodeDirectory blob */
    CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0, /* embedded form of signature data */
    CSMAGIC_EMBEDDED_SIGNATURE_OLD = 0xfade0b02,    /* XXX */
    CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171,    /* embedded entitlements */
    CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1, /* multi-arch collection of embedded signatures */
    CSMAGIC_BLOBWRAPPER = 0xfade0b01,    /* CMS Signature, among other things */
    
    CS_SUPPORTSSCATTER = 0x20100,
    CS_SUPPORTSTEAMID = 0x20200,
    CS_SUPPORTSCODELIMIT64 = 0x20300,
    CS_SUPPORTSEXECSEG = 0x20400,
    
    CSSLOT_CODEDIRECTORY = 0,                /* slot index for CodeDirectory */
    CSSLOT_INFOSLOT = 1,
    CSSLOT_REQUIREMENTS = 2,
    CSSLOT_RESOURCEDIR = 3,
    CSSLOT_APPLICATION = 4,
    CSSLOT_ENTITLEMENTS = 5,
    
    CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000, /* first alternate CodeDirectory, if any */
    CSSLOT_ALTERNATE_CODEDIRECTORY_MAX = 5,        /* max number of alternate CD slots */
    CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT = CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX, /* one past the last */
    
    CSSLOT_SIGNATURESLOT = 0x10000,            /* CMS Signature */
    
    CSTYPE_INDEX_REQUIREMENTS = 0x00000002,        /* compat with amfi */
    CSTYPE_INDEX_ENTITLEMENTS = 0x00000005,        /* compat with amfi */
    
    CS_HASHTYPE_SHA1 = 1,
    CS_HASHTYPE_SHA256 = 2,
    CS_HASHTYPE_SHA256_TRUNCATED = 3,
    CS_HASHTYPE_SHA384 = 4,
    
    CS_SHA1_LEN = 20,
    CS_SHA256_LEN = 32,
    CS_SHA256_TRUNCATED_LEN = 20,
    
    CS_CDHASH_LEN = 20,                        /* always - larger hashes are truncated */
    CS_HASH_MAX_SIZE = 48, /* max size of the hash we'll support */
    
    /*
     * Currently only to support Legacy VPN plugins,
     * but intended to replace all the various platform code, dev code etc. bits.
     */
    CS_SIGNER_TYPE_UNKNOWN = 0,
    CS_SIGNER_TYPE_LEGACYVPN = 5,
};

/*
 * Choose among different hash algorithms.
 * Higher is better, 0 => don't use at all.
 */
static const uint32_t hashPriorities[] = {
    CS_HASHTYPE_SHA1,
    CS_HASHTYPE_SHA256_TRUNCATED,
    CS_HASHTYPE_SHA256,
    CS_HASHTYPE_SHA384,
};

typedef struct __SC_GenericBlob {
    uint32_t magic;                    /* magic number */
    uint32_t length;                /* total length of blob */
    char data[];
} CS_GenericBlob;

/*
 * C form of a CodeDirectory.
 */
typedef struct __CodeDirectory {
    uint32_t magic;                    /* magic number (CSMAGIC_CODEDIRECTORY) */
    uint32_t length;                /* total length of CodeDirectory blob */
    uint32_t version;                /* compatibility version */
    uint32_t flags;                    /* setup and mode flags */
    uint32_t hashOffset;            /* offset of hash slot element at index zero */
    uint32_t identOffset;            /* offset of identifier string */
    uint32_t nSpecialSlots;            /* number of special hash slots */
    uint32_t nCodeSlots;            /* number of ordinary (code) hash slots */
    uint32_t codeLimit;                /* limit to main image signature range */
    uint8_t hashSize;                /* size of each hash in bytes */
    uint8_t hashType;                /* type of hash (cdHashType* constants) */
    uint8_t spare1;                    /* unused (must be zero) */
    uint8_t    pageSize;                /* log2(page size in bytes); 0 => infinite */
    uint32_t spare2;                /* unused (must be zero) */
    /* followed by dynamic content as located by offset fields above */
} CS_CodeDirectory;

#define CS_OPS_ENTITLEMENTS_BLOB 7    /* get entitlements blob */
int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

struct cs_blob {
    struct cs_blob    *csb_next;
    cpu_type_t    csb_cpu_type;
    unsigned int    csb_flags;
    off_t        csb_base_offset;    /* Offset of Mach-O binary in fat binary */
    off_t        csb_start_offset;    /* Blob coverage area start, from csb_base_offset */
    off_t        csb_end_offset;        /* Blob coverage area end, from csb_base_offset */
    vm_size_t    csb_mem_size;
    vm_offset_t    csb_mem_offset;
    vm_address_t    csb_mem_kaddr;
    unsigned char    csb_cdhash[CS_CDHASH_LEN];
    const struct cs_hash  *csb_hashtype;
    vm_size_t    csb_hash_pagesize;    /* each hash entry represent this many bytes in the file */
    vm_size_t    csb_hash_pagemask;
    vm_size_t    csb_hash_pageshift;
    vm_size_t    csb_hash_firstlevel_pagesize;    /* First hash this many bytes, then hash the hashes together */
    const CS_CodeDirectory *csb_cd;
    const char     *csb_teamid;
    const CS_GenericBlob *csb_entitlements_blob;    /* raw blob, subrange of csb_mem_kaddr */
    void *          csb_entitlements;    /* The entitlements as an OSDictionary */
    unsigned int    csb_signer_type;
    
    /* The following two will be replaced by the csb_signer_type. */
    unsigned int    csb_platform_binary:1;
    unsigned int    csb_platform_path:1;
};
