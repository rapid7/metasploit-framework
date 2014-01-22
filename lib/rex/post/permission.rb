# -*- coding: binary -*-

# Generic page protection flags
PROT_NONE         =        0
PROT_READ         = (1 <<  0)
PROT_WRITE        = (1 <<  1)
PROT_EXEC         = (1 <<  2)
PROT_COW          = (1 << 20)

# Generic permissions
GEN_NONE          =        0
GEN_READ          = (1 <<  0)
GEN_WRITE         = (1 <<  1)
GEN_EXEC          = (1 <<  2)

# Generic process open permissions
PROCESS_READ      = (1 <<  0)
PROCESS_WRITE     = (1 <<  1)
PROCESS_EXECUTE   = (1 <<  2)
PROCESS_ALL       = 0xffffffff

# Generic thread open permissions
THREAD_READ       = (1 <<  0)
THREAD_WRITE      = (1 <<  1)
THREAD_EXECUTE    = (1 <<  2)
THREAD_ALL        = 0xffffffff
