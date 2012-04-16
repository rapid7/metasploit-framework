############################################################################
# error.rb
#
# Includes all of the error codes in error.h, msterr.h and some from
# winerror.h.
#
# Adds the following convenience methods:
#
# get_last_error - Returns a human readable string for the error returned
# by the GetLastError() function.
############################################################################
require 'windows/api'

module Windows
  module Error
    API.auto_namespace = 'Windows::Error'
    API.auto_method    = true
    API.auto_constant  = true
    API.auto_unicode   = true

    private

    FORMAT_MESSAGE_ALLOCATE_BUFFER   = 0x00000100
    FORMAT_MESSAGE_IGNORE_INSERTS    = 0x00000200
    FORMAT_MESSAGE_FROM_STRING       = 0x00000400
    FORMAT_MESSAGE_FROM_HMODULE      = 0x00000800
    FORMAT_MESSAGE_FROM_SYSTEM       = 0x00001000
    FORMAT_MESSAGE_ARGUMENT_ARRAY    = 0x00002000
    FORMAT_MESSAGE_MAX_WIDTH_MASK    = 0x000000FF

    SEM_FAILCRITICALERRORS     = 0x0001
    SEM_NOALIGNMENTFAULTEXCEPT = 0x0004
    SEM_NOGPFAULTERRORBOX      = 0x0002
    SEM_NOOPENFILEERRORBOX     = 0x8000

    S_OK                      = 0
    NO_ERROR                  = 0
    ERROR_SUCCESS             = 0
    ERROR_INVALID_FUNCTION    = 1
    ERROR_FILE_NOT_FOUND      = 2
    ERROR_PATH_NOT_FOUND      = 3
    ERROR_TOO_MANY_OPEN_FILES = 4
    ERROR_ACCESS_DENIED       = 5
    ERROR_INVALID_HANDLE      = 6
    ERROR_ARENA_TRASHED       = 7
    ERROR_NOT_ENOUGH_MEMORY   = 8
    ERROR_INVALID_BLOCK       = 9
    ERROR_BAD_ENVIRONMENT     = 10
    ERROR_BAD_FORMAT          = 11
    ERROR_INVALID_ACCESS      = 12
    ERROR_INVALID_DATA        = 13
    ERROR_INVALID_DRIVE       = 15
    ERROR_CURRENT_DIRECTORY   = 16
    ERROR_NOT_SAME_DEVICE     = 17
    ERROR_NO_MORE_FILES       = 18

    ERROR_WRITE_PROTECT    = 19
    ERROR_BAD_UNIT         = 20
    ERROR_NOT_READY        = 21
    ERROR_BAD_COMMAND      = 22
    ERROR_CRC              = 23
    ERROR_BAD_LENGTH       = 24
    ERROR_SEEK             = 25
    ERROR_NOT_DOS_DISK     = 26
    ERROR_SECTOR_NOT_FOUND = 27
    ERROR_OUT_OF_PAPER     = 28
    ERROR_WRITE_FAULT      = 29
    ERROR_READ_FAULT       = 30
    ERROR_GEN_FAILURE      = 31

    ERROR_SHARING_VIOLATION       = 32
    ERROR_LOCK_VIOLATION          = 33
    ERROR_WRONG_DISK              = 34
    ERROR_FCB_UNAVAILABLE         = 35
    ERROR_SHARING_BUFFER_EXCEEDED = 36
    ERROR_HANDLE_EOF              = 38
    ERROR_HANDLE_DISK_FULL        = 39

    ERROR_NOT_SUPPORTED = 50

    ERROR_FILE_EXISTS  = 80
    ERROR_DUP_FCB      = 81
    ERROR_CANNOT_MAKE  = 82
    ERROR_FAIL_I24     = 83

    ERROR_OUT_OF_STRUCTURES = 84
    ERROR_ALREADY_ASSIGNED  = 85
    ERROR_INVALID_PASSWORD  = 86
    ERROR_INVALID_PARAMETER = 87
    ERROR_NET_WRITE_FAULT   = 88

    ERROR_NO_PROC_SLOTS = 89  # no process slots available
    ERROR_NOT_FROZEN    = 90
    ERR_TSTOVFL         = 91  # timer service table overflow
    ERR_TSTDUP          = 92  # timer service table duplicate
    ERROR_NO_ITEMS      = 93  # There were no items to operate upon
    ERROR_INTERRUPT     = 95  # interrupted system call

    ERROR_TOO_MANY_SEMAPHORES       = 100
    ERROR_EXCL_SEM_ALREADY_OWNED    = 101
    ERROR_SEM_IS_SET                = 102
    ERROR_TOO_MANY_SEM_REQUESTS     = 103
    ERROR_INVALID_AT_INTERRUPT_TIME = 104

    ERROR_SEM_OWNER_DIED = 105 # waitsem found owner died
    ERROR_SEM_USER_LIMIT = 106 # too many procs have this sem
    ERROR_DISK_CHANGE    = 107 # insert disk b into drive a
    ERROR_DRIVE_LOCKED   = 108 # drive locked by another process
    ERROR_BROKEN_PIPE    = 109 # write on pipe with no reader

    ERROR_OPEN_FAILED             = 110 # open/created failed
    ERROR_DISK_FULL               = 112 # not enough space
    ERROR_NO_MORE_SEARCH_HANDLES  = 113 # can't allocate
    ERROR_INVALID_TARGET_HANDLE   = 114 # handle in DOSDUPHANDLE is invalid
    ERROR_PROTECTION_VIOLATION    = 115 # bad user virtual address
    ERROR_VIOKBD_REQUEST          = 116
    ERROR_INVALID_CATEGORY        = 117 # category for DEVIOCTL not defined
    ERROR_INVALID_VERIFY_SWITCH   = 118 # invalid value
    ERROR_BAD_DRIVER_LEVEL        = 119 # DosDevIOCTL not level four
    ERROR_CALL_NOT_IMPLEMENTED    = 120
    ERROR_SEM_TIMEOUT             = 121 # timeout from semaphore function
    ERROR_INSUFFICIENT_BUFFER     = 122

    ERROR_INVALID_NAME    = 123 # illegal char or malformed file system name
    ERROR_INVALID_LEVEL   = 124 # unimplemented level for info retrieval
    ERROR_NO_VOLUME_LABEL = 125 # no volume label found
    ERROR_MOD_NOT_FOUND   = 126 # w_getprocaddr, w_getmodhandle
    ERROR_PROC_NOT_FOUND  = 127 # w_getprocaddr

    ERROR_WAIT_NO_CHILDREN   = 128 # CWait finds to children
    ERROR_CHILD_NOT_COMPLETE = 129 # CWait children not dead yet

    ERROR_DIRECT_ACCESS_HANDLE = 130 # invalid for direct disk access
    ERROR_NEGATIVE_SEEK        = 131 # tried to seek negative offset
    ERROR_SEEK_ON_DEVICE       = 132 # tried to seek on device or pipe

    ERROR_IS_JOIN_TARGET         = 133
    ERROR_IS_JOINED              = 134
    ERROR_IS_SUBSTED             = 135
    ERROR_NOT_JOINED             = 136
    ERROR_NOT_SUBSTED            = 137
    ERROR_JOIN_TO_JOIN           = 138
    ERROR_SUBST_TO_SUBST         = 139
    ERROR_JOIN_TO_SUBST          = 140
    ERROR_SUBST_TO_JOIN          = 141
    ERROR_BUSY_DRIVE             = 142
    ERROR_SAME_DRIVE             = 143
    ERROR_DIR_NOT_ROOT           = 144
    ERROR_DIR_NOT_EMPTY          = 145
    ERROR_IS_SUBST_PATH          = 146
    ERROR_IS_JOIN_PATH           = 147
    ERROR_PATH_BUSY              = 148
    ERROR_IS_SUBST_TARGET        = 149
    ERROR_SYSTEM_TRACE           = 150 # system trace error
    ERROR_INVALID_EVENT_COUNT    = 151 # DosMuxSemWait errors
    ERROR_TOO_MANY_MUXWAITERS    = 152
    ERROR_INVALID_LIST_FORMAT    = 153
    ERROR_LABEL_TOO_LONG         = 154
    ERROR_TOO_MANY_TCBS          = 155
    ERROR_SIGNAL_REFUSED         = 156
    ERROR_DISCARDED              = 157
    ERROR_NOT_LOCKED             = 158
    ERROR_BAD_THREADID_ADDR      = 159
    ERROR_BAD_ARGUMENTS          = 160
    ERROR_BAD_PATHNAME           = 161
    ERROR_SIGNAL_PENDING         = 162
    ERROR_UNCERTAIN_MEDIA        = 163
    ERROR_MAX_THRDS_REACHED      = 164
    ERROR_MONITORS_NOT_SUPPORTED = 165

    ERROR_INVALID_SEGMENT_NUMBER = 180
    ERROR_INVALID_CALLGATE       = 181
    ERROR_INVALID_ORDINAL        = 182
    ERROR_ALREADY_EXISTS         = 183
    ERROR_NO_CHILD_PROCESS       = 184
    ERROR_CHILD_ALIVE_NOWAIT     = 185
    ERROR_INVALID_FLAG_NUMBER    = 186
    ERROR_SEM_NOT_FOUND          = 187

    ERROR_INVALID_STARTING_CODESEG  = 188
    ERROR_INVALID_STACKSEG          = 189
    ERROR_INVALID_MODULETYPE        = 190
    ERROR_INVALID_EXE_SIGNATURE     = 191
    ERROR_EXE_MARKED_INVALID        = 192
    ERROR_BAD_EXE_FORMAT            = 193
    ERROR_ITERATED_DATA_EXCEEDS_64k = 194
    ERROR_INVALID_MINALLOCSIZE      = 195
    ERROR_DYNLINK_FROM_INVALID_RING = 196
    ERROR_IOPL_NOT_ENABLED          = 197
    ERROR_INVALID_SEGDPL            = 198
    ERROR_AUTODATASEG_EXCEEDS_64k   = 199
    ERROR_RING2SEG_MUST_BE_MOVABLE  = 200
    ERROR_RELOC_CHAIN_XEEDS_SEGLIM  = 201
    ERROR_INFLOOP_IN_RELOC_CHAIN    = 202

    ERROR_ENVVAR_NOT_FOUND        = 203
    ERROR_NOT_CURRENT_CTRY        = 204
    ERROR_NO_SIGNAL_SENT          = 205
    ERROR_FILENAME_EXCED_RANGE    = 206 # if filename > 8.3
    ERROR_RING2_STACK_IN_USE      = 207 # for FAPI
    ERROR_META_EXPANSION_TOO_LONG = 208 # if "*a" > 8.3

    ERROR_INVALID_SIGNAL_NUMBER = 209
    ERROR_THREAD_1_INACTIVE     = 210
    ERROR_INFO_NOT_AVAIL        = 211 #@@ PTM 5550
    ERROR_LOCKED                = 212
    ERROR_BAD_DYNALINK          = 213 #@@ PTM 5760
    ERROR_TOO_MANY_MODULES      = 214
    ERROR_NESTING_NOT_ALLOWED   = 215
    ERROR_BAD_PIPE              = 230
    ERROR_PIPE_BUSY             = 231
    ERROR_NO_DATA               = 232
    ERROR_PIPE_NOT_CONNECTED    = 233
    ERROR_MORE_DATA             = 234

    ERROR_PIPE_CONNECTED = 535
    ERROR_PIPE_LISTENING = 536

    ERROR_OPERATION_ABORTED = 995
    ERROR_IO_INCOMPLETE     = 996
    ERROR_IO_PENDING        = 997

    ERROR_USER_DEFINED_BASE = 0xF000

    ERROR_I24_WRITE_PROTECT         = 0
    ERROR_I24_BAD_UNIT              = 1
    ERROR_I24_NOT_READY             = 2
    ERROR_I24_BAD_COMMAND           = 3
    ERROR_I24_CRC                   = 4
    ERROR_I24_BAD_LENGTH            = 5
    ERROR_I24_SEEK                  = 6
    ERROR_I24_NOT_DOS_DISK          = 7
    ERROR_I24_SECTOR_NOT_FOUND      = 8
    ERROR_I24_OUT_OF_PAPER          = 9
    ERROR_I24_WRITE_FAULT           = 0x0A
    ERROR_I24_READ_FAULT            = 0x0B
    ERROR_I24_GEN_FAILURE           = 0x0C
    ERROR_I24_DISK_CHANGE           = 0x0D
    ERROR_I24_WRONG_DISK            = 0x0F
    ERROR_I24_UNCERTAIN_MEDIA       = 0x10
    ERROR_I24_CHAR_CALL_INTERRUPTED = 0x11
    ERROR_I24_NO_MONITOR_SUPPORT    = 0x12
    ERROR_I24_INVALID_PARAMETER     = 0x13

    APPLICATION_ERROR_MASK       = 0x20000000
    ERROR_SEVERITY_SUCCESS       = 0x00000000
    ERROR_SEVERITY_INFORMATIONAL = 0x40000000
    ERROR_SEVERITY_WARNING       = 0x80000000
    ERROR_SEVERITY_ERROR         = 0xc0000000

    ALLOWED_FAIL   = 0x0001
    ALLOWED_ABORT  = 0x0002
    ALLOWED_RETRY  = 0x0004
    ALLOWED_IGNORE = 0x0008

    I24_OPERATION = 0x1
    I24_AREA      = 0x6
    I24_CLASS     = 0x80

    ERRCLASS_OUTRES  = 1   # Out of Resource
    ERRCLASS_TEMPSIT = 2   # Temporary Situation
    ERRCLASS_AUTH    = 3   # Permission problem
    ERRCLASS_INTRN   = 4   # Internal System Error
    ERRCLASS_HRDFAIL = 5   # Hardware Failure
    ERRCLASS_SYSFAIL = 6   # System Failure
    ERRCLASS_APPERR  = 7   # Application Error
    ERRCLASS_NOTFND  = 8   # Not Found
    ERRCLASS_BADFMT  = 9   # Bad Format
    ERRCLASS_LOCKED  = 10  # Locked
    ERRCLASS_MEDIA   = 11  # Media Failure
    ERRCLASS_ALREADY = 12  # Collision with Existing Item
    ERRCLASS_UNK     = 13  # Unknown/other
    ERRCLASS_CANT    = 14
    ERRCLASS_TIME    = 15

    ERRACT_RETRY  = 1   # Retry
    ERRACT_DLYRET = 2   # Delay Retry, retry after pause
    ERRACT_USER   = 3   # Ask user to regive info
    ERRACT_ABORT  = 4   # abort with clean up
    ERRACT_PANIC  = 5   # abort immediately
    ERRACT_IGNORE = 6   # ignore
    ERRACT_INTRET = 7   # Retry after User Intervention

    ERRLOC_UNK    = 1   # No appropriate value
    ERRLOC_DISK   = 2   # Random Access Mass Storage
    ERRLOC_NET    = 3   # Network
    ERRLOC_SERDEV = 4   # Serial Device
    ERRLOC_MEM    = 5   # Memory

    TC_NORMAL  = 0
    TC_HARDERR = 1
    TC_GP_TRAP = 2
    TC_SIGNAL  = 3

    # From WinError.h

    ERROR_INVALID_FLAGS          = 0x1004
    ERROR_NO_UNICODE_TRANSLATION = 0x1113

    E_INVALIDARG  = 0x80070057
    E_NOINTERFACE = 0x80004002
    E_NOTIMPL     = 0x80004001
    E_OUTOFMEMORY = 0x8007000E
    E_UNEXPECTED  = 0x8000FFFF

    RPC_E_TIMEOUT = 0x8001011F

    CO_E_NOT_SUPPORTED = 0x80004021

    CLASS_E_NOAGGREGATION = 0x80040110

    DISP_E_BADINDEX       = 0x8002000B
    DISP_E_PARAMNOTFOUND  = 0x80020004
    DISP_E_EXCEPTION      = 0x80020009
    DISP_E_MEMBERNOTFOUND = 0x80020003

    # Registry errors

    REGDB_E_CLASSNOTREG = 0x80040154

    # msterr.h

    SCHED_S_TASK_READY                  = 0x00041300
    SCHED_S_TASK_RUNNING                = 0x00041301
    SCHED_S_TASK_DISABLED               = 0x00041302
    SCHED_S_TASK_HAS_NOT_RUN            = 0x00041303
    SCHED_S_TASK_HAS_NO_MORE_RUNS       = 0x00041304
    SCHED_S_TASK_NOT_SCHEDULED          = 0x00041305
    SCHED_S_TASK_TERMINATED             = 0x00041306
    SCHED_S_TASK_NO_VALID_TRIGGERS      = 0x00041307
    SCHED_S_EVENT_TRIGGER               = 0x00041308
    SCHED_E_TRIGGER_NOT_FOUND           = 0x00041309
    SCHED_E_TASK_NOT_READY              = 0x0004130A
    SCHED_E_TASK_NOT_RUNNING            = 0x0004130B
    SCHED_E_SERVICE_NOT_INSTALLED       = 0x0004130C
    SCHED_E_CANNOT_OPEN_TASK            = 0x0004130D
    SCHED_E_INVALID_TASK                = 0x0004130E
    SCHED_E_ACCOUNT_INFORMATION_NOT_SET = 0x0004130F
    SCHED_E_ACCOUNT_NAME_NOT_FOUND      = 0x00041310
    SCHED_E_ACCOUNT_DBASE_CORRUPT       = 0x00041311
    SCHED_E_NO_SECURITY_SERVICES        = 0x00041312
    SCHED_E_UNKNOWN_OBJECT_VERSION      = 0x00041313

    # Socket errors

    WSA_INVALID_HANDLE      = 6
    WSA_NOT_ENOUGH_MEMORY   = 8
    WSA_INVALID_PARAMETER   = 87
    WSA_OPERATION_ABORTED   = 995
    WSA_IO_INCOMPLETE       = 996
    WSA_IO_PENDING          = 997
    WSAEINTR                = 10004
    WSAEBADF                = 10009
    WSAEACCESS              = 10013
    WSAEFAULT               = 10014
    WSAEINVAL               = 10022
    WSAEMFILE               = 10024
    WSAEWOULDBLOCK          = 10035
    WSAEINPROGRESS          = 10036
    WSAEALREADY             = 10037
    WSAENOTSOCK             = 10038
    WSAEDESTADDRREQ         = 10039
    WSAEMSGSIZE             = 10040
    WSAEPROTOTYPE           = 10041
    WSAENOPROTOOPT          = 10042
    WSAEPROTONOSUPPORT      = 10043
    WSAESOCKTNOSUPPORT      = 10044
    WSAEOPNOTSUPP           = 10045
    WSAEPFNOSUPPORT         = 10046
    WSAEAFNOSUPPORT         = 10047
    WSAEADDRINUSE           = 10048
    WSAEADDRNOTAVAIL        = 10049
    WSAENETDOWN             = 10050
    WSAENETUNREACH          = 10051
    WSAENETRESET            = 10052
    WSAECONNABORTED         = 10053
    WSAECONNRESET           = 10054
    WSAENOBUFS              = 10055
    WSAEISCONN              = 10056
    WSAENOTCONN             = 10057
    WSAESHUTDOWN            = 10058
    WSAETOOMANYREFS         = 10059
    WSATIMEDOUT             = 10060
    WSAECONNREFUSED         = 10061
    WSAELOOP                = 10062
    WSAENAMETOOLONG         = 10063
    WSAEHOSTDOWN            = 10064
    WSAEHOSTUNREACH         = 10065
    WSAENOEMPTY             = 10066
    WSAEPROCLIM             = 10067
    WSAEUSERS               = 10068
    WSAEDQUOT               = 10069
    WSAESTALE               = 10070
    WSAEREMOTE              = 10071
    WSASYSNOTREADY          = 10091
    WSAVERNOTSUPPORTED      = 10092
    WSANOTINITIALISED       = 10093
    WSAEDISCON              = 10101
    WSAENOMORE              = 10102
    WSAECANCELLED           = 10103
    WSAEINVALIDPROCTABLE    = 10104
    WSAEINVALIDPROVIDER     = 10105
    WSAEPROVIDERFAILEDINIT  = 10106
    WSASYSCALLFAILURE       = 10107
    WSASERVICE_NOT_FOUND    = 10108
    WSATYPE_NOT_FOUND       = 10109
    WSA_E_NO_MORE           = 10110
    WSA_E_CANCELLED         = 10111
    WSAEREFUSED             = 10112
    WSAHOST_NOT_FOUND       = 11001
    WSATRY_AGAIN            = 11002
    WSANO_RECOVERY          = 11003
    WSANO_DATA              = 11004
    WSA_QOS_RECEIVERS       = 11005
    WSA_QOS_SENDERS         = 11006

    API.new('GetLastError', 'V', 'L')
    API.new('SetLastError', 'L', 'V')
    API.new('SetErrorMode', 'I', 'I')
    API.new('FormatMessage', 'LLLLPLP', 'L')

    begin
      API.new('SetLastErrorEx', 'LL', 'V', 'user32')
    rescue Win32::API::LoadLibraryError
      # VC++ 7.0 or later
    end

    # Convenience method that wraps FormatMessage with some sane defaults and
    # returns a human readable string.
    #
    def get_last_error(err_num = GetLastError.call)
      buf   = 0.chr * 260
      flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ARGUMENT_ARRAY
      FormatMessageA.call(flags, 0, err_num, 0, buf, buf.size, 0)
      buf.strip
    end

    # Macros from WinError.h

    def IS_ERROR(status)
      status >> 31 == 1
    end

    def MAKE_HRESULT(sev, fac, code)
      sev << 31 | fac << 16 | code
    end

    def MAKE_SCODE(sev, fac, code)
      sev << 31 | fac << 16 | code
    end

    def HRESULT_CODE(hr)
      hr & 0xFFFF
    end

    def HRESULT_FACILITY(hr)
      (hr >> 16) & 0x1fff
    end

    def HRESULT_FROM_NT(x)
      x | 0x10000000 # FACILITY_NT_BIT
    end

    def HRESULT_FROM_WIN32(x)
      if x <= 0
        x
      else
        (x & 0x0000FFFF) | (7 << 16) | 0x80000000
      end
    end

    def HRESULT_SEVERITY(hr)
      (hr >> 31) & 0x1
    end

    def FAILED(status)
      status < 0
    end

    def SUCCEEDED(status)
      status >= 0
    end
  end
end
