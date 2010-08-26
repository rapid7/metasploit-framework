/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* the following corresponds to the error codes of the Linux kernel used by the Android platform
 * these are distinct from the OpenBSD ones, which is why we need to redeclare them here
 *
 * this file may be included several times to define either error constants or their
 * string representation
 */

#ifndef __BIONIC_ERRDEF
#error "__BIONIC_ERRDEF must be defined before including this file"
#endif
__BIONIC_ERRDEF( EPERM          ,   1, "Operation not permitted" )
__BIONIC_ERRDEF( ENOENT         ,   2, "No such file or directory" )
__BIONIC_ERRDEF( ESRCH          ,   3, "No such process" )
__BIONIC_ERRDEF( EINTR          ,   4, "Interrupted system call" )
__BIONIC_ERRDEF( EIO            ,   5, "I/O error" )
__BIONIC_ERRDEF( ENXIO          ,   6, "No such device or address" )
__BIONIC_ERRDEF( E2BIG          ,   7, "Argument list too long" )
__BIONIC_ERRDEF( ENOEXEC        ,   8, "Exec format error" )
__BIONIC_ERRDEF( EBADF          ,   9, "Bad file number" )
__BIONIC_ERRDEF( ECHILD         ,  10, "No child processes" )
__BIONIC_ERRDEF( EAGAIN         ,  11, "Try again" )
__BIONIC_ERRDEF( ENOMEM         ,  12, "Out of memory" )
__BIONIC_ERRDEF( EACCES         ,  13, "Permission denied" )
__BIONIC_ERRDEF( EFAULT         ,  14, "Bad address" )
__BIONIC_ERRDEF( ENOTBLK        ,  15, "Block device required" )
__BIONIC_ERRDEF( EBUSY          ,  16, "Device or resource busy" )
__BIONIC_ERRDEF( EEXIST         ,  17, "File exists" )
__BIONIC_ERRDEF( EXDEV          ,  18, "Cross-device link" )
__BIONIC_ERRDEF( ENODEV         ,  19, "No such device" )
__BIONIC_ERRDEF( ENOTDIR        ,  20, "Not a directory" )
__BIONIC_ERRDEF( EISDIR         ,  21, "Is a directory" )
__BIONIC_ERRDEF( EINVAL         ,  22, "Invalid argument" )
__BIONIC_ERRDEF( ENFILE         ,  23, "File table overflow" )
__BIONIC_ERRDEF( EMFILE         ,  24, "Too many open files" )
__BIONIC_ERRDEF( ENOTTY         ,  25, "Not a typewriter" )
__BIONIC_ERRDEF( ETXTBSY        ,  26, "Text file busy" )
__BIONIC_ERRDEF( EFBIG          ,  27, "File too large" )
__BIONIC_ERRDEF( ENOSPC         ,  28, "No space left on device" )
__BIONIC_ERRDEF( ESPIPE         ,  29, "Illegal seek" )
__BIONIC_ERRDEF( EROFS          ,  30, "Read-only file system" )
__BIONIC_ERRDEF( EMLINK         ,  31, "Too many links" )
__BIONIC_ERRDEF( EPIPE          ,  32, "Broken pipe" )
__BIONIC_ERRDEF( EDOM           ,  33, "Math argument out of domain of func" )
__BIONIC_ERRDEF( ERANGE         ,  34, "Math result not representable" )
__BIONIC_ERRDEF( EDEADLK        ,  35, "Resource deadlock would occur" )
__BIONIC_ERRDEF( ENAMETOOLONG   ,  36, "File name too long" )
__BIONIC_ERRDEF( ENOLCK         ,  37, "No record locks available" )
__BIONIC_ERRDEF( ENOSYS         ,  38, "Function not implemented" )
__BIONIC_ERRDEF( ENOTEMPTY      ,  39, "Directory not empty" )
__BIONIC_ERRDEF( ELOOP          ,  40, "Too many symbolic links encountered" )
__BIONIC_ERRDEF( ENOMSG         ,  42, "No message of desired type" )
__BIONIC_ERRDEF( EIDRM          ,  43, "Identifier removed" )
__BIONIC_ERRDEF( ECHRNG         ,  44, "Channel number out of range" )
__BIONIC_ERRDEF( EL2NSYNC       ,  45, "Level 2 not synchronized" )
__BIONIC_ERRDEF( EL3HLT         ,  46, "Level 3 halted" )
__BIONIC_ERRDEF( EL3RST         ,  47, "Level 3 reset" )
__BIONIC_ERRDEF( ELNRNG         ,  48, "Link number out of range" )
__BIONIC_ERRDEF( EUNATCH        ,  49, "Protocol driver not attached" )
__BIONIC_ERRDEF( ENOCSI         ,  50, "No CSI structure available" )
__BIONIC_ERRDEF( EL2HLT         ,  51, "Level 2 halted" )
__BIONIC_ERRDEF( EBADE          ,  52, "Invalid exchange" )
__BIONIC_ERRDEF( EBADR          ,  53, "Invalid request descriptor" )
__BIONIC_ERRDEF( EXFULL         ,  54, "Exchange full" )
__BIONIC_ERRDEF( ENOANO         ,  55, "No anode" )
__BIONIC_ERRDEF( EBADRQC        ,  56, "Invalid request code" )
__BIONIC_ERRDEF( EBADSLT        ,  57, "Invalid slot" )
__BIONIC_ERRDEF( EBFONT         ,  59, "Bad font file format" )
__BIONIC_ERRDEF( ENOSTR         ,  60, "Device not a stream" )
__BIONIC_ERRDEF( ENODATA        ,  61, "No data available" )
__BIONIC_ERRDEF( ETIME          ,  62, "Timer expired" )
__BIONIC_ERRDEF( ENOSR          ,  63, "Out of streams resources" )
__BIONIC_ERRDEF( ENONET         ,  64, "Machine is not on the network" )
__BIONIC_ERRDEF( ENOPKG         ,  65, "Package not installed" )
__BIONIC_ERRDEF( EREMOTE        ,  66, "Object is remote" )
__BIONIC_ERRDEF( ENOLINK        ,  67, "Link has been severed" )
__BIONIC_ERRDEF( EADV           ,  68, "Advertise error" )
__BIONIC_ERRDEF( ESRMNT         ,  69, "Srmount error" )
__BIONIC_ERRDEF( ECOMM          ,  70, "Communication error on send" )
__BIONIC_ERRDEF( EPROTO         ,  71, "Protocol error" )
__BIONIC_ERRDEF( EMULTIHOP      ,  72, "Multihop attempted" )
__BIONIC_ERRDEF( EDOTDOT        ,  73, "RFS specific error" )
__BIONIC_ERRDEF( EBADMSG        ,  74, "Not a data message" )
__BIONIC_ERRDEF( EOVERFLOW      ,  75, "Value too large for defined data type" )
__BIONIC_ERRDEF( ENOTUNIQ       ,  76, "Name not unique on network" )
__BIONIC_ERRDEF( EBADFD         ,  77, "File descriptor in bad state" )
__BIONIC_ERRDEF( EREMCHG        ,  78, "Remote address changed" )
__BIONIC_ERRDEF( ELIBACC        ,  79, "Can not access a needed shared library" )
__BIONIC_ERRDEF( ELIBBAD        ,  80, "Accessing a corrupted shared library" )
__BIONIC_ERRDEF( ELIBSCN        ,  81, ".lib section in a.out corrupted" )
__BIONIC_ERRDEF( ELIBMAX        ,  82, "Attempting to link in too many shared libraries" )
__BIONIC_ERRDEF( ELIBEXEC       ,  83, "Cannot exec a shared library directly" )
__BIONIC_ERRDEF( EILSEQ         ,  84, "Illegal byte sequence" )
__BIONIC_ERRDEF( ERESTART       ,  85, "Interrupted system call should be restarted" )
__BIONIC_ERRDEF( ESTRPIPE       ,  86, "Streams pipe error" )
__BIONIC_ERRDEF( EUSERS         ,  87, "Too many users" )
__BIONIC_ERRDEF( ENOTSOCK       ,  88, "Socket operation on non-socket" )
__BIONIC_ERRDEF( EDESTADDRREQ   ,  89, "Destination address required" )
__BIONIC_ERRDEF( EMSGSIZE       ,  90, "Message too long" )
__BIONIC_ERRDEF( EPROTOTYPE     ,  91, "Protocol wrong type for socket" )
__BIONIC_ERRDEF( ENOPROTOOPT    ,  92, "Protocol not available" )
__BIONIC_ERRDEF( EPROTONOSUPPORT,  93, "Protocol not supported" )
__BIONIC_ERRDEF( ESOCKTNOSUPPORT,  94, "Socket type not supported" )
__BIONIC_ERRDEF( EOPNOTSUPP     ,  95, "Operation not supported on transport endpoint" )
__BIONIC_ERRDEF( EPFNOSUPPORT   ,  96, "Protocol family not supported" )
__BIONIC_ERRDEF( EAFNOSUPPORT   ,  97, "Address family not supported by protocol" )
__BIONIC_ERRDEF( EADDRINUSE     ,  98, "Address already in use" )
__BIONIC_ERRDEF( EADDRNOTAVAIL  ,  99, "Cannot assign requested address" )
__BIONIC_ERRDEF( ENETDOWN       , 100, "Network is down" )
__BIONIC_ERRDEF( ENETUNREACH    , 101, "Network is unreachable" )
__BIONIC_ERRDEF( ENETRESET      , 102, "Network dropped connection because of reset" )
__BIONIC_ERRDEF( ECONNABORTED   , 103, "Software caused connection abort" )
__BIONIC_ERRDEF( ECONNRESET     , 104, "Connection reset by peer" )
__BIONIC_ERRDEF( ENOBUFS        , 105, "No buffer space available" )
__BIONIC_ERRDEF( EISCONN        , 106, "Transport endpoint is already connected" )
__BIONIC_ERRDEF( ENOTCONN       , 107, "Transport endpoint is not connected" )
__BIONIC_ERRDEF( ESHUTDOWN      , 108, "Cannot send after transport endpoint shutdown" )
__BIONIC_ERRDEF( ETOOMANYREFS   , 109, "Too many references: cannot splice" )
__BIONIC_ERRDEF( ETIMEDOUT      , 110, "Connection timed out" )
__BIONIC_ERRDEF( ECONNREFUSED   , 111, "Connection refused" )
__BIONIC_ERRDEF( EHOSTDOWN      , 112, "Host is down" )
__BIONIC_ERRDEF( EHOSTUNREACH   , 113, "No route to host" )
__BIONIC_ERRDEF( EALREADY       , 114, "Operation already in progress" )
__BIONIC_ERRDEF( EINPROGRESS    , 115, "Operation now in progress" )
__BIONIC_ERRDEF( ESTALE         , 116, "Stale NFS file handle" )
__BIONIC_ERRDEF( EUCLEAN        , 117, "Structure needs cleaning" )
__BIONIC_ERRDEF( ENOTNAM        , 118, "Not a XENIX named type file" )
__BIONIC_ERRDEF( ENAVAIL        , 119, "No XENIX semaphores available" )
__BIONIC_ERRDEF( EISNAM         , 120, "Is a named type file" )
__BIONIC_ERRDEF( EREMOTEIO      , 121, "Remote I/O error" )
__BIONIC_ERRDEF( EDQUOT         , 122, "Quota exceeded" )
__BIONIC_ERRDEF( ENOMEDIUM      , 123, "No medium found" )
__BIONIC_ERRDEF( EMEDIUMTYPE    , 124, "Wrong medium type" )
__BIONIC_ERRDEF( ECANCELED      , 125, "Operation Canceled" )
__BIONIC_ERRDEF( ENOKEY         , 126, "Required key not available" )
__BIONIC_ERRDEF( EKEYEXPIRED    , 127, "Key has expired" )
__BIONIC_ERRDEF( EKEYREVOKED    , 128, "Key has been revoked" )
__BIONIC_ERRDEF( EKEYREJECTED   , 129, "Key was rejected by service" )
__BIONIC_ERRDEF( EOWNERDEAD     , 130, "Owner died" )
__BIONIC_ERRDEF( ENOTRECOVERABLE, 131, "State not recoverable" )

/* the following is not defined by Linux but needed for the BSD portions of the C library */
__BIONIC_ERRDEF( EFTYPE, 1000, "Stupid C library hack !!" )

#undef __BIONIC_ERRDEF
