LOCAL_PATH:= $(call my-dir)

include $(LOCAL_PATH)/arch-$(TARGET_ARCH)/syscalls.mk

# Define the common source files for all the libc instances
# =========================================================
libc_common_src_files := \
	$(syscall_src) \
	unistd/abort.c \
	unistd/alarm.c \
	unistd/brk.c \
	unistd/creat.c \
	unistd/daemon.c \
	unistd/exec.c \
	unistd/fcntl.c \
	unistd/fnmatch.c \
	unistd/ftime.c \
	unistd/ftok.c \
	unistd/getcwd.c \
	unistd/getdtablesize.c \
	unistd/gethostname.c \
	unistd/getopt_long.c \
	unistd/getpgrp.c \
	unistd/getpriority.c \
	unistd/getpt.c \
	unistd/initgroups.c \
	unistd/isatty.c \
	unistd/issetugid.c \
	unistd/killpg.c \
	unistd/lseek64.c \
	unistd/mmap.c \
	unistd/nice.c \
	unistd/open.c \
	unistd/openat.c \
	unistd/opendir.c \
	unistd/pathconf.c \
	unistd/perror.c \
	unistd/popen.c \
	unistd/pread.c \
	unistd/pselect.c \
	unistd/ptsname.c \
	unistd/ptsname_r.c \
	unistd/pwrite.c \
	unistd/raise.c \
	unistd/reboot.c \
	unistd/recv.c \
	unistd/sbrk.c \
	unistd/send.c \
	unistd/setegid.c \
	unistd/setuid.c \
	unistd/seteuid.c \
	unistd/setreuid.c \
	unistd/setresuid.c \
	unistd/setpgrp.c \
	unistd/sigblock.c \
	unistd/siginterrupt.c \
	unistd/siglist.c \
	unistd/signal.c \
	unistd/signame.c \
	unistd/sigsetmask.c \
	unistd/sigsuspend.c \
	unistd/sigwait.c \
	unistd/sleep.c \
	unistd/statfs.c \
	unistd/strsignal.c \
	unistd/sysconf.c \
	unistd/syslog.c \
	unistd/system.c \
	unistd/tcgetpgrp.c \
	unistd/tcsetpgrp.c \
	unistd/time.c \
	unistd/umount.c \
	unistd/unlockpt.c \
	unistd/usleep.c \
	unistd/wait.c \
	stdio/asprintf.c \
	stdio/clrerr.c \
	stdio/fclose.c \
	stdio/fdopen.c \
	stdio/feof.c \
	stdio/ferror.c \
	stdio/fflush.c \
	stdio/fgetc.c \
	stdio/fgetln.c \
	stdio/fgetpos.c \
	stdio/fgets.c \
	stdio/fileno.c \
	stdio/findfp.c \
	stdio/flags.c \
	stdio/flockfile.c \
	stdio/fopen.c \
	stdio/fprintf.c \
	stdio/fpurge.c \
	stdio/fputc.c \
	stdio/fputs.c \
	stdio/fread.c \
	stdio/freopen.c \
	stdio/fscanf.c \
	stdio/fseek.c \
	stdio/fsetpos.c \
	stdio/ftell.c \
	stdio/funopen.c \
	stdio/fvwrite.c \
	stdio/fwalk.c \
	stdio/fwrite.c \
	stdio/getc.c \
	stdio/getchar.c \
	stdio/gets.c \
	stdio/makebuf.c \
	stdio/mktemp.c \
	stdio/printf.c \
	stdio/putc.c \
	stdio/putchar.c \
	stdio/puts.c \
	stdio/putw.c \
	stdio/refill.c \
	stdio/remove.c \
	stdio/rewind.c \
	stdio/rget.c \
	stdio/scanf.c \
	stdio/setbuf.c \
	stdio/setbuffer.c \
	stdio/setvbuf.c \
	stdio/snprintf.c\
	stdio/sprintf.c \
	stdio/sscanf.c \
	stdio/stdio.c \
	stdio/tempnam.c \
	stdio/tmpfile.c \
	stdio/tmpnam.c \
	stdio/ungetc.c \
	stdio/vasprintf.c \
	stdio/vfprintf.c \
	stdio/vfscanf.c \
	stdio/vprintf.c \
	stdio/vsnprintf.c \
	stdio/vsprintf.c \
	stdio/vscanf.c \
	stdio/vsscanf.c \
	stdio/wbuf.c \
	stdio/wsetup.c \
	stdlib/rand.c \
	stdlib/assert.c \
	stdlib/atexit.c \
	stdlib/atoi.c \
	stdlib/atol.c \
	stdlib/atoll.c \
	stdlib/bsearch.c \
	stdlib/ctype_.c \
	stdlib/div.c \
	stdlib/exit.c \
	stdlib/getenv.c \
	stdlib/ldiv.c \
	stdlib/lldiv.c \
	stdlib/locale.c \
	stdlib/putenv.c \
	stdlib/qsort.c \
	stdlib/setenv.c \
	stdlib/setjmperr.c \
	stdlib/strntoimax.c \
	stdlib/strntoumax.c \
	stdlib/strtod.c \
	stdlib/strtoimax.c \
	stdlib/strtol.c \
	stdlib/strtoll.c \
	stdlib/strtoul.c \
	stdlib/strtoull.c \
	stdlib/strtoumax.c \
	stdlib/tolower_.c \
	stdlib/toupper_.c \
	stdlib/wchar.c \
	string/index.c \
	string/memccpy.c \
	string/memchr.c \
	string/memmem.c \
	string/memrchr.c \
	string/memswap.c \
	string/strcasecmp.c \
	string/strcasestr.c \
	string/strcat.c \
	string/strchr.c \
	string/strcoll.c \
	string/strcpy.c \
	string/strcspn.c \
	string/strdup.c \
	string/strerror.c \
	string/strerror_r.c \
	string/strlcat.c \
	string/strlcpy.c \
	string/strncat.c \
	string/strncpy.c \
	string/strndup.c \
	string/strnlen.c \
	string/strpbrk.c \
	string/strrchr.c \
	string/strsep.c \
	string/strspn.c \
	string/strstr.c \
	string/strtok.c \
	string/strtotimeval.c \
	string/strxfrm.c \
	inet/bindresvport.c \
	inet/inet_addr.c \
	inet/inet_aton.c \
	inet/inet_ntoa.c \
	inet/inet_ntop.c \
	inet/inet_pton.c \
	inet/ether_aton.c \
	inet/ether_ntoa.c \
	tzcode/asctime.c \
	tzcode/difftime.c \
	tzcode/localtime.c \
	tzcode/strftime.c \
	tzcode/strptime.c \
	bionic/__errno.c \
	bionic/__set_errno.c \
	bionic/cpuacct.c \
	bionic/arc4random.c \
	bionic/basename.c \
	bionic/basename_r.c \
	bionic/clearenv.c \
	bionic/dirname.c \
	bionic/dirname_r.c \
	bionic/err.c \
	bionic/fdprintf.c \
	bionic/fork.c \
	bionic/fts.c \
	bionic/if_nametoindex.c \
	bionic/if_indextoname.c \
	bionic/ioctl.c \
	bionic/ldexp.c \
	bionic/libc_init_common.c \
	bionic/logd_write.c \
	bionic/md5.c \
	bionic/pututline.c \
	bionic/realpath.c \
	bionic/semaphore.c \
	bionic/sha1.c \
	bionic/ssp.c \
	bionic/stubs.c \
	bionic/system_properties.c \
	bionic/time64.c \
	bionic/thread_atexit.c \
	bionic/utime.c \
	bionic/utmp.c \
	netbsd/gethnamaddr.c \
	netbsd/isc/ev_timers.c \
	netbsd/isc/ev_streams.c \
	netbsd/inet/nsap_addr.c \
	netbsd/resolv/__dn_comp.c \
	netbsd/resolv/__res_close.c \
	netbsd/resolv/__res_send.c \
	netbsd/resolv/herror.c \
	netbsd/resolv/res_comp.c \
	netbsd/resolv/res_data.c \
	netbsd/resolv/res_debug.c \
	netbsd/resolv/res_init.c \
	netbsd/resolv/res_mkquery.c \
	netbsd/resolv/res_query.c \
	netbsd/resolv/res_send.c \
	netbsd/resolv/res_state.c \
	netbsd/resolv/res_cache.c \
	netbsd/net/nsdispatch.c \
	netbsd/net/getaddrinfo.c \
	netbsd/net/getnameinfo.c \
	netbsd/net/getservbyname.c \
	netbsd/net/getservent.c \
	netbsd/net/base64.c \
	netbsd/net/getservbyport.c \
	netbsd/nameser/ns_name.c \
	netbsd/nameser/ns_parse.c \
	netbsd/nameser/ns_ttl.c \
	netbsd/nameser/ns_netint.c \
	netbsd/nameser/ns_print.c \
	netbsd/nameser/ns_samedomain.c \
	regex/regcomp.c \
	regex/regerror.c \
	regex/regexec.c \
	regex/regfree.c \

# Architecture specific source files go here
# =========================================================
ifeq ($(TARGET_ARCH),arm)
libc_common_src_files += \
	bionic/bionic_clone.c \
	arch-arm/bionic/__get_pc.S \
	arch-arm/bionic/__get_sp.S \
	arch-arm/bionic/_exit_with_stack_teardown.S \
	arch-arm/bionic/_setjmp.S \
	arch-arm/bionic/atomics_arm.S \
	arch-arm/bionic/clone.S \
	arch-arm/bionic/eabi.c \
	arch-arm/bionic/ffs.S \
	arch-arm/bionic/kill.S \
	arch-arm/bionic/libgcc_compat.c \
	arch-arm/bionic/tkill.S \
	arch-arm/bionic/memcmp.S \
	arch-arm/bionic/memcmp16.S \
	arch-arm/bionic/memcpy.S \
	arch-arm/bionic/memset.S \
	arch-arm/bionic/setjmp.S \
	arch-arm/bionic/sigsetjmp.S \
	arch-arm/bionic/strlen.c.arm \
	arch-arm/bionic/syscall.S \
	arch-arm/bionic/sigaction.c \
	arch-arm/bionic/__sig_restorer.S \
	string/memmove.c.arm \
	string/bcopy.c \
	string/strcmp.c \
	string/strncmp.c \
	unistd/socketcalls.c

# These files need to be arm so that gdbserver
# can set breakpoints in them without messing
# up any thumb code.
libc_common_src_files += \
	bionic/pthread.c.arm \
	bionic/pthread-atfork.c.arm \
	bionic/pthread-timers.c.arm \
	bionic/ptrace.c.arm

# these are used by the static and dynamic versions of the libc
# respectively
libc_arch_static_src_files := \
	arch-arm/bionic/exidx_static.c

libc_arch_dynamic_src_files := \
	arch-arm/bionic/exidx_dynamic.c
else # !arm

ifeq ($(TARGET_ARCH),x86)
libc_common_src_files += \
	arch-x86/bionic/__get_sp.S \
	arch-x86/bionic/__get_tls.c \
	arch-x86/bionic/__set_tls.c \
	arch-x86/bionic/atomics_x86.S \
	arch-x86/bionic/clone.S \
	arch-x86/bionic/_exit_with_stack_teardown.S \
	arch-x86/bionic/setjmp.S \
	arch-x86/bionic/_setjmp.S \
	arch-x86/bionic/vfork.S \
	arch-x86/bionic/syscall.S \
	arch-x86/string/bcopy_wrapper.S \
	arch-x86/string/memcpy_wrapper.S \
	arch-x86/string/memmove_wrapper.S \
	arch-x86/string/bzero_wrapper.S \
	arch-x86/string/memcmp_wrapper.S \
	arch-x86/string/memset_wrapper.S \
	arch-x86/string/strcmp_wrapper.S \
	arch-x86/string/strncmp_wrapper.S \
	arch-x86/string/strlen.S \
	bionic/pthread.c \
	bionic/pthread-atfork.c \
	bionic/pthread-timers.c \
	bionic/ptrace.c

# this is needed for static versions of libc
libc_arch_static_src_files := \
	arch-x86/bionic/dl_iterate_phdr_static.c

libc_arch_dynamic_src_files :=
else # !x86

ifeq ($(TARGET_ARCH),sh)
libc_common_src_files += \
	arch-sh/bionic/__get_pc.S \
	arch-sh/bionic/__get_sp.S \
	arch-sh/bionic/_exit_with_stack_teardown.S \
	arch-sh/bionic/_setjmp.S \
	arch-sh/bionic/atomics_sh.c \
	arch-sh/bionic/atomic_cmpxchg.S \
	arch-sh/bionic/clone.S \
	arch-sh/bionic/pipe.S \
	arch-sh/bionic/memcpy.S \
	arch-sh/bionic/memset.S \
	arch-sh/bionic/bzero.S \
	arch-sh/bionic/setjmp.S \
	arch-sh/bionic/sigsetjmp.S \
	arch-sh/bionic/syscall.S \
	arch-sh/bionic/memmove.S \
	arch-sh/bionic/__set_tls.c \
	arch-sh/bionic/__get_tls.c \
	arch-sh/bionic/ffs.S \
	string/bcopy.c \
	string/strcmp.c \
	string/strncmp.c \
	string/memcmp.c \
	string/strlen.c \
	bionic/pthread.c \
	bionic/pthread-atfork.c \
	bionic/pthread-timers.c \
	bionic/ptrace.c \
	unistd/socketcalls.c
endif # sh

endif # !x86
endif # !arm

# Define some common cflags
# ========================================================
libc_common_cflags := \
		-DWITH_ERRLIST			\
		-DANDROID_CHANGES		\
		-DUSE_LOCKS 			\
		-DREALLOC_ZERO_BYTES_FREES 	\
		-D_LIBC=1 			\
		-DSOFTFLOAT                     \
		-DFLOATING_POINT		\
		-DNEED_PSELECT=1		\
		-DINET6 \
		-I$(LOCAL_PATH)/private \
		-DUSE_DL_PREFIX \
		-DPOSIX_MISTAKE

# these macro definitions are required to implement the
# 'timezone' and 'daylight' global variables, as well as
# properly update the 'tm_gmtoff' field in 'struct tm'.
#
libc_common_cflags += \
    -DTM_GMTOFF=tm_gmtoff \
    -DUSG_COMPAT=1

ifeq ($(strip $(DEBUG_BIONIC_LIBC)),true)
  libc_common_cflags += -DDEBUG
endif

ifeq ($(TARGET_ARCH),arm)
  libc_common_cflags += -fstrict-aliasing
  libc_crt_target_cflags := -mthumb-interwork
  #
  # Define HAVE_ARM_TLS_REGISTER macro to indicate to the C library
  # that it should access the hardware TLS register directly in
  # private/bionic_tls.h
  #
  # The value must match your kernel configuration
  #
  ifeq ($(ARCH_ARM_HAVE_TLS_REGISTER),true)
    libc_common_cflags += -DHAVE_ARM_TLS_REGISTER
  endif
else # !arm
  ifeq ($(TARGET_ARCH),x86)
    libc_crt_target_cflags := -m32

    # Enable recent IA friendly memory routines (such as for Atom)
    # These will not work on the earlier x86 machines
    #libc_common_cflags += -mtune=i686 -DUSE_SSSE3 -DUSE_SSE2

	# egypt: compile for 386 so meterpreter will have a chance of working on
	# older processors
    libc_common_cflags += -march=i386
  endif # x86
endif # !arm

# Define some common includes
# ========================================================
libc_common_c_includes := \
		$(LOCAL_PATH)/stdlib  \
		$(LOCAL_PATH)/string  \
		$(LOCAL_PATH)/stdio

# Needed to access private/__dso_handle.S from
# crtbegin_xxx.S and crtend_xxx.S
#
libc_crt_target_cflags += -I$(LOCAL_PATH)/private

# Define the libc run-time (crt) support object files that must be built,
# which are needed to build all other objects (shared/static libs and
# executables)
# ==========================================================================

ifneq ($(filter arm x86,$(TARGET_ARCH)),)
# ARM and x86 need crtbegin_so/crtend_so.
#
# For x86, the .init section must point to a function that calls all
# entries in the .ctors section. (on ARM this is done through the
# .init_array section instead).
#
# For both platforms, the .fini_array section must point to a function
# that will call __cxa_finalize(&__dso_handle) in order to ensure that
# static C++ destructors are properly called on dlclose().
#
GEN := $(TARGET_OUT_STATIC_LIBRARIES)/crtbegin_so.o
$(GEN): $(LOCAL_PATH)/arch-$(TARGET_ARCH)/bionic/crtbegin_so.S
	@mkdir -p $(dir $@)
	$(TARGET_CC) $(libc_crt_target_cflags) -o $@ -c $<
ALL_GENERATED_SOURCES += $(GEN)

GEN := $(TARGET_OUT_STATIC_LIBRARIES)/crtend_so.o
$(GEN): $(LOCAL_PATH)/arch-$(TARGET_ARCH)/bionic/crtend_so.S
	@mkdir -p $(dir $@)
	$(TARGET_CC) $(libc_crt_target_cflags) -o $@ -c $<
ALL_GENERATED_SOURCES += $(GEN)
endif # TARGET_ARCH == x86


GEN := $(TARGET_OUT_STATIC_LIBRARIES)/crtbegin_static.o
$(GEN): $(LOCAL_PATH)/arch-$(TARGET_ARCH)/bionic/crtbegin_static.S
	@mkdir -p $(dir $@)
	$(TARGET_CC) $(libc_crt_target_cflags) -o $@ -c $<
ALL_GENERATED_SOURCES += $(GEN)

GEN := $(TARGET_OUT_STATIC_LIBRARIES)/crtbegin_dynamic.o
$(GEN): $(LOCAL_PATH)/arch-$(TARGET_ARCH)/bionic/crtbegin_dynamic.S
	@mkdir -p $(dir $@)
	$(TARGET_CC) $(libc_crt_target_cflags) -o $@ -c $<
ALL_GENERATED_SOURCES += $(GEN)


# We rename crtend.o to crtend_android.o to avoid a
# name clash between gcc and bionic.
GEN := $(TARGET_OUT_STATIC_LIBRARIES)/crtend_android.o
$(GEN): $(LOCAL_PATH)/arch-$(TARGET_ARCH)/bionic/crtend.S
	@mkdir -p $(dir $@)
	$(TARGET_CC) $(libc_crt_target_cflags) -o $@ -c $<
ALL_GENERATED_SOURCES += $(GEN)


# To enable malloc leak check for statically linked programs, add
# "WITH_MALLOC_CHECK_LIBC_A := true" to buildspec.mk
WITH_MALLOC_CHECK_LIBC_A := $(strip $(WITH_MALLOC_CHECK_LIBC_A))

# ========================================================
# libc_common.a
# ========================================================
include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(libc_common_src_files)
LOCAL_CFLAGS := $(libc_common_cflags)
LOCAL_C_INCLUDES := $(libc_common_c_includes)
LOCAL_MODULE := libc_common
LOCAL_SYSTEM_SHARED_LIBRARIES :=

include $(BUILD_STATIC_LIBRARY)


# ========================================================
# libc_nomalloc.a
# ========================================================
#
# This is a version of the static C library that does not
# include malloc. It's useful in situations when calling
# the user wants to provide their own malloc implementation,
# or wants to explicitly disallow the use of the use of malloc,
# like the dynamic loader.

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	$(libc_arch_static_src_files) \
	bionic/libc_init_static.c

LOCAL_C_INCLUDES := $(libc_common_c_includes)
LOCAL_CFLAGS := $(libc_common_cflags)

LOCAL_MODULE := libc_nomalloc
LOCAL_WHOLE_STATIC_LIBRARIES := libc_common
LOCAL_SYSTEM_SHARED_LIBRARIES :=

include $(BUILD_STATIC_LIBRARY)


# ========================================================
# libc.a
# ========================================================
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	$(libc_arch_static_src_files) \
	bionic/dlmalloc.c \
	bionic/malloc_debug_common.c \
	bionic/libc_init_static.c

LOCAL_CFLAGS := $(libc_common_cflags) \
                -DLIBC_STATIC
LOCAL_C_INCLUDES := $(libc_common_c_includes)
LOCAL_MODULE := libc
LOCAL_WHOLE_STATIC_LIBRARIES := libc_common
LOCAL_SYSTEM_SHARED_LIBRARIES :=

include $(BUILD_STATIC_LIBRARY)


# ========================================================
# libc.so
# ========================================================
include $(CLEAR_VARS)

LOCAL_CFLAGS := $(libc_common_cflags)
LOCAL_C_INCLUDES := $(libc_common_c_includes)

LOCAL_SRC_FILES := \
	$(libc_arch_dynamic_src_files) \
	bionic/dlmalloc.c \
	bionic/malloc_debug_common.c \
	bionic/libc_init_dynamic.c

LOCAL_MODULE:= libc

# WARNING: The only library libc.so should depend on is libdl.so!  If you add other libraries,
# make sure to add -Wl,--exclude-libs=libgcc.a to the LOCAL_LDFLAGS for those libraries.  This
# ensures that symbols that are pulled into those new libraries from libgcc.a are not declared
# external; if that were the case, then libc would not pull those symbols from libgcc.a as it
# should, instead relying on the external symbols from the dependent libraries.  That would
# create an "cloaked" dependency on libgcc.a in libc though the libraries, which is not what
# you wanted!

LOCAL_SHARED_LIBRARIES := libdl
LOCAL_WHOLE_STATIC_LIBRARIES := libc_common
LOCAL_SYSTEM_SHARED_LIBRARIES :=

include $(BUILD_SHARED_LIBRARY)


# For all builds, except for the -user build we will enable memory
# allocation checking (including memory leaks, buffer overwrites, etc.)
# Note that all these checks are also controlled by env. settings
# that can enable, or disable specific checks. Note also that some of
# the checks are available only in emulator and are implemeted in
# libc_malloc_qemu_instrumented.so.
ifneq ($(TARGET_BUILD_VARIANT),user)

# ========================================================
# libc_malloc_debug_leak.so
# ========================================================
include $(CLEAR_VARS)

LOCAL_CFLAGS := \
	$(libc_common_cflags) \
	-DMALLOC_LEAK_CHECK

LOCAL_C_INCLUDES := $(libc_common_c_includes)

LOCAL_SRC_FILES := \
	bionic/malloc_debug_leak.c

LOCAL_MODULE:= libc_malloc_debug_leak

LOCAL_SHARED_LIBRARIES := libc
LOCAL_WHOLE_STATIC_LIBRARIES := libc_common
LOCAL_SYSTEM_SHARED_LIBRARIES :=
LOCAL_ALLOW_UNDEFINED_SYMBOLS := true
# Don't prelink
LOCAL_PRELINK_MODULE := false
# Don't install on release build
LOCAL_MODULE_TAGS := eng debug

include $(BUILD_SHARED_LIBRARY)


# ========================================================
# libc_malloc_debug_qemu.so
# ========================================================
include $(CLEAR_VARS)

LOCAL_CFLAGS := \
	$(libc_common_cflags) \
	-DMALLOC_QEMU_INSTRUMENT

LOCAL_C_INCLUDES := $(libc_common_c_includes)

LOCAL_SRC_FILES := \
	bionic/malloc_debug_qemu.c

LOCAL_MODULE:= libc_malloc_debug_qemu

LOCAL_SHARED_LIBRARIES := libc
LOCAL_WHOLE_STATIC_LIBRARIES := libc_common
LOCAL_SYSTEM_SHARED_LIBRARIES :=
# Don't prelink
LOCAL_PRELINK_MODULE := false
# Don't install on release build
LOCAL_MODULE_TAGS := eng debug

include $(BUILD_SHARED_LIBRARY)

endif	#!user


# ========================================================
include $(call all-makefiles-under,$(LOCAL_PATH))
