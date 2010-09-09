#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# This creates/uses a ring0 driver for tracing a program
# x86/windows/singlecore only
# the scripts allows interacting with the driver
# you still have to set the target thread in singlestep mode (eg using Debugger)

# How does it work:
# the driver hooks the IDT int1/int0f (NOT SMP PROOF)
# on int1, it logs eip in a memory buffer
# on int0f, it returns the memory buffer (memcopy to mem pointed by eax)
# the buffer 1st dword is the number of used dwords in the buffer (0 = empty)
# on overflow, eips are lost

require 'metasm'
include Metasm

$drv = 'r0trace.sys'
# size of the eip buffer (in dwords)
TRACE_BUF_SZ = 4*1024*1024-4
if not File.exist? $drv
PE.assemble(Ia32.new, <<EOS).encode_file($drv, 'kmod')
#define bufsz #{TRACE_BUF_SZ}

.data
oldi1 dd 0,0
oldi15 dd 0,0
buf dd bufsz dup(?)

.text
.entrypoint
mov eax, [esp+4]
mov dword ptr [eax+0x34], unload	// drv->DriverUnload
call setup_idt
xor eax, eax
mov [buf], eax	// buf used size
ret

unload:
// XXX smp
call get_idt
push [oldi1+4]
push [oldi1]
pop [eax+8*1]
pop [eax+8*1+4]
push [oldi15+4]
push [oldi15]
pop [eax+8*15]
pop [eax+8*15+4]
xor eax, eax
ret

setup_idt:
// XXX smp
call get_idt
push [eax+8*1]
push [eax+8*1+4]
pop [oldi1+4]
pop [oldi1]
push [eax+8*15]
push [eax+8*15+4]
pop [oldi15+4]
pop [oldi15]

mov ecx, i1hook
mov [eax+8*1], ecx
mov [eax+8*1+4], ecx
mov ecx, cs
mov [eax+8*1+2], cx
mov word ptr [eax+8*1+4], (15 + (3<<5) + (1<<7)) << 8	// call gate

mov ecx, i15hook
mov [eax+8*15], ecx
mov [eax+8*15+4], ecx
mov ecx, cs
mov [eax+8*15+2], cx
mov word ptr [eax+8*15+4], (15 + (3<<5) + (1<<7)) << 8	// call gate
ret

get_idt:
sub esp, 8
sidt [esp]
mov eax, [esp+2]
add esp, 8
ret

i1hook:
push eax
mov eax, buf
cmp [eax], bufsz
jae 1f
inc [eax]
add eax, [eax]
push [esp+4]
pop [eax]
1:
pop eax
iret

i15hook:
push esi
push edi
push ecx
mov esi, buf
mov edi, eax
mov ecx, [esi]
inc ecx
rep movsd
mov dword ptr [buf], 0
pop ecx
pop edi
pop esi
iret
EOS
end

DynLdr.new_api_c <<EOS
typedef int BOOL;
typedef char CHAR;
typedef unsigned long DWORD;
typedef const CHAR *LPCSTR;
typedef DWORD *LPDWORD;
typedef void *HANDLE;
struct SC_HANDLE__ { int unused; };
struct _SERVICE_STATUS {
	DWORD dwServiceType;
	DWORD dwCurrentState;
	DWORD dwControlsAccepted;
	DWORD dwWin32ExitCode;
	DWORD dwServiceSpecificExitCode;
	DWORD dwCheckPoint;
	DWORD dwWaitHint;
};
typedef struct SC_HANDLE__ *SC_HANDLE;
typedef struct _SERVICE_STATUS *LPSERVICE_STATUS;

__stdcall BOOL CloseServiceHandle(SC_HANDLE hSCObject __attribute__((in)));
__stdcall SC_HANDLE CreateServiceA(SC_HANDLE hSCManager __attribute__((in)), LPCSTR lpServiceName __attribute__((in)), LPCSTR lpDisplayName __attribute__((in)), DWORD dwDesiredAccess __attribute__((in)), DWORD dwServiceType __attribute__((in)), DWORD dwStartType __attribute__((in)), DWORD dwErrorControl __attribute__((in)), LPCSTR lpBinaryPathName __attribute__((in)), LPCSTR lpLoadOrderGroup __attribute__((in)), LPDWORD lpdwTagId __attribute__((out)), LPCSTR lpDependencies __attribute__((in)), LPCSTR lpServiceStartName __attribute__((in)), LPCSTR lpPassword __attribute__((in)));
__stdcall BOOL DeleteService(SC_HANDLE hService __attribute__((in)));
__stdcall SC_HANDLE OpenSCManagerA(LPCSTR lpMachineName __attribute__((in)), LPCSTR lpDatabaseName __attribute__((in)), DWORD dwDesiredAccess __attribute__((in)));
__stdcall SC_HANDLE OpenServiceA(SC_HANDLE hSCManager __attribute__((in)), LPCSTR lpServiceName __attribute__((in)), DWORD dwDesiredAccess __attribute__((in)));
__stdcall BOOL StartServiceA(SC_HANDLE hService __attribute__((in)), DWORD dwNumServiceArgs __attribute__((in)), LPCSTR *lpServiceArgVectors __attribute__((in)));
__stdcall BOOL ControlService(SC_HANDLE hService __attribute__((in)), DWORD dwControl __attribute__((in)), LPSERVICE_STATUS lpServiceStatus __attribute__((out)));

__stdcall HANDLE OpenThread(DWORD dwDesiredAccess __attribute__((in)), BOOL bInheritHandle __attribute__((in)), DWORD dwThreadId __attribute__((in)));
__stdcall DWORD ResumeThread(HANDLE hThread __attribute__((in)));
__stdcall DWORD SuspendThread(HANDLE hThread __attribute__((in)));
__stdcall BOOL SetThreadContext(HANDLE hThread __attribute__((in)), void *lpContext __attribute__((in)));
__stdcall BOOL GetThreadContext(HANDLE hThread __attribute__((in)), void *lpContext);
__stdcall BOOL CloseHandle(HANDLE hObject __attribute__((in)));



#define STANDARD_RIGHTS_REQUIRED         (0x000F0000L)

#define SC_MANAGER_CONNECT             0x0001
#define SC_MANAGER_CREATE_SERVICE      0x0002
#define SC_MANAGER_ENUMERATE_SERVICE   0x0004
#define SC_MANAGER_LOCK                0x0008
#define SC_MANAGER_QUERY_LOCK_STATUS   0x0010
#define SC_MANAGER_MODIFY_BOOT_CONFIG  0x0020
#define SC_MANAGER_ALL_ACCESS          (STANDARD_RIGHTS_REQUIRED      | \
                                        SC_MANAGER_CONNECT            | \
                                        SC_MANAGER_CREATE_SERVICE     | \
                                        SC_MANAGER_ENUMERATE_SERVICE  | \
                                        SC_MANAGER_LOCK               | \
                                        SC_MANAGER_QUERY_LOCK_STATUS  | \
                                        SC_MANAGER_MODIFY_BOOT_CONFIG)

#define SERVICE_QUERY_CONFIG           0x0001
#define SERVICE_CHANGE_CONFIG          0x0002
#define SERVICE_QUERY_STATUS           0x0004
#define SERVICE_ENUMERATE_DEPENDENTS   0x0008
#define SERVICE_START                  0x0010
#define SERVICE_STOP                   0x0020
#define SERVICE_PAUSE_CONTINUE         0x0040
#define SERVICE_INTERROGATE            0x0080
#define SERVICE_USER_DEFINED_CONTROL   0x0100
#define SERVICE_ALL_ACCESS             (STANDARD_RIGHTS_REQUIRED     | \
                                        SERVICE_QUERY_CONFIG         | \
                                        SERVICE_CHANGE_CONFIG        | \
                                        SERVICE_QUERY_STATUS         | \
                                        SERVICE_ENUMERATE_DEPENDENTS | \
                                        SERVICE_START                | \
                                        SERVICE_STOP                 | \
                                        SERVICE_PAUSE_CONTINUE       | \
                                        SERVICE_INTERROGATE          | \
                                        SERVICE_USER_DEFINED_CONTROL)

#define SERVICE_KERNEL_DRIVER          0x00000001
#define SERVICE_FILE_SYSTEM_DRIVER     0x00000002
#define SERVICE_ADAPTER                0x00000004
#define SERVICE_RECOGNIZER_DRIVER      0x00000008
#define SERVICE_DRIVER                 (SERVICE_KERNEL_DRIVER | \
                                        SERVICE_FILE_SYSTEM_DRIVER | \
                                        SERVICE_RECOGNIZER_DRIVER)
#define SERVICE_WIN32_OWN_PROCESS      0x00000010
#define SERVICE_WIN32_SHARE_PROCESS    0x00000020
#define SERVICE_WIN32                  (SERVICE_WIN32_OWN_PROCESS | \
                                        SERVICE_WIN32_SHARE_PROCESS)
#define SERVICE_INTERACTIVE_PROCESS    0x00000100
#define SERVICE_TYPE_ALL               (SERVICE_WIN32  | \
                                        SERVICE_ADAPTER | \
                                        SERVICE_DRIVER  | \
                                        SERVICE_INTERACTIVE_PROCESS)

#define SERVICE_BOOT_START             0x00000000
#define SERVICE_SYSTEM_START           0x00000001
#define SERVICE_AUTO_START             0x00000002
#define SERVICE_DEMAND_START           0x00000003
#define SERVICE_DISABLED               0x00000004

#define SERVICE_ERROR_IGNORE           0x00000000
#define SERVICE_ERROR_NORMAL           0x00000001
#define SERVICE_ERROR_SEVERE           0x00000002
#define SERVICE_ERROR_CRITICAL         0x00000003

#define SYNCHRONIZE                    0x00100000L
#define THREAD_TERMINATE               0x0001
#define THREAD_SUSPEND_RESUME          0x0002
#define THREAD_GET_CONTEXT             0x0008
#define THREAD_SET_CONTEXT             0x0010
#define THREAD_SET_INFORMATION         0x0020
#define THREAD_QUERY_INFORMATION       0x0040
#define THREAD_SET_THREAD_TOKEN        0x0080
#define THREAD_IMPERSONATE             0x0100
#define THREAD_DIRECT_IMPERSONATION    0x0200
#define THREAD_ALL_ACCESS         (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3FF)

#define CONTEXT_i386    0x00010000
#define CONTEXT_CONTROL         (CONTEXT_i386 | 0x00000001L) // SS:SP, CS:IP, FLAGS, BP
#define CONTEXT_INTEGER         (CONTEXT_i386 | 0x00000002L) // AX, BX, CX, DX, SI, DI
#define CONTEXT_SEGMENTS        (CONTEXT_i386 | 0x00000004L) // DS, ES, FS, GS
#define CONTEXT_FLOATING_POINT  (CONTEXT_i386 | 0x00000008L) // 387 state
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_i386 | 0x00000010L) // DB 0-3,6,7
#define CONTEXT_EXTENDED_REGISTERS  (CONTEXT_i386 | 0x00000020L) // cpu specific extensions
#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS)
#define CONTEXT_ALL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS)
EOS

DynLdr.new_func_c <<EOS
int get_trace_buf(void *ptr)
{
	asm("mov eax, [ebp+8] int 0fh");
	return *(int*)ptr;
}
EOS

def loadmod(mod=$drv)
	sh = DynLdr.openscmanagera(0, 0, DynLdr::SC_MANAGER_ALL_ACCESS)
	raise "cannot openscm" if (sh == 0)
	rh = DynLdr.createservicea(sh, mod, mod, DynLdr::SERVICE_ALL_ACCESS, DynLdr::SERVICE_KERNEL_DRIVER, DynLdr::SERVICE_DEMAND_START, DynLdr::SERVICE_ERROR_NORMAL, File.expand_path(mod), 0, 0, 0, 0, 0)
	if (DynLdr.startservicea(rh, 0, 0) == 0)
		raise "cannot start service"
	end
	DynLdr.CloseServiceHandle(rh)
	DynLdr.CloseServiceHandle(sh)
end

def unloadmod(mod=$drv)
	sh = DynLdr.openscmanagera(0, 0, DynLdr::SC_MANAGER_ALL_ACCESS)
	raise "cannot openscm" if (sh == 0)
	rh = DynLdr.openservicea(sh, mod, DynLdr::SERVICE_ALL_ACCESS)
	DynLdr.controlservice(rh, DynLdr::SERVICE_CONTROL_STOP, 0.chr*4*32)
	DynLdr.deleteservice(rh)
	DynLdr.CloseServiceHandle(rh)
	DynLdr.CloseServiceHandle(sh)
end

def trace(tid, delay=1)
	# put thread in singlestep mode
	th = DynLdr.openthread(DynLdr::THREAD_GET_CONTEXT | DynLdr::THREAD_SET_CONTEXT | DynLdr::THREAD_SUSPEND_RESUME, 0, tid)
	raise "openthread" if (th == 0)
	DynLdr.suspendthread(th)
	ctx = 0.chr * 1024
	ctx[0, 4] = [DynLdr::CONTEXT_CONTROL].pack('V')
	DynLdr.getthreadcontext(th, ctx)
	ctx[192, 4] = [ctx[192, 4].unpack('V').first | (1 << 8)].pack('V')
	DynLdr.setthreadcontext(th, ctx)
	DynLdr.resumethread(th)
	DynLdr.closehandle(th)

	
	buf = 0.chr * 4 * TRACE_BUF_SZ
	loop do
		sleep delay.to_f
		nr = DynLdr.get_trace_buf(buf)
		puts "got #{'%x' % nr} instrs"
		# eips = buf[4, 4*nr].unpack('V*')
	end

ensure
	th = DynLdr.openthread(DynLdr::THREAD_GET_CONTEXT | DynLdr::THREAD_SET_CONTEXT | DynLdr::THREAD_SUSPEND_RESUME, 0, tid)
	if (th != 0)
		DynLdr.suspendthread(th)
		ctx = 0.chr * 1024
		ctx[0, 4] = [DynLdr::CONTEXT_CONTROL].pack('V')
		DynLdr.getthreadcontext(th, ctx)
		ctx[192, 4] = [ctx[192, 4].unpack('V').first & ~(1 << 8)].pack('V')
		DynLdr.setthreadcontext(th, ctx)
		DynLdr.resumethread(th)
		DynLdr.closehandle(th)
	end
end

if $0 == __FILE__
	case ARGV.shift
	when /unload/; unloadmod(*ARGV)
	when /load/; loadmod(*ARGV)
	when /trace/; trace(*ARGV)
	end
end
