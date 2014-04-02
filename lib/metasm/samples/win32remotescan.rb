#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# here we compile and inject a C stub into a running process
# the sample stub will scan the whole process memory for a 32bit value (aligned)
# and report the results using MessageBox
#
# This shows how to mix C and asm, and a few WinOS functions.

require 'metasm'

include Metasm

abort 'usage: scan <targetprocess> <value>' if ARGV.length != 2
targetproc = ARGV.shift
searchval = Integer(ARGV.shift)

raise 'cannot find target' if not target = WinOS.find_process(targetproc)

sc = Shellcode.compile_c(Ia32.new, <<'EOC')
asm {
sc_start:
xor edi, edi
mov ebp, edi	// ebp = match count
push fs:[edi]	// backup UEH
call setup_ueh

// our UEH: edi += 4k, check for end of addrspace
ueh:
mov eax, [esp+0ch]
add eax, 7ch		// optimize code size
add dword ptr [eax+21h], 10h	// ctx[edi] += 4k
cmp word ptr [eax+22h], -1
jb ueh_retloc

call ueh_endloop	// ctx[eip] = &jmp walk_loop_end
jmp walk_loop_end
ueh_endloop:
pop dword ptr [eax+3ch]

ueh_retloc:
xor eax, eax
ret			// UEH: return(CONTINUE)
// end of UEH

setup_ueh:
push -1
mov fs:[edi], esp
mov eax, SEARCHEDVALUE

walk_loop_next:
cmp edi, 0xffff_fff0
jae walk_loop_end
scasd
jnz walk_loop_next

found:
call found_value

jmp walk_loop_next

walk_loop_end:
pop eax
pop ebx
inc eax
pop dword ptr fs:[eax]

call metasm_intern_geteip
mov [eax+matchcount-metasm_intern_geteip], ebp

call scan_finished

// virtualfree shellcode & exitthread
push 8000h	// type = MEM_RELEASE
push 0		// size = 0
call end_getaddr	// addr = sc_start
end_getaddr:
add dword ptr [esp], end_getaddr - sc_start
push ExitThread
jmp VirtualFree
// end of main


// found new match at edi
found_value:
push eax
cmp ebp, 1024
jae skipsave
call metasm_intern_geteip
add eax, table - metasm_intern_geteip
sub edi, 4
mov dword ptr [eax+4*ebp], edi
add edi, 4
inc ebp
skipsave:
pop eax
mov dword ptr [esp-4], 0	// hide the searched value from our stack
ret

}

__declspec(stdcall) void MessageBoxA(int, char*, char*, int);
int wsprintfA(char *buf, char *fmt, ...);

unsigned long table[1024];
unsigned long matchcount;
char outbuf[4096];

void scan_finished(void)
{
  int off = 0;
  int i;

  off += wsprintfA(outbuf+off, "Found %d matches: ", matchcount);
  for (i=0 ; i<matchcount ; i++) {
    if (off > sizeof(outbuf)-20)
      break;
    off += wsprintfA(outbuf+off, "%X, ", table[i]);
  }
  outbuf[off-2] = '.';
  outbuf[off-1] = 0;

  MessageBoxA(0, outbuf, "search finished", 0);
}
EOC

sc = sc.encoded

sc.fixup! 'SEARCHEDVALUE' => searchval

WinOS.inject_run_shellcode(target, sc)
