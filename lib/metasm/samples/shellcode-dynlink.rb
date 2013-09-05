#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# this script compiles a source file (asm or C) into a shellcode that will
# dynamically resolve the address of functions it uses
# windows only, supposes the shellcode is run in the address space of a process
# whose PEB allows to find all required libraries.

require 'metasm'

sc = Metasm::Shellcode.new(Metasm::Ia32.new)

case ARGV[0]
when /\.c(pp)?$/i
 	src_c = File.read(ARGV[0])
  sc.assemble 'jmp main'
  sc.compile_c src_c
when /\.asm$/i
  src = File.read(ARGV[0])
  sc.assemble src
when nil; abort "need sourcefile"
else abort "unknown srcfile extension"
end

# find external symbols needed by the shellcode
ext_syms = sc.encoded.reloc_externals

# resolver code
sc.parse <<EOS
get_libbase:
  mov eax, fs:[0x30]	// peb
  mov eax, [eax+12]	// peb_ldr
  add eax, 12		// &inloadorder
libbase_loop:
  mov eax, [eax]		// next
  mov edx, [eax+12*4]	// basename ptr
  mov cl, [edx+6]
  shl ecx, 8
  mov cl, [edx+4]
  shl ecx, 8
  mov cl, [edx+2]
  shl ecx, 8
  mov cl, [edx]
  or ecx, 0x20202020	// downcase
  cmp ecx, [esp+4]
  jnz libbase_loop
  mov eax, [eax+6*4]	// baseaddr
  ret 4

hash_name:
  push ecx
  push edx
  xor eax, eax
  xor ecx, ecx
  mov edx, [esp+12]
  dec edx
hash_loop:
  ror eax, 0dh
  add eax, ecx
  inc edx
  mov cl, [edx]
  test cl, cl
  jnz hash_loop
  pop edx
  pop ecx
  ret 4

resolve_proc:
  push ecx
  push edx
  push ebp
  push dword ptr [esp+0x14]	// arg_2
  call get_libbase
  mov ebp, eax		// imagebase
  add eax, [eax+0x3c]	// coffhdr
  mov edx, [eax+0x78]	// exportdirectory
  add edx, ebp
  or ecx, -1
resolve_loop:
  inc ecx
  mov eax, [edx+0x20]	// name
  add eax, ebp
  mov eax, [eax+4*ecx]
  add eax, ebp
  push eax
  call hash_name
  cmp eax, [esp+0x10]	// cmp hash(name[i]), arg_1
  jnz resolve_loop
  mov eax, [edx+0x24]	// ord
  add eax, ebp
  movzx ecx, word ptr [eax+2*ecx]
  mov eax, [edx+0x1c]	// func
  add eax, ebp
  mov eax, [eax+4*ecx]	// func[ord[i]]
  add eax, ebp
  pop ebp
  pop edx
  pop ecx
  ret 8
EOS

def hash_name(sym)
  hash = 0
  sym.each_byte { |char|
    hash = (((hash >> 0xd) | (hash << (32-0xd))) + char) & 0xffff_ffff
  }
  hash
end

def lib_name(sym)
  raise "unknown libname for #{sym}" if not lib = Metasm::WindowsExports::EXPORT[sym]
  n = lib.downcase[0, 4].unpack('C*')
  n[0] + (n[1]<<8) + (n[2] << 16) + (n[3] << 24)
end

# encode stub for each symbol
ext_syms.uniq.each { |sym|
  next if sym == 'next_payload'
  sc.parse <<EOS
#{sym}:
  push #{lib_name(sym)}
  push #{hash_name(sym)}
  call resolve_proc
  jmp eax
EOS
}

# marker to the next payload if the payload is a stager
sc.assemble "next_payload:"

# output to a file
sc.encode_file 'shellcode-dynlink.raw'

__END__
// sample payload

extern __stdcall int MessageBoxA(int, char*, char*, int);
extern void next_payload(void);

int main(void)
{
  MessageBoxA(0, "Hello, world !", "Hi", 0);
  next_payload();
}
