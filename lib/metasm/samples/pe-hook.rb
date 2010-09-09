#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# in this file, we open an existing PE, add some code to its last section and
# patch the entrypoint so that we are executed at program start
#

require 'metasm'

# read original file
raise 'need a target filename' if not target = ARGV.shift
pe_orig = Metasm::PE.decode_file(target)
pe = pe_orig.mini_copy
pe.mz.encoded = pe_orig.encoded[0, pe_orig.coff_offset-4]
pe.mz.encoded.export = pe_orig.encoded[0, 512].export.dup
pe.header.time = pe_orig.header.time

has_mb = pe.imports.find { |id| id.imports.find { |i| i.name == 'MessageBoxA' } } ? 1 : 0
# hook code to run on start
newcode = Metasm::Shellcode.assemble(pe.cpu, <<EOS).encoded
hook_entrypoint:
pushad
#if ! #{has_mb}
push hook_libname
call [iat_LoadLibraryA]
push hook_funcname
push eax
call [iat_GetProcAddress]
#else
mov eax, [iat_MessageBoxA]
#endif

push 0
push hook_title
push hook_msg
push 0
call eax

popad
jmp entrypoint

.align 4
hook_msg db '(c) David Hasselhoff', 0
hook_title db 'Hooked on a feeling', 0
#if ! #{has_mb}
hook_libname db 'user32', 0
hook_funcname db 'MessageBoxA', 0
#endif
EOS

# modify last section
s = Metasm::PE::Section.new
s.name = '.hook'
s.encoded = newcode
s.characteristics = %w[MEM_READ MEM_WRITE MEM_EXECUTE]
s.encoded.fixup!('entrypoint' => pe.optheader.image_base + pe.optheader.entrypoint)	# tell the original entrypoint address to our hook
pe.sections << s
pe.invalidate_header

# patch entrypoint
pe.optheader.entrypoint = 'hook_entrypoint'

# save
pe.encode_file(target.sub(/\.exe$/i, '-patch.exe'))
