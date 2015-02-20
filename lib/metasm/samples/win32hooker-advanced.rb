#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# in this exemple we will patch a process specified on the commandline (pid or part of the image name)
# we will retrieve the user32.dll library mapped, and hook every exported function.
# each hook will redirect the code flow to our shellcode, which will display the hooked function
# name in a messagebox.
# The hook is this time a real hook: we overwrite the first instructions with a jump to our code,
# and run those overwritten instruction again before giving control back to original function.
#
# usage: ruby w32hook-advance.rb notepad
# use ruby -d to impress your friends :)
#
# XXX obsolete, should replace all virtallocex etc by WinOS calls

require 'metasm'

include Metasm

# open target
WinOS.get_debug_privilege
if not pr = WinOS.find_process(ARGV.first)
  # display list of running processes and exit
  puts WinOS.list_processes.sort_by { |pr_| pr_.pid }
  exit
end
raise 'cannot open target process' if not pr.handle

# the main shellcode
sc = Shellcode.assemble Ia32.new, <<EOS
main_hook:
 pushfd				; save registers
 pushad

 mov eax, dword ptr [in_hook]	; check if we are in the hook (yay threadsafe)
 test eax, eax
 jnz main_hook_done
 mov dword ptr [in_hook], 1

 mov eax, dword ptr [esp+4+4*9]	; get the function name (1st argument)

 push 0
 push eax
 push eax
 push 0
 call messageboxw

 mov dword ptr [in_hook], 0
main_hook_done:
 popad
 popfd
 ret 4

.align 4
in_hook   dd 0			; l33t mutex
EOS

# this is where we store every function hook
hooks = {}
prepare_hook = lambda { |mpe, base, export|
  hooklabel = sc.new_label('hook')
  namelabel = sc.new_label('name')

  # this will overwrite the function entrypoint
  target = base + export.target
  hooks[target] = Shellcode.new(sc.cpu).share_namespace(sc).parse("jmp #{hooklabel}").assemble.encoded

  # backup the overwritten instructions
  # retrieve instructions until their length is >= our hook length
  mpe.encoded.ptr = export.target
  sz = 0
  overwritten = []
  while sz < hooks[target].length
    di = sc.cpu.decode_instruction mpe.encoded, target
    if not di or not di.opcode or not di.instruction
      puts "W: unknown instruction in #{export.name} !"
      break
    end
    overwritten << di.instruction
    sz += di.bin_length
  end
  puts "overwritten at #{export.name}:", overwritten, '' if $DEBUG
  resumeaddr = target + sz

  # append the call-specific shellcode to the main hook code
  sc.cursource << Label.new(hooklabel)
  sc.parse <<EOS
 push #{namelabel}
 call main_hook		; log the call
; rerun the overwritten instructions
#{overwritten.join("\n")}
 jmp #{resumeaddr}	; get back to original code flow
EOS
  sc.cursource << Label.new(namelabel)
  sc.parse "dw #{export.name.inspect}, 0"
}

msgboxw = nil
# decode interesting libraries from address space
pr.modules[1..-1].each { |m|
  # search for messageboxw
  if m.path =~ /user32/i
    mpe = LoadedPE.load pr.memory[m.addr, 0x1000000]
    mpe.decode_header
    mpe.decode_exports
    mpe.export.exports.each { |e| msgboxw = m.addr + mpe.label_rva(e.target) if e.name == 'MessageBoxW' }
  end
  # prepare hooks
  next if m.path !~ /user32/i	# filter interesting libraries
  puts "handling #{File.basename m.path}" if $VERBOSE

  if not mpe
    mpe = LoadedPE.load pr.memory[m.addr, 0x1000000]
    mpe.decode_header
    mpe.decode_exports
  end
  next if not mpe.export or not mpe.export.exports

  # discard exported data
  text = mpe.sections.find { |s| s.name == '.text' }
  mpe.export.exports.each { |e|
    next if not e.target or not e.name
    next if e.name =~ /(?:Translate|Get|Dispatch)Message|CallNextHookEx|TranslateAccelerator/

    # ensure we have an offset and not a label name
    e.target = mpe.label_rva(e.target)

    # ensure the exported thing is in the .text section
    next if e.target < text.virtaddr or e.target >= text.virtaddr + text.virtsize

    # prepare the hook
    prepare_hook[mpe, m.addr, e]
  }
}

raise 'Did not find MessageBoxW !' if not msgboxw

puts 'linking...'
sc.assemble
puts 'done'

# allocate memory for our code
raise 'remote allocation failed' if not injected_addr = WinAPI.virtualallocex(pr.handle, 0, sc.encoded.length, WinAPI::MEM_COMMIT|WinAPI::MEM_RESERVE, WinAPI::PAGE_EXECUTE_READWRITE)

puts "Injecting hooks at #{'%x' % injected_addr}"

# fixup & inject our code
binding = { 'messageboxw' => msgboxw }
hooks.each { |addr, edata| binding.update edata.binding(addr) }
binding.update sc.encoded.binding(injected_addr)

# fixup
sc.encoded.fixup(binding)
# inject
pr.memory[injected_addr, sc.encoded.data.length] = sc.encoded.data

# now overwrite entry points
hooks.each { |addr, edata|
  edata.fixup(binding)
  pr.memory[addr, edata.data.length] = edata.data
}

puts 'done'

WinAPI.closehandle(pr.handle)
