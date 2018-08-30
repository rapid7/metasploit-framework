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

  def stub
    "\xeb\x28" +              #         jmp   _call
    "\x59" +                  # _ret:   pop   ecx
    "\x89\xcb" +              #         mov   ebx, ecx
    "\x89\xde" +              #         mov   esi, ebx
    "\x80\x39\x61" +          # _lp1:   cmp   BYTE PTR [ecx], 'a'
    "\x74\x03" +              #         je    _ok
    "\x41" +                  #         inc   ecx
    "\xeb\xf8" +              #         jmp   _lp1
    "\x41" +                  # _ok:    inc   ecx
    "\x89\xcf" +              #         mov   edi,ecx
    "\x66\x81\x39\x62\x62" +  # _lp:    cmp   WORD PTR [ecx], 'bb'
    "\x74\x0f" +              #         je    _jmp
    "\x8a\x03" +              #         mov   al,BYTE PTR [ebx]
    "\x30\x01" +              #         xor   BYTE PTR [ecx], al
    "\x41" +                  #         inc   ecx
    "\x43" +                  #         inc   ebx
    "\x80\x3b\x61" +          #         cmp   BYTE PTR [ebx], 'a'
    "\x75\xee" +              #         jne   _lp
    "\x89\xf3" +              #         mov   ebx, esi
    "\xeb\xea" +              #         jmp   _lp
    "\xff\xe7" +              # _jmp:   jmp   edi
    "\xe8\xd3\xff\xff\xff"    # _call:  call  _ret
  end

  def stub_key_term
    /a/
  end

  def stub_payload_term
    /bb/
  end
end
