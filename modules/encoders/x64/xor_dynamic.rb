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

  def stub
    "\xeb\x34" +              #         jmp   _call
    "\x59" +                  # _ret:   pop   rcx
    "\x48\x89\xcb" +          #         mov   rbx,rcx
    "\x48\x89\xde" +          #         mov   rsi,rbx
    "\x80\x39\x41" +          # _lp1:   cmp   BYTE PTR [rcx], 'A'
    "\x74\x05" +              #         je    _ok
    "\x48\xff\xc1" +          #         inc   rcx
    "\xeb\xf6" +              #         jmp   _lp1
    "\x48\xff\xc1" +          # _ok:    inc   rcx
    "\x48\x89\xcf" +          #         mov   rdi, rcx
    "\x66\x81\x39\x42\x42" +  # _lp:    cmp   WORD PTR [rcx], 'BB'
    "\x74\x14" +              #         je    _jmp
    "\x8a\x03" +              #         mov   al, BYTE PTR [rbx]
    "\x30\x01" +              #         xor   BYTE PTR [rcx], al
    "\x48\xff\xc1" +          #         inc   rcx
    "\x48\xff\xc3" +          #         inc   rbx
    "\x80\x3b\x41" +          #         cmp   BYTE PTR [rbx], 'A'
    "\x75\xea" +              #         jne   _lp
    "\x48\x89\xf3" +          #         mov   rbx, rsi
    "\xeb\xe5" +              #         jmp   _lp
    "\xff\xe7" +              # _jmp:   jmp   rdi
    "\xe8\xc7\xff\xff\xff"    # _call:  call  _ret
  end

  def stub_key_term
    /A/
  end

  def stub_payload_term
    /BB/
  end
end
