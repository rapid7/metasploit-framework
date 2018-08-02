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
          obfuscation, Metasm, and anti-emulation are used to achieve this. For best results,
          please try to use payloads that use a more secure channel such as HTTPS or RC4
          in order to avoid the payload network traffic getting caught by AV.
        },
        'Author'      => [ 'sinn3r' ],
        'License'     => MSF_LICENSE,
        'Platform'    => 'win',
        'Arch'        => ARCH_X86
      ))
  end

  def c_template
    %Q|#include <Windows.h>

    int main() {
      const char* msgBody = "Hello World";
      const char* msgTitle = "Test";
      MessageBox(NULL, msgBody, msgTitle, MB_OK);
      return 0;
    }|
  end

  def generate(opts={})
    Metasploit::Framework::Compiler::Windows.compile_random_c(c_template)
  end

end