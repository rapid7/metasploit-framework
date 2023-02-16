require 'metasploit/framework/compiler/windows'

class MetasploitModule < Msf::Evasion

  def initialize(info={})
    super(merge_info(info,
      'Name'        => 'test',
      'Targets'     => [ ['Microsoft Windows', {}] ],
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
    ))
  end
  

  def c_template
    @c_template ||= %Q|
#include <windows.h>
#include <rc4.h>


int main(int argc, char **argv)
{
  char str[] = "Hello World!";
  printf("%s\\n", str);
  return 0;
}|
  end

  def run
    m = Metasploit::Framework::Compiler::Mingw::X86.new({ show_compile_cmd: true, f_name: "OK", compile_options: " -lpsapi -lwininet " })
    bin = m.compile_c(c_template)
    print_status("#{bin}")
  end

end
