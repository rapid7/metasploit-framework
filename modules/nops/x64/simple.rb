##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Nop

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'Simple',
            'Alias'       => 'x64_simple',
            'Description' => 'An x64 single/multi byte NOP instruction generator.',
            'Author'      => [ 'sf' ],
            'License'     => MSF_LICENSE,
            'Arch'        => ARCH_X86_64
        )
    )

    register_advanced_options( [ OptBool.new( 'RandomNops', [ false, "Generate a random NOP sled", true ] ) ], self.class )
    register_advanced_options( [ OptBool.new( 'MultiByte',  [ false, "Generate a multi byte instruction NOP sled", false ] ) ], self.class )
  end

  # This instruction list is far from complete (Only single byte instructions and some multi byte ADD/MOV instructions are used).
  # A more complete list might warrent an pseudo assembler (Rex::Arch::X64) instead of hardcoding these.
  INSTRUCTIONS = [	[ "\x90",             0, "nop" ],
            [ "\x91",             0, "xchg eax, ecx" ],
            [ "\x92",             0, "xchg eax, edx" ],
            [ "\x93",             0, "xchg eax, ebx" ],
            [ "\x94",             0, "xchg eax, esp" ],
            [ "\x95",             0, "xchg eax, ebp" ],
            [ "\x96",             0, "xchg eax, esi" ],
            [ "\x97",             0, "xchg eax, edi" ],
            [ "\x98",             0, "cwde" ],
            [ "\x99",             0, "cdq" ],
            [ "\x9B",             0, "wait" ],
            [ "\x9C",             0, "pushfq" ],
            [ "\x9D",             0, "popfq" ],
            [ "\x9E",             0, "sahf" ],
            [ "\x9F",             0, "lahf" ],
            [ "\xFC",             0, "cld" ],
            [ "\xFD",             0, "std" ],
            [ "\xF8",             0, "clc" ],
            [ "\xF9",             0, "cmc" ],
            [ "\x50",             0, "push rax" ],
            [ "\x51",             0, "push rcx" ],
            [ "\x52",             0, "push rdx" ],
            [ "\x53",             0, "push rbx" ],
            [ "\x54",             0, "push rsp" ],
            [ "\x55",             0, "push rbp" ],
            [ "\x56",             0, "push rsi" ],
            [ "\x57",             0, "push rdi" ],
            [ "\x58",             0, "pop rax" ],
            [ "\x59",             0, "pop rcx" ],
            [ "\x5A",             0, "pop rdx" ],
            [ "\x5B",             0, "pop rbx" ],
            [ "\x5C",             0, "pop rsp" ],
            [ "\x5D",             0, "pop rbp" ],
            [ "\x5E",             0, "pop rsi" ],
            [ "\x5F",             0, "pop rdi" ],
            [ "\x04",             1, "add al, 0x??" ],
            [ "\x80\xC3",         1, "add bl, 0x??" ],
            [ "\x80\xC1",         1, "add cl, 0x??" ],
            [ "\x80\xC2",         1, "add dl, 0x??" ],
            [ "\x80\xC4",         1, "add ah, 0x??" ],
            [ "\x80\xC7",         1, "add bh, 0x??" ],
            [ "\x80\xC5",         1, "add ch, 0x??" ],
            [ "\x80\xC6",         1, "add dh, 0x??" ],
            [ "\x66\x05",         2, "add ax, 0x????" ],
            [ "\x66\x81\xC3",     2, "add bx, 0x????" ],
            [ "\x66\x81\xC1",     2, "add cx, 0x????" ],
            [ "\x66\x81\xC2",     2, "add dx, 0x????" ],
            [ "\x66\x81\xC6",     2, "add si, 0x????" ],
            [ "\x66\x81\xC7",     2, "add di, 0x????" ],
            [ "\x66\x41\x81\xC0", 2, "add r8w, 0x????" ],
            [ "\x66\x41\x81\xC1", 2, "add r9w, 0x????" ],
            [ "\x66\x41\x81\xC2", 2, "add r10w, 0x????" ],
            [ "\x66\x41\x81\xC3", 2, "add r11w, 0x????" ],
            [ "\x66\x41\x81\xC4", 2, "add r12w, 0x????" ],
            [ "\x66\x41\x81\xC5", 2, "add r13w, 0x????" ],
            [ "\x66\x41\x81\xC6", 2, "add r14w, 0x????" ],
            [ "\x66\x41\x81\xC7", 2, "add r15w, 0x????" ],
            [ "\x05",             4, "add eax, 0x????????" ],
            [ "\x81\xC3",         4, "add ebx, 0x????????" ],
            [ "\x81\xC1",         4, "add ecx, 0x????????" ],
            [ "\x81\xC2",         4, "add edx, 0x????????" ],
            [ "\x81\xC6",         4, "add esi, 0x????????" ],
            [ "\x81\xC7",         4, "add edi, 0x????????" ],
            [ "\x41\x81\xC0",     4, "add r8d, 0x????????" ],
            [ "\x41\x81\xC1",     4, "add r9d, 0x????????" ],
            [ "\x41\x81\xC2",     4, "add r10d, 0x????????" ],
            [ "\x41\x81\xC3",     4, "add r11d, 0x????????" ],
            [ "\x41\x81\xC4",     4, "add r12d, 0x????????" ],
            [ "\x41\x81\xC5",     4, "add r13d, 0x????????" ],
            [ "\x41\x81\xC6",     4, "add r14d, 0x????????" ],
            [ "\x41\x81\xC7",     4, "add r15d, 0x????????" ],
            [ "\x48\xB8",         8, "mov rax, 0x????????????????" ],
            [ "\x48\xBB",         8, "mov rbx, 0x????????????????" ],
            [ "\x48\xB9",         8, "mov rcx, 0x????????????????" ],
            [ "\x48\xBA",         8, "mov rdx, 0x????????????????" ],
            [ "\x48\xBE",         8, "mov rsi, 0x????????????????" ],
            [ "\x48\xBF",         8, "mov rdi, 0x????????????????" ],
            [ "\x49\xB8",         8, "mov r8, 0x????????????????" ],
            [ "\x49\xB9",         8, "mov r8, 0x????????????????" ],
            [ "\x49\xBA",         8, "mov r10, 0x????????????????" ],
            [ "\x49\xBB",         8, "mov r11, 0x????????????????" ],
            [ "\x49\xBC",         8, "mov r12, 0x????????????????" ],
            [ "\x49\xBD",         8, "mov r13, 0x????????????????" ],
            [ "\x49\xBE",         8, "mov r14, 0x????????????????" ],
            [ "\x49\xBF",         8, "mov r15, 0x????????????????" ],
  ]

  I_OP   = 0
  I_SIZE = 1
  I_TEXT = 2

  REGISTERS = [		[ "rsp", "esp", "sp" ],
            [ "rbp", "ebp", "bp" ],
            [ "rax", "eax", "ax", "al", "ah" ],
            [ "rbx", "ebx", "bx", "bl", "bh" ],
            [ "rcx", "ecx", "cx", "cl", "ch" ],
            [ "rdx", "edx", "dx", "dl", "dh" ],
            [ "rsi", "esi", "si" ],
            [ "rdi", "edi", "di" ],
            [ "r8", "r8d", "r8w", "r8b" ],
            [ "r9", "r9d", "r9w", "r9b" ],
            [ "r10", "r10d", "r10w", "r10b" ],
            [ "r11", "r11d", "r11w", "r11b" ],
            [ "r12", "r12d", "r12w", "r12b" ],
            [ "r13", "r13d", "r13w", "r13b" ],
            [ "r14", "r14d", "r14w", "r14b" ],
            [ "r15", "r15d", "r15w", "r15b" ],
  ]

  def generate_random_sled( length, instructions, badchars, badregs )
    opcodes_stack = []
    total_size    = 0
    sled          = ''
    try_count     = 0
    good_bytes    = []

    # Fixup SaveRegisters so for example, if we wish to preserve RSP we also should also preserve ESP and SP
    REGISTERS.each { | reg | reg.each { |x| badregs += reg if badregs.include?( x ) } }
    badregs = badregs.uniq()

    # If we are preserving RSP we should avoid all PUSH/POP instructions...
    if badregs.include?( "rsp" )
      badregs.push( 'push' )
      badregs.push( 'pop' )
    end

    # Loop while we still have bytes to fill in the sled...
    while true
      # Pick a random instruction and see if we can use it...
      instruction = instructions[ rand(instructions.length) ]

      # Avoid using any bad mnemonics/registers...
      try_another = false
      badregs.each do | bad |
        try_another = true if instruction[I_TEXT].include?( bad.downcase() )
        break if try_another
      end
      next if try_another

      # Get the first bytes of the chosed instructions opcodes...
      opcodes = instruction[I_OP]

      # If their are additional bytes to append, do it now...
      1.upto( instruction[I_SIZE] ) do | i |
        opcodes += Rex::Text.rand_char( badchars )
      end

      # If we have gone over the requested sled length, try again.
      if total_size + opcodes.length > length
        try_count -= 1

        # If we have tried unsuccessfully 32 times we start unwinding the chosen opcode_stack to speed things up
        if try_count == 0
          pop_count = 4
          while opcodes_stack.length and pop_count
            total_size -= opcodes_stack.pop().length
            pop_count -= 1
          end
        end
        next
      end

      # Reset the try_count for the next itteration.
      try_count = 32

      # save the opcodes we just generated.
      opcodes_stack.push( opcodes )

      # Increment the total size appropriately.
      total_size += opcodes.length

      # Once we have generated the requested amount of bytes we can finish.
      break if total_size == length
    end

    # Now that we have chosen all the instructions to use we must generate the actual sled.
    opcodes_stack.each do | opcodes_ |
      sled += opcodes_
    end

    return sled
  end

  def generate_sled( length, opts )
    badchars  = opts['BadChars'] || ''
    random    = opts['Random'] || datastore['RandomNops']
    badregs   = opts['SaveRegisters'] || []
    good_instructions = []
    sled      = ''

    # Weed out any instructions which will contain a bad char/instruction...
    INSTRUCTIONS.each do | instruction |
      good = true;
      # If the instruction contains some bad chars we wont use it...
      badchars.each do | bc |
        if instruction[I_OP].include?( bc )
          good = false
          break
        end
      end
      # if we are only to generate single byte instructions, weed out the multi byte ones...
      good = false if instruction[I_SIZE] > 0 and not datastore['MultiByte']

      good_instructions.push( instruction ) if good
    end

    # After we have pruned the instruction list we can proceed to generate a sled...
    if good_instructions.empty?
      # If we are left with no valid instructions to use we simple cant generate a sled.
      sled = nil
    elsif not random
      if not badchars.include?( "\x90" )
        sled += "\x90" * length
      else
        sled = nil
      end
    else
      sled += generate_random_sled( length, good_instructions, badchars, badregs )
    end

    return sled
  end

end
