##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder::Xor

  def initialize
    super(
      'Name' => 'XOR POLY Encoder',
      'Description' => 'An x86 Simple POLY Xor encoding method. using polymorphism Register swapping, and instructions modification',
      'Author' => [ 'Arthur RAOUT' ],
      'Arch' => ARCH_X86,
      'License' => MSF_LICENSE,
      'Decoder' => {
        'KeySize' => 4,
        'BlockSize' => 4,
        'KeyPack' => 'V'
      }
      )
  end

  # Indicate that this module can preserve the registers used
  def can_preserve_registers?
    true
  end

  # select a permutation from table
  def choose_permutation(state, table)
    table = table.shuffle
    for i in 0..table.length - 1
      if table[i].count(state.badchars).zero?
        return table[i]
      end
    end
    raise 'No permutation found for the badchar set :' + state.badchars.inspect
  end

  # generate instruction for a push
  def register_preservation_generate(flag, regs)
    ret = ''
    pop = 0b0101_1000
    push = 0b0101_0000
    if flag == 0
      for r in regs
        ret += [push | r].pack('C')
      end
    end
    if flag == 1
      for r in regs.reverse
        ret += [pop | r].pack('C')
      end
    end
    return ret
  end

  def decoder_stub(state)
    state.decoder_key_size = 4
    state.decoder_key_pack = 'V'
    # calculate the (negative) and positiv block count.
    block_count = [-(((state.buf.length - 1) / state.decoder_key_size) + 1)].pack('V')
    block_count_positive = [(((state.buf.length - 1) / state.decoder_key_size) + 1)].pack('V')

    regs = [0b0000, 0b0001, 0b0010, 0b0011, 0b0110, 0b0111]

    pop = 0b0101_1000
    push = 0b0101_0000
    mov = 0b1011_1000

    reg1 = regs[rand(6)]
    regs.delete(reg1)
    reg2 = regs[rand(5)]
    regs.delete(reg2)
    reg3 = regs[rand(4)]
    regs.delete(reg3)
    reg4 = regs[rand(3)] # reg4 is useless and used for nopLike operations
    regs.delete(reg4)

    # NOPS
    nop_nop_nop_nop = "\x90\x90\x90\x90" # 4 bytes
    push_pop12 = [push | reg1, push | reg2, pop | reg2, pop | reg1].pack('CCCC') # 4 bytes
    push_pop34 = [push | reg3, push | reg4, pop | reg4, pop | reg3].pack('CCCC') # 4 bytes
    push_pop56 = [push | reg4, push | reg1, pop | reg1, pop | reg4].pack('CCCC') # 4 bytes

    sub_reg_0 = [0x83, (0xE8 | rand(6)), 0x00].pack('CCC') # 3 bytes
    add_reg_0 = [0x83, (0xc0 | rand(6)), 0x00].pack('CCC') # 3 bytes
    add_reg4_1 = [0x83, (0xc0 | reg4), 0x01].pack('CCC') # 3 bytes
    add_reg4_33 = [0x83, (0xc0 | reg4), 0x33].pack('CCC') # 3 bytes
    add_reg4_f1 = [0x83, (0xc0 | reg4), 0xf1].pack('CCC') # 3 bytes
    nop_nop_nop = "\x90\x90\x90" # 3 bytes

    push_pop1 = [push | reg1, pop | reg1].pack('CC') # 2 bytes
    push_pop2 = [push | reg2, pop | reg2].pack('CC') # 2 bytes
    push_pop3 = [push | reg3, pop | reg3].pack('CC') # 2 bytes
    push_pop4 = [push | reg4, pop | reg4].pack('CC') # 2 bytes
    inc_reg1_dec_reg1 = [0x40 | reg1, 0x48 | reg1].pack('CC') # 2 bytes
    inc_reg2_dec_reg2 = [0x40 | reg2, 0x48 | reg2].pack('CC') # 2 bytes
    inc_reg3_dec_reg3 = [0x40 | reg3, 0x48 | reg3].pack('CC') # 2 bytes
    inc_reg4_dec_reg4 = [0x40 | reg4, 0x48 | reg4].pack('CC') # 2 bytes

    # nops tables by size
    nops_2_bytes = [push_pop1, push_pop2, push_pop3, push_pop4, "\x90\x90", inc_reg1_dec_reg1, inc_reg2_dec_reg2, inc_reg3_dec_reg3, inc_reg4_dec_reg4]
    nops_3_bytes = [nop_nop_nop, push_pop1 + "\x90", push_pop2 + "\x90", push_pop3 + "\x90", push_pop4 + "\x90", sub_reg_0, add_reg_0, choose_permutation(state, nops_2_bytes) + "\x90", add_reg4_1, add_reg4_33, add_reg4_f1]
    nops_4_bytes = [nop_nop_nop_nop, push_pop12, push_pop34, push_pop56, choose_permutation(state, nops_2_bytes) + choose_permutation(state, nops_2_bytes), choose_permutation(state, nops_3_bytes) + "\x90"]

    # THE DECODER CODE
    pop_reg1 = [pop | reg1].pack('C')

    # sub 5 from reg1 on 5 byte
    sub_reg1_5 = [0x83, (0xE8 | reg1), 0x05].pack('CCC') + choose_permutation(state, nops_2_bytes) # 5 bytes
    add_reg1_neg5 = [0x83, (0xc0 | reg1), 0xfb].pack('CCC') + choose_permutation(state, nops_2_bytes) # 5 bytes
    dec_reg1_5 = [0x48 | reg1, 0x48 | reg1, 0x48 | reg1, 0x48 | reg1, 0x48 | reg1].pack('CCCCC') # 5 bytes

    # set reg2 to 0, on 6 bytes
    xor_reg2_reg2 = [0x31, (0xC0 | (reg2 << 3) | reg2)].pack('CC') + choose_permutation(state, nops_4_bytes) # 6 bytes
    and_reg2_0 = [0x83, (0xE0 | reg2), 0x00].pack('CCC') + choose_permutation(state, nops_3_bytes) # 6 bytes
    lea_reg2_0 = [0x8D, (0x05 | (reg2 << 3)), 0x00, 0x00, 0x00, 0x00].pack('CCCCCC')
    imul_reg2_reg2_0 = [0x6b, (0xC0 | (reg2 << 3) | reg2), 0x00].pack('CCC') + choose_permutation(state, nops_3_bytes) # 6 bytes
    sub_reg2_reg2 = [0x29, (0xC0 | (reg2 << 3) | reg2)].pack('CC') + choose_permutation(state, nops_4_bytes) # 6 bytes
    push0_popreg2 = [0x6A, 0x00, (0x58 | reg2)].pack('CCC') + choose_permutation(state, nops_3_bytes) # 6 bytes

    # SET REG2 TO BLOCK_COUNT
    sub_reg2_bc = [0x81, (0xe8 | reg2)].pack('CC') + block_count
    add_reg2_bc = [0x81, (0xc0 | reg2)].pack('CC') + block_count_positive

    mov_reg3 = [mov | reg3].pack('C')
    xor_rel_reg1_reg3 = [0x31, (0x40 | (reg3 << 3 | reg1))].pack('cc')

    # ADD 4 TO REG1
    add_reg1_4 = [0x83, (0xC0 | reg1), 0x04].pack('CCC') + choose_permutation(state, nops_3_bytes) # 6 bytes
    sub_reg1_neg4 = [0x83, (0xE8 | reg1), 0xFC].pack('CCC') + choose_permutation(state, nops_3_bytes) # 6 bytes
    inc_reg1_4 = [0x40 | reg1, 0x40 | reg1, 0x40 | reg1, 0x40 | reg1].pack('CCCC') + choose_permutation(state, nops_2_bytes) # 6 bytes

    # sub 1 from reg2 on 6 bytes
    dec_r2 = [0xFF, (0xC8 | reg2)].pack('CC')
    sub_reg2_1 = [0x83, (0xE8 | reg2), 0x01].pack('CCC')
    add_reg2_neg1 = [0x83, (0xC0 | reg2), 0xFF].pack('CCC')

    set_reg2_0 = [xor_reg2_reg2, and_reg2_0, lea_reg2_0, imul_reg2_reg2_0, sub_reg2_reg2, push0_popreg2]
    sub_reg1_0x5 = [sub_reg1_5, add_reg1_neg5, dec_reg1_5]
    set_reg2_bc = [sub_reg2_bc, add_reg2_bc]

    # GET EIP TO REG1
    call_pop = [0xE8, 0x00, 0x00, 0x00, 0x00].pack('CCCCC') + pop_reg1 + choose_permutation(state, sub_reg1_0x5)
    fpu_inst = ["\xD9\xE0", "\xDF\xE9", "\xDB\xC9", "\xDA\xD9", "\xDA\xC1", "\xDA\xD1", "\xDB\xD9"] # 2 bytes
    fnstenv_pop = choose_permutation(state, fpu_inst) + "\xD9\x74\x24\xF4" + pop_reg1
    add_reg1_0x4 = [add_reg1_4, sub_reg1_neg4, inc_reg1_4]
    dec_reg2 = [dec_r2, sub_reg2_1, add_reg2_neg1]
    get_eip = [call_pop, fnstenv_pop]

    small_junk = [choose_permutation(state, nops_2_bytes), choose_permutation(state, nops_3_bytes), choose_permutation(state, nops_4_bytes)]

    reg_for_preservation = [reg1, reg2, reg3, reg4].shuffle
    reg_push = register_preservation_generate(0, reg_for_preservation)
    reg_pop = register_preservation_generate(1, reg_for_preservation)
    geip = choose_permutation(state, get_eip)
    junk = choose_permutation(state, small_junk)
    reg2_0 = choose_permutation(state, set_reg2_0)
    block_count_set = choose_permutation(state, set_reg2_bc)
    reg1_add4 = choose_permutation(state, add_reg1_0x4)
    decrement_reg2 = choose_permutation(state, dec_reg2)

    decoder = reg_push +
              geip +                                      # get EIP into REG1
              junk +                                      # small junk
              reg2_0 +                                    # set REG2 to 0
              block_count_set + # sub reg2, block_count
              mov_reg3 + 'XXXX' +                         # mov reg3, 0xKEY_KEY_KEY_KEY
              xor_rel_reg1_reg3 + 'LL' +                  # xor [reg1+DECODER_LEN], reg3
              reg1_add4 + # add reg1, 4
              decrement_reg2 + # dec reg2
              "\x75" + 'SS' + # jnz to xor
              reg_pop

    decoder_len = decoder.size
    jmp = decoder.index(xor_rel_reg1_reg3) - decoder.index('SS')
    decoder.sub! 'SS', [jmp].pack('C')
    decoder.sub! 'LL', [decoder_len - 6].pack('C')
    # example of decoder generated
    # e800000000     call loc._start.continue
    # 58             pop eax
    # 83e805         sub eax, 5
    # 31c9           xor ecx, ecx
    # 81e9bbbbbbbb   sub ecx, 0xbbbbbbbb
    # bbaaaaaaaa     mov ebx, 0xaaaaaaaa
    # 31581f         xor dword [eax + 0x1f], ebx
    # 83e8f4         sub eax, 0xfffffff4
    # e2f8           loop loc._start.check
    state.decoder_key_offset = decoder.index('XXXX')
    return decoder
  end
end
