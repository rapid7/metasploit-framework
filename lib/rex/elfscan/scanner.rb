# -*- coding: binary -*-

module Rex
module ElfScan
module Scanner
class Generic

  attr_accessor :elf, :regex

  def initialize(elf)
    self.elf = elf
  end

  def config(param)
  end

  def scan(param)
    config(param)

    $stdout.puts "[#{param['file']}]"
    elf.program_header.each do |program_header|

      # Scan only loadable segment entries in the program header table
      if program_header.p_type == Rex::ElfParsey::ElfBase::PT_LOAD
        hits = scan_segment(program_header, param)
        hits.each do |hit|
          rva  = hit[0]
          message  = hit[1].is_a?(Array) ? hit[1].join(" ") : hit[1]
          $stdout.puts elf.ptr_s(rva) + " " + message
        end
      end

    end
  end

  def scan_segment(program_header, param={})
    []
  end
end

class JmpRegScanner < Generic

  def config(param)
    regnums = param['args']

    # build a list of the call bytes
    calls  = _build_byte_list(0xd0, regnums - [4]) # note call esp's don't work..
    jmps   = _build_byte_list(0xe0, regnums)
    pushs1 = _build_byte_list(0x50, regnums)
    pushs2 = _build_byte_list(0xf0, regnums)

    regexstr = '('
    if !calls.empty?
      regexstr += "\xff[#{calls}]|"
    end

    regexstr += "\xff[#{jmps}]|([#{pushs1}]|\xff[#{pushs2}])(\xc3|\xc2..))"

    self.regex = Regexp.new(regexstr, nil, 'n')
  end

  # build a list for regex of the possible bytes, based on a base
  # byte and a list of register numbers..
  def _build_byte_list(base, regnums)
    regnums.collect { |regnum| Regexp.escape((base | regnum).chr) }.join('')
  end

  def _ret_size(offset)
    case elf.read(offset, 1)
      when "\xc3"
        return 1
      when "\xc2"
        return 3
    end

    raise "wtf"
  end

  def _parse_ret(data)
    if data.length == 1
      return "ret"
    else
      return "retn 0x%04x" % data[1, 2].unpack('v')[0]
    end
  end


  def scan_segment(program_header, param={})
    offset = program_header.p_offset

    hits = []

    while (offset = elf.index(regex, offset)) != nil

      rva     = elf.offset_to_rva(offset)
      message = ''

      parse_ret = false

      byte1 = elf.read(offset, 1).unpack('C')[0]

      if byte1 == 0xff
        byte2   = elf.read(offset+1, 1).unpack('C')[0]
        regname = Rex::Arch::X86.reg_name32(byte2 & 0x7)

        case byte2 & 0xf8
        when 0xd0
          message = "call #{regname}"
          offset += 2
        when 0xe0
          message = "jmp #{regname}"
          offset += 2
        when 0xf0
          retsize = _ret_size(offset+2)
          message = "push #{regname}; " + _parse_ret(elf.read(offset+2, retsize))
          offset += 2 + retsize
        else
          raise "wtf"
        end
      else
        regname = Rex::Arch::X86.reg_name32(byte1 & 0x7)
        retsize = _ret_size(offset+1)
        message = "push #{regname}; " + _parse_ret(elf.read(offset+1, retsize))
        offset += 1 + retsize
      end

      hits << [ rva, message ]
    end

    return hits
  end
end

class PopPopRetScanner < JmpRegScanner

  def config(param)
    pops = _build_byte_list(0x58, (0 .. 7).to_a - [4]) # we don't want pop esp's...
    self.regex = Regexp.new("[#{pops}][#{pops}](\xc3|\xc2..)", nil, 'n')
  end

  def scan_segment(program_header, param={})
    offset = program_header.p_offset

    hits = []

    while offset < program_header.p_offset + program_header.p_filesz &&
    (offset = elf.index(regex, offset)) != nil

      rva     = elf.offset_to_rva(offset)
      message = ''

      pops = elf.read(offset, 2)
      reg1 = Rex::Arch::X86.reg_name32(pops[0,1].unpack('C*')[0] & 0x7)
      reg2 = Rex::Arch::X86.reg_name32(pops[1,1].unpack('C*')[0] & 0x7)

      message = "pop #{reg1}; pop #{reg2}; "

      retsize = _ret_size(offset+2)
      message += _parse_ret(elf.read(offset+2, retsize))

      offset += 2 + retsize

      hits << [ rva, message ]
    end

    return hits
  end
end

class RegexScanner < JmpRegScanner

  def config(param)
    self.regex = Regexp.new(param['args'], nil, 'n')
  end

  def scan_segment(program_header, param={})
    offset = program_header.p_offset

    hits = []

    while offset < program_header.p_offset + program_header.p_filesz &&
    (offset = elf.index(regex, offset)) != nil

      idx = offset
      buf = ''
      mat = nil

      while (! (mat = buf.match(regex)))
        buf << elf.read(idx, 1)
        idx += 1
      end

      rva = elf.offset_to_rva(offset)

      hits << [ rva, buf.unpack("H*") ]
      offset += buf.length
    end

    return hits
  end
end

end
end
end

