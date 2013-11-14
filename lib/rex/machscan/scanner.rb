# -*- coding: binary -*-

module Rex
module MachScan
module Scanner
class Generic

  attr_accessor :mach, :fat, :regex

  def initialize(binary)
    if binary.class == Rex::MachParsey::Mach
      self.mach = binary
    else
      self.fat = binary
    end
  end

  def config(param)
  end

  def scan(param)
      config(param)

      $stdout.puts "[#{param['file']}]"

      if !self.mach
        for mach in fat.machos
          if mach.mach_header.cputype == 0x7 #since we only support intel for the time being its all we process
            self.mach = mach
          end
        end
      end

      self.mach.segments.each do |segment|
        if segment.segname.include? "__TEXT"
          scan_segment(segment, param).each do |hit|
            vaddr  = hit[0]
            message  = hit[1].is_a?(Array) ? hit[1].join(" ") : hit[1]
            $stdout.puts self.mach.ptr_s(vaddr - self.mach.fat_offset) + " " + message
          end
        end
      end

  end

  def scan_segment(segment, param={})
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
    case mach.read(offset, 1)
    when "\xc3"
        return 1
    when "\xc2"
        return 3
    end
    $stderr.puts("Invalid return instruction")
  end

  def _parse_ret(data)
    if data.length == 1
      return "ret"
    else
      return "retn 0x%04x" % data[1, 2].unpack('v')[0]
    end
  end

  def scan_segment(segment, param={})
    base_addr = segment.vmaddr
    segment_offset = segment.fileoff
    offset = segment_offset

    hits = []

    while (offset = mach.index(regex, offset)) != nil

      vaddr = base_addr + (offset - segment_offset)
      message = ''

      parse_ret = false

      byte1 = mach.read(offset, 1).unpack("C*")[0]

      if byte1 == 0xff
        byte2   = mach.read(offset+1, 1).unpack("C*")[0]
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
            message = "push #{regname}; " + _parse_ret(mach.read(offset+2, retsize))
            offset += 2 + retsize
        else
            raise "wtf"
        end
      else
        regname = Rex::Arch::X86.reg_name32(byte1 & 0x7)
        retsize = _ret_size(offset+1)
        message = "push #{regname}; " + _parse_ret(mach.read(offset+1, retsize))
        offset += 1 + retsize
      end

      hits << [ vaddr, message ]
    end

    return hits
  end
end

class PopPopRetScanner < JmpRegScanner

  def config(param)
    pops = _build_byte_list(0x58, (0 .. 7).to_a - [4]) # we don't want pop esp's...
    self.regex = Regexp.new("[#{pops}][#{pops}](\xc3|\xc2..)", nil, 'n')
  end

  def scan_segment(segment, param={})
    base_addr = segment.vmaddr
    segment_offset = segment.fileoff
    offset = segment_offset

    hits = []

    while offset < segment.fileoff + segment.filesize && (offset = mach.index(regex, offset)) != nil

      vaddr = base_addr + (offset - segment_offset)
      message = ''

      pops = mach.read(offset, 2)
      reg1 = Rex::Arch::X86.reg_name32(pops[0,1].unpack("C*")[0] & 0x7)
      reg2 = Rex::Arch::X86.reg_name32(pops[1,1].unpack("C*")[0] & 0x7)

      message = "pop #{reg1}; pop #{reg2}; "

      retsize = _ret_size(offset+2)
      message += _parse_ret(mach.read(offset+2, retsize))

      offset += 2 + retsize

      hits << [ vaddr, message ]
    end

    return hits
  end
end

class RegexScanner < JmpRegScanner

  def config(param)
    self.regex = Regexp.new(param['args'], nil, 'n')
  end

  def scan_segment(segment, param={})
    base_addr = segment.vmaddr
    segment_offset = segment.fileoff
    offset = segment_offset

    hits = []

    while offset < segment.fileoff + segment.filesize && (offset = mach.index(regex, offset)) != nil

      idx = offset
      buf = ''
      mat = nil

      while (! (mat = buf.match(regex)))
        buf << mach.read(idx, 1)
        idx += 1
      end

      vaddr = base_addr + (offset - segment_offset)

      hits << [ vaddr, buf.unpack("H*") ]
      offset += buf.length
    end
    return hits
  end
end

end
end
end

