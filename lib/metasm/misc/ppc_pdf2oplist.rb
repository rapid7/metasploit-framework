#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory
#
# parses the PPC specification PDF to generate the opcode list
#

require 'pdfparse'

$field_mask = {}
$field_shift = {}
$opcodes = []
def make_instr(bins, bits, text)
  # calc bitfields length from their offset
  last = 32
  bitlen = []
  bits.reverse_each { |bit|
    bitlen.unshift last-bit
    last = bit
  }

  # the opcode binary value (w/o fields)
  bin = 0
  fields = []

  # parse the data
  bins.zip(bits, bitlen).each { |val, off, len|
    off = 32-(off+len)
    msk = (1 << len) - 1
    case val
    when '/', '//', '///'	# reserved field, value unspecified
    when /^\d+$/; bin |= val.to_i << off	# constant field
    when /^[A-Za-z]+$/
      fld = val.downcase.to_sym
      fld = "#{fld}_".to_sym while $field_mask[fld] and ($field_mask[fld] != msk or $field_shift[fld] != off)
      fields << fld
      $field_mask[fld] ||= msk
      $field_shift[fld] ||= off
    end
  }

  text.each { |txt|
    # fnabs FRT,FRB (Rc=0)
    curbin = bin
    curfields = fields.dup
    txt.sub!('  Rc=1)', '  (Rc=1)') if txt.include? 'fdiv.'		# typo: fdiv. has no '('
    if txt =~ /(.*\S)\s*\((\w+=.*)\)/
      txt = $1
      $2.split.each { |e|
 				raise e if e !~ /(\w+)=(\d+)/
        name, val = $1.downcase, $2.to_i
        raise "bad bit #{name} in #{txt}" if not fld = curfields.find { |fld_| fld_.to_s.delete('_') == name }
        curfields.delete fld
        curbin |= val << $field_shift[fld]
      }
    end
    opname, args = txt.split(/\s+/, 2)
    args = args.to_s.downcase.split(/\s*,\s*/).map { |arg| fld = curfields.find { |fld_| fld_.to_s.delete('_') == arg } ; curfields.delete fld ; fld }
    if args.include? nil and curfields.length == 2 and (curfields - [:ra, :d]).empty?
      args[args.index(nil)] = :ra_i16
      curfields.clear
    elsif args.include? nil and curfields.length == 2 and (curfields - [:ra, :ds]).empty?
      args[args.index(nil)] = :ra_i16s
      curfields.clear
    elsif args.include? nil and curfields.length == 2 and (curfields - [:ra, :dq]).empty?
      args[args.index(nil)] = :ra_i16q
      curfields.clear
    elsif args.include? nil and curfields.length == 1
      args[args.index(nil)] = curfields.shift
    end
    raise "bad args #{args.inspect} (#{curfields.inspect}) in #{txt}" if args.include? nil
    $opcodes << [opname, curbin, args]

    n = (opname.inspect << ',').ljust(10) + '0x%08X' % curbin
    n << ', ' if not args.empty?
    puts "\taddop " + n + args.map { |e| e.inspect }.join(', ')
  }
end

# handle instruction aliases
# NOT WORKING
# should be implemented in the parser/displayer instead of opcode list
# manual work needed for eg conditionnal jumps
def make_alias(newop, newargs, oldop, oldargs)
  raise "unknown alias #{newop} => #{oldop}" if not op = $opcodes.reverse.find { |op_| op_[0] == oldop }
  op2 = op.dup
  op2[0] = newop
  oldargs.each_with_index { |oa, i|
    # XXX bcctr 4, 6  ->  bcctr 4, 6, 0 => not the work
    if oa =~ /^[0-9]+$/ or oa =~ /^0x[0-9a-f]+$/i
      fld = op[2][i]
      op2[1] |= Integer(oa) << $field_shift[fld]
    end
  }
  puts "#\talias #{newop} #{newargs.join(', ')}  ->  #{oldop} #{oldargs.join(', ')}".downcase
end

require 'enumerator'
def epilog
  puts "\n\t@field_shift = {"
  puts $field_shift.sort_by { |k, v| k.to_s }.enum_slice(6).map { |slc|
    "\t\t" + slc.map { |k, v| "#{k.inspect} => #{v}" }.join(', ')
  }.join(",\n")
  puts "\t}"
  puts "\n\t@field_mask = {"
  puts $field_mask.sort_by { |k, v| k.to_s }.enum_slice(6).map { |slc|
    "\t\t" + slc.map { |k, v| "#{k.inspect} => #{v > 1000 ? '0x%X' % v : v}" }.join(', ')
  }.join(",\n")
  puts "\t}"
end

$foundop = false
def parse_page(lines)
  # all instr defining pages include this
  return unless lines.find { |l| l.str =~ /Special Registers Altered|Memory Barrier Instructions|Data Cache Instructions/  }	# sync L/dcbt

  ilist = [] # line buffer
  extended = false

  # concat lines with same y
  lines = lines.sort_by { |l| [-l.y, l.x] }
  lastline = nil
  lines.delete_if { |l|
    if lastline and lastline.y == l.y and ([lastline.fontx, lastline.fonty] == [l.fontx, l.fonty] or l.str =~ /^\s*$/)
      lastline.str << ' ' << l.str
      true
    else
      lastline = l
      false
    end
  }

  lines.each { |l|
    # search for the bit indices list
    if l.fonty < 7 and l.str =~ /^0 [\d ]+ 31\s*$/ and (ilist.last.str.split.length == l.str.split.length or ilist.last.str.split.length == l.str.split.length-1)
      $foundop = true
      bitindices = l.str.split.map { |i| i.to_i }
      # previous line is the binary encoding
      encoding = ilist.pop.str.split
      bitindices.pop if encoding.length < bitindices.length
      # previous line is the instruction text format
      ilist.pop if ilist.last.str =~ /\[POWER2? mnemonics?: (.*)\]/
      text = []
      text.unshift l while l = ilist.pop and l = l.str and (l =~ /,|\)$/ or text.empty?)
      ilist = []
      make_instr(encoding, bitindices, text)
    elsif l.str.include? 'Special Registers Altered'
      if not $foundop
        puts ilist.map { |l_| "(#{l_.y}) #{l_.str}" }
        puts lines.map { |l_| "(#{l_.y}) #{l_.str}" } if ilist.empty?
        raise 'nofoundop'
      else
        $foundop = false
      end
    elsif l.str =~ /Extended:\s+Equivalent to:/
      extended = true
    elsif extended
      if l.str.include? ',' and l.str =~ /^(\S+)\s+(\S+)\s+(\S+)\s+(.*)/ and $opcodes.find { |op| op[0] == $3 }
        newop, newargs, exop, exargs = $1, $2, $3, $4
        make_alias(newop, newargs.split(','), exop, exargs.split(','))
      else extended = false
      end
    else ilist << l
    end
  }
end

# PowerPC Architecture v2.02:
#  1 - User Instruction Set
#  2 - Virtual Environment
#  3 - Operating Environment
Dir['PPC_Vers202_Book?_public.pdf'].sort.each { |book|
  $stderr.puts book if $stderr.tty?
  pdf = PDF.read book
  pagecount = pdf.trailer['Root']['Pages']['Count'] || 0
  curpage = 0
  pdf.each_page { |p|
    $stderr.print "#{curpage+=1}/#{pagecount} \r" if $stderr.tty?
    p.clip_lines(50, 740)
    list = p.lines.flatten

    # split columns
    sp1, sp2 = list.partition { |l| l.x < 288 }

    parse_page(sp1)
    parse_page(sp2)
  }
  $stderr.print "           \r" if $stderr.tty?
}

epilog()
