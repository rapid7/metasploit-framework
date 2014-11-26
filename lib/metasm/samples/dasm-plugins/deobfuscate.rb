#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# To use your own patterns, create a script that defines Deobfuscate::Patterns, then eval() this file.
# Use your script as argument to --plugin
#
# This script is to be used with the --plugin option of samples/disassemble(-gtk).rb
# It holds methods to ease the definition of instruction patterns that are to be replaced
# by another arbitrary instruction sequence, using mostly a regexp syntax
#
# The pattern search&replace is done every time the disassembler
# finds a new instruction, through the callback_newinstr callback.
#
# The patterns can use shortcuts for frequently-used regexps (like 'any machine registers'),
# defined in the PatternMacros hash.
#
# The patterns are matched first against the sequence of instruction opcode names, then
# each instruction is rendered as text (using Instruction#to_s), and the global regexp
# is checked.
# Backreferences can be used in the substitution instruction sequence, through the %1 ... %9
# special values.
#
# A pattern consists of a sequence of regexp for instructions, separated by ' ; '
# Each subregexps should not match multiple instructions (ie a patterns matches a fixed-length
# instruction sequence, whose length equals the number of ' ; '-separated regexps)
# The first word of each regexp should match only the instruction opcode name.
#
# The substitution may be a Proc, which will receive |dasm object, matched decodedinstr list| as
# arguments, and should return:
# a String, holding a sequence of instructions separated by ' ; ', which will be parsed by the CPU (no labels allowed)
# nil if the pattern did not match, continue searching
# an Array of Instruction/DecodedInstruction. If the array is the original di list, same as returning nil
#
# If the substitution array is different from the matched sequence, the new instructions are passed
# to dasm.replace_instrs, which will patch the disassembler decoded instruction graph ; and each
# new instruction is passed through the callback once more, allowing for recursive patterns.
#

module Deobfuscate


# special constructs : %i => an integer (immediate/standard label)
#                      %r => standard x86 register (except esp), all sizes
#                      %m => modr/m 32 (memory indirection or reg)
PatternMacros = {
  '%i' => '(?:-|loc_|sub_|xref_)?[0-9][0-9a-fA-F]*h?',
  '%r' => '(?:[re]?[abcd]x|[re]?[sd]i|[re]?bp|[abcd][lh])',
  '%m' => '(?:(?:dword ptr )?\[.*?\]|eax|ebx|ecx|edx|edi|esi|ebp)',
} if not defined? PatternMacros




# instructions are separated by ' ; '
# instruction must be '<simple regexp matching opcode> <arbitrary regexp>'
# in the pattern target, %1-%9 are used for backreferences from the regexp match
Patterns = {
  'nop ; (.*)' => '%1',	# concat 'nop' into following instruction
  'mov (%r|esp), \1' => 'nop',
  'lea (%r|esp), (?:dword ptr )?\[\1(?:\+0)?\]' => 'nop',
  '(.*)' => lambda { |dasm, list| # remove 'jmp imm' preceding us without interfering with running dasm
    if pdi = prev_di(dasm, list.last) and pdi.opcode.name == 'jmp' and
        pdi.instruction.args[0].kind_of? Metasm::Expression
      dasm.replace_instrs(pdi.address, pdi.address, [])
    end
    nil
  },
  #'call %i ; pop (%r)' => lambda { |dasm, list| "mov %1, #{list.first.next_addr}" },
} if not defined? Patterns




# returns an array of strings matching the regexp (only |,?,[], non-nested allowed, no special chars)
# expand_regexp['a[bcd]?(ef|gh)'] => [abef acef adef aef abgh acgh adgh agh]
def self.expand_regexp(str)
  case str
  when nil, '', '.*'; return [str.to_s]
  when /^\\\./
    l1, p2 = ['.'], $'
  when /^(\w+)(\?)?/
 		s1, q, p2 = $1, $2, $'
    l1 = (q ? [s1, s1.chop] : [s1])
  when /^\[(.*?)\](\?)?/
    p1, q, p2 = $1, $2, $'
    l1 = p1.split(//)
    l1 << '' if q
  when /^\((?:\?:)?(.*?)\)(\?)?/
    p1, q, p2 = $1, $2, $'
    l1 = p1.split('|').map { |p| expand_regexp(p) }.flatten
    l1 << '' if q
  else raise "bad pattern #{str.inspect}"
  end
 	expand_regexp(p2).map { |s2| l1.map { |s1_| s1_ + s2 } }.flatten.uniq
end

# find the instr preceding adi ; follows from_normal if it is a single element array
def self.prev_di(dasm, di)
  if di.block.list.first != di
    di.block.list[di.block.list.index(di)-1]
  elsif di.block.from_normal.to_a.length == 1
    dasm.decoded[di.block.from_normal.first]
  end
end

# preprocess the pattern list to optimize matching on each new instruction
# last pattern instr opname => prev instr opname => prev instr opname => :pattern => [patterns]
def self.generate_precalc(next_hash, next_ops, pattern)
  if next_ops.empty?
    next_hash[:pattern] ||= []
    next_hash[:pattern] << pattern
  else
    (expand_regexp(next_ops[-1]) rescue ['.*']).each { |op|
      nh = next_hash[op] ||= {}
      generate_precalc(nh, next_ops[0...-1], pattern)
    }
  end
end

PrecalcPatterns = {} if not defined? PrecalcPatterns

# replace Macros in patterns, do some precalc to speedup pattern matching
def self.init
  PrecalcPatterns.clear
  Patterns.keys.each { |pat|
    # replace PatternMacros in patterns
    newp = pat.dup
    PatternMacros.each { |mk, mv| newp.gsub!(mk, mv) }
    Patterns[newp] = Patterns.delete(pat) if pat != newp
    pat = newp

    # TODO handle instructions with prefix (lock/rep), conditional regexp over multiple instructions..
    ops = pat.split(' ; ').map { |instr| instr[/^\S+/] }

    generate_precalc(PrecalcPatterns, ops, pat)
  }
end

# the actual disassembler callback
# checks the current instruction opname against the end of patterns using precomputed tree, then check  previous instr etc
# once full pattern may match, convert each instr to string, and run the regexp match
# on match, reuse the captures in the pattern target, parse the target, generate decoded instrs, and replace in the dasm graph.
# on match, rerun the callback on each replaced instruction (for recursive patterns)
def self.newinstr_callback(dasm, di)
  # compute the merged subtree of t1 and t2
  # merges patterns if found
  mergetree = lambda { |t1, t2|
    if t1 and t2
      case t1
      when Array; t1 + t2
      when Hash; (t1.keys | t2.keys).inject({}) { |t, k| t.update k => mergetree[t1[k], t2[k]] }
      end
    else t1 || t2
    end
  }

  di_seq = [di]
  lastdi = di
  tree = PrecalcPatterns
  tree = mergetree[tree['.*'], tree[lastdi.instruction.opname]]
  newinstrs = match = nil
  # walk the Precalc tree
  while tree
    if tree[:pattern]
      strs = di_seq.map { |pdi| pdi.instruction.to_s }
      break if tree[:pattern].find { |pat|
        if match = /^#{pat}$/.match(strs.join(' ; '))
          newinstrs = Patterns[pat]
          newinstrs = newinstrs[dasm, di_seq] if newinstrs.kind_of? Proc
          newinstrs = nil if newinstrs == di_seq
        else newinstrs = nil
        end
        newinstrs
      } or tree.length == 1
    end

    if lastdi = prev_di(dasm, lastdi)
      di_seq.unshift lastdi
      tree = mergetree[tree['.*'], tree[lastdi.instruction.opname]]
    else break
    end
  end

  # match found : create instruction stream, replace in dasm, recurse
  if newinstrs
    # replace %1-%9 by the matched substrings
    newinstrs = newinstrs.gsub(/%(\d)/) { match.captures[$1.to_i-1] }.split(' ; ').map { |str| dasm.cpu.parse_instruction(str) } if newinstrs.kind_of? String
    if newinstrs.last.kind_of? Metasm::Instruction and newinstrs.last.opname != 'jmp' and
        lastdi.address + di_seq.inject(-di.bin_length) { |len, i| len + i.bin_length } != di.address
      # ensure that the last instr ends the same place as the original last instr (to allow disassemble_block to continue)
      newinstrs << dasm.cpu.parse_instruction("jmp #{Metasm::Expression[di.next_addr]}")
      # nop ; jmp => jmp
      newinstrs.shift if newinstrs.length >= 2 and newinstrs.first.kind_of? Metasm::Instruction and newinstrs.first.opname == 'nop'
    end

    # remove instructions from the match to have only 2 linked blocks passed to replace_instrs
    unused = di_seq[1..-2] || []
    unused.delete_if { |udi| udi.block.address == di_seq[0].block.address or udi.block.address == di_seq[-1].block.address }
    dasm.replace_instrs(unused.shift.address, unused.shift.address, []) while unused.length > 1
    dasm.replace_instrs(unused.first.address, unused.first.address, []) if not unused.empty?

    # patch the dasm graph
    if dasm.replace_instrs(lastdi.address, di.address, newinstrs, true)
      puts ' deobfuscate', di_seq, ' into', newinstrs, ' ---' if $DEBUG
      # recurse, keep the last generated di to return to caller as replacement
      newinstrs.each { |bdi| di = newinstr_callback(dasm, bdi) || di }
    else
      di = nil
    end
  end

  di
end

# call newinstr_callback on all existing instructions of dasm
def self.deobfuscate_existing(dasm)
  dasm.each_instructionblock { |b|
    b.list.dup.each { |di| newinstr_callback(dasm, di) }
  }
end

# calls dasm.merge_blocks(true) on all instruction blocks to merge sequences of blocks
def self.merge_blocks(dasm)
  dasm.each_instructionblock { |b|
    if pv = dasm.di_at(b.from_normal.to_a.first) and not pv.block.list.last.opcode.props[:setip] and
        b.from_normal.length == 1 and pv.block.to_normal.to_a.length == 1
      dasm.merge_blocks(pv.block, b, true)
    end
  }
end
end

if $DEBUG
# update DecodedInstr.to_s to include instr length
class Metasm::DecodedInstruction
  def to_s ; "#{Metasm::Expression[address] if address} +#{bin_length} #{instruction}" end
end
end

# do the pattern precalc
Deobfuscate.init

if self.kind_of? Metasm::Disassembler
dasm = self
# setup the newinstr callback
dasm.callback_newinstr = lambda { |di| Deobfuscate.newinstr_callback(dasm, di) }
end
