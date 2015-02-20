#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm plugin: allow loading library signature files (see samples/generate_libsigs.rb)

class LibSignature
attr_accessor :sigs, :siglenmax, :giantregex
# load signatures from a signature file
def initialize(file)
  # hash symbolname => signature
  @sigs = {}

  # populate sigs
  symname = nil
  sig = ''
  File.read(file).each_line { |l|
    case l
    when /^ /
      sig << l.strip
    else
      @sigs[symname] = sig
      symname = l.strip
      sig = ''
    end
  }
  @sigs[symname] = sig
  @sigs.delete nil
  @siglenmax = @sigs.values.map { |v| v.length }.max

  # compile a giant regex from the signatures
  re = @sigs.values.uniq.map { |sigh|
    sigh.gsub(/../) { |b| b == '..' ? '.' : ('\\x' + b) }
  }.join('|')

  # 'n' is a magic flag to allow high bytes in the regex (ruby1.9 + utfail)
  @giantregex = Regexp.new re, Regexp::MULTILINE, 'n'
end

# we found a match on str at off, identify the specific symbol that matched
# on conflict, only return the first match
def matched_findsym(str, off)
  str = str[off, @siglenmax].unpack('H*').first
  @sigs.find { |sym, sig| str =~ /^#{sig}/i }[0]
end

# matches the signatures against a raw string
# yields offset, symname for each match
# returns nr of matches found
def match_chunk(str)
  count = 0
  off = 0
  while o = (str[off..-1] =~ @giantregex)
    count += 1
    off += o
    sym = matched_findsym(str, off)
    yield off, sym
    off += 1
  end
  count
end

# matches the signatures against a big raw string
# yields offset, symname for each match
# returns nr of matches found
def match(str)
  chunksz = 1 << 20

  chunkoff = 0
  count = 0
  while chunkoff < str.length
    chunk = str[chunkoff, chunksz+@siglenmax]
    count += match_chunk(chunk) { |o, sym| yield chunkoff+o, sym if o < chunksz }
    chunkoff += chunksz
  end
  count
end
end

def match_libsigs(sigfile)
  ls = LibSignature.new(sigfile)
  count = 0
  @sections.each { |b, s|
    count += ls.match(s.data) { |off, sym| set_label_at(b+off, sym) }
  }
  count
end

if gui
  gui.openfile('signature file to load') { |f| gui.messagebox "#{match_libsigs(f)} signatures found" }
end
