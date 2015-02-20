#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# shows the preprocessor path to find a specific line
# usage: ruby chdr-find.rb 'regex pattern' list of files.h
#

def gets
  l = $ungets
  $ungets = nil
  l || super()
end

def parse(root=false)
  want = false
  ret = []
  while l = gets
    case l = l.strip
    when /^#if/
      ret << l
      r = parse(true)
      if r.empty?
        ret.pop
      else
        want = true
        rr = r.pop
        ret.concat r.map { |l_| (l_[0,3] == '#el' ? ' ' : '    ') << l_ }
        ret << rr
      end
    when /^#el/
      if not root
        $ungets = l
        break
      end
      ret << l
      r = parse
      want = true if not r.empty?
      ret.concat r
    when /^#endif/
      if not root
        $ungets = l
        break
      end
      ret << l
      break
    when /#$srch/ #, /^#include/
      want = true
      ret << l
    end
  end
  want ? ret : []
end

$srch = ARGV.shift
puts parse
