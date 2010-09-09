#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# A script to help finding performance bottlenecks:
# ruby-prof myscript.rb
#  => String#+ gets called 50k times and takes 30s
# LOGCALLER='String#+' ruby -r log_caller myscript.rb
#  => String#+ called 40k times from:
#      stuff.rb:42 in Myclass#uglymethod from
#      stuff.rb:32 in Myclass#initialize
# now you know what to rewrite


def log_caller(cls, meth, histlen=-1)
	malias = meth.to_s.gsub(/[^a-z0-9_]/i, '') + '_log_caller'
	mcntr = '$' + meth.to_s.gsub(/[^a-z0-9_]/i, '') + '_counter'
	eval <<EOS
class #{cls}
 alias #{malias} #{meth}
 def #{meth}(*a, &b)
  #{mcntr}[caller[0..#{histlen}]] += 1
  #{malias}(*a, &b)
 end
end

#{mcntr} = Hash.new(0)
at_exit { puts " callers of #{cls} #{meth}:", #{mcntr}.sort_by { |k, v| -v }[0, 4].map { |k, v| ["\#{v} times from", k, ''] } }
EOS
end

if ENV['LOGCALLER'] =~ /^(.*)#(.*)$/
	cls, meth = $1, $2.to_sym
	cls = cls.split('::').inject(Object) { |o, cst| o.const_get(cst) }
	log_caller(cls, meth)
end
