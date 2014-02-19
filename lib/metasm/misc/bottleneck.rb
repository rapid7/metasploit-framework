#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# A script to help finding performance bottlenecks:
#
# $ ruby-prof myscript.rb
#  => String#+ gets called 50k times and takes 30s
#
# $ LOGCALLER='String#+' ruby -r bottleneck myscript.rb
#  => String#+ called 40k times from:
#      stuff.rb:42 in Myclass#uglymethod from
#      stuff.rb:32 in Myclass#initialize
#
# now you know what to rewrite



def log_caller(cls, meth, singleton=false, histlen=nil)
  histlen ||= ENV.fetch('LOGCALLER_MAXHIST', 16).to_i
  dec_meth = 'm_' + meth.to_s.gsub(/[^\w]/) { |c| c.unpack('H*')[0] }
  malias = dec_meth + '_log_caller'
  mcntr = '$' + dec_meth + '_counter'
  eval <<EOS

#{cls.kind_of?(Class) ? 'class' : 'module'} #{cls}
#{'class << self' if singleton}
 alias #{malias} #{meth}

 def #{meth}(*a, &b)
  #{mcntr}[caller[0, #{histlen}]] += 1
  #{malias}(*a, &b)
 end

#{'end' if singleton}
end

#{mcntr} = Hash.new(0)

at_exit {
  total = #{mcntr}.inject(0) { |a, (k, v)| a+v } 
  puts "\#{total} callers of #{cls} #{meth}:"
  #{mcntr}.sort_by { |k, v|
    -v
  }[0, 4].each { |k, v|
    puts " \#{'%.2f%%' % (100.0*v/total)} - \#{v} times from", k, ''
  }
}

EOS

end

ENV['LOGCALLER'].to_s.split(';').map { |lc|
  next if not lc =~ /^(.*)([.#])(.*)$/
  cls, sg, meth = $1, $2, $3.to_sym
  sg = { '.' => true, '#' => false }[sg]
  cls = cls.split('::').inject(::Object) { |o, cst| o.const_get(cst) }
  log_caller(cls, meth, sg)
}
