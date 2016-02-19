#!/usr/bin/env ruby
# -*- coding: binary -*-

str = '# -*- coding: binary -*-'

fname = ARGV.shift || exit
data  = ''
done  = nil
fd = ::File.open(fname, "rb")
fd.each_line do |line|
  if line =~ /^#.*coding:.*/
    done = true
  end

 	if not done
    unless line =~ /^#\!.*env ruby/
      data << str + "\n"
      done = true
    end
  end

  data << line
end
fd.close

fd = ::File.open(fname, "wb")
fd.write(data)
fd.close
