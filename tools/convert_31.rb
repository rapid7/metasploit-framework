#!/usr/bin/env ruby
#
# $Id$
# $Revision$
#

path = ARGV.shift || exit
data = File.read(path)
outp = ""

endc = 0
data.each_line do |line|
  if(line =~ /^\s*module\s+[A-Z]/)
    endc += 1
    next
  end

  if(line =~ /^(\s*)include (.*)/)
    spaces = $1
    inc = $2
    if (inc !~ /Msf/)
      line = "#{spaces}include Msf::#{inc.strip}\n"
    end
  end

  if(line =~ /^(\s*)class ([^\<]+)\s*<\s*(.*)/)
    prefix = ""
    spaces = $1
    parent = $3

    if(parent !~ /^Msf/)
      prefix = "Msf::"
    end
    line = "#{spaces}class Metasploit3 < #{prefix}#{parent.strip}\n"
  end

  outp += line
end



endc.downto(1) do |idx|
  i = outp.rindex("end")
  outp[i, 4] = "" if i
end

outp.rstrip!
outp << "\n"

fd = File.open(path, "wb")
fd.write(outp)
fd.close
