#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory



synclen = 6
ctxlen = 16

file1 = ('x'*ctxlen) + File.read(ARGV.shift)
file2 = ('x'*ctxlen) + File.read(ARGV.shift)

count1 = count2 = ctxlen

# prints the string in 80 cols
# with the first column filled with +pfx+
def show(pfx, str)
	loop do
		if str.length > 79
			len = 79 - str[0...79][/\S+$/].to_s.length
			len = 79 if len == 0
			puts pfx + str[0...len]
			str = str[len..-1]
		else
			puts pfx + str
			break
		end
	end
end

loop do
	w1 = file1[count1]
	w2 = file2[count2]
	break if not w1 and not w2
	if w1 == w2
		count1 += 1
		count2 += 1
	else
		diff1 = diff2 = nil
		catch(:resynced) {
		1000.times { |depth|
			(-depth..depth).map { |d|
				if d == 0
					[depth, depth]
				elsif d < 0
					[depth, depth+d]
				elsif d > 0
					[depth-d, depth]
				end
			}.each { |dc1, dc2|
				next if !(0...synclen).all? { |i| file1[count1 + dc1 + i] == file2[count2 + dc2 + i] }

				puts "@#{(count1-ctxlen).to_s 16} #{(count2-ctxlen).to_s 16}"
				show ' ', file1[count1-ctxlen, ctxlen].inspect
				if dc1 > 0
					show '-', file1[count1, dc1].inspect
				end
				if dc2 > 0
					show '+', file2[count2, dc2].inspect
				end
				count1 += dc1
				count2 += dc2
				show ' ', file1[count1, ctxlen].inspect
				puts

				throw :resynced
			}
		}
		raise 'nomatch..'
		}
	end
end
