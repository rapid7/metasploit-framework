#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory



class IO
def hexdump(ctx={})
	ctx[:noend] = true
	while buf = read(512) and not buf.empty?
		buf.hexdump(ctx)
	end
	ctx.delete :noend
	''.hexdump(ctx)
end
end

class String
def hexdump(ctx={})
	fmt = ctx[:fmt] ||= ['c', 'd', 'a']
	ctx[:pos] ||= 0
	ctx[:linelen] ||= 16
	scan(/.{1,#{ctx[:linelen]}}/m) { |s|
		if s != ctx[:lastline]
			ctx[:lastdup] = false
			print '%04x  ' % ctx[:pos]
			print s.unpack('C*').map { |b| '%02x' % b }.join(' ').ljust(3*16-1) + '  ' if fmt.include? 'c'
			print s.unpack('v*').map { |b| '%04x' % b }.join(' ').ljust(5*8-1)  + '  ' if fmt.include? 'w'
			print s.unpack('L*').map { |b| '%08x' % b }.join(' ').ljust(9*4-1)  + '  ' if fmt.include? 'd'
			print s.tr("\0-\x1f\x7f-\xff", '.') if fmt.include? 'a'
			puts
		elsif not ctx[:lastdup]
			ctx[:lastdup] = true
			puts '*'
		end
		ctx[:lastline] = s
		ctx[:pos] += s.length
	}
	puts '%04x' % ctx[:pos] if not ctx[:noend]
end
end

if $0 == __FILE__
	fmt = ['c', 'a'] if ARGV.delete '-C'
	fmt = ['d', 'a'] if ARGV.delete '-d'
	fmt = ['c', 'd', 'a'] if ARGV.delete '-a'
	File.open(ARGV.first, 'rb').hexdump(:fmt => fmt)
end
