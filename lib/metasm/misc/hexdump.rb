#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory



require 'enumerator'

class String
def hexdump
	o = -16
	lastl = []
	lastdpl = false
	unpack('C*').each_slice(16) { |s|
		o += 16
		if s != lastl
			lastdpl = false
			print '%04x  ' % o
			print s.map { |b| '%02x' % b }.join(' ').ljust(3*16-1) + '  '
			print s.pack('C*').unpack('L*').map { |bb| '%08x' % bb }.join(' ').ljust(9*4-1) + '  '
			puts  s.map { |c| (32..126).include?(c) ? c : ?. }.pack('C*')
		elsif not lastdpl
			lastdpl = true
			puts '*'
		end
		lastl = s
	}
	puts '%04x' % length
end
end

if $0 == __FILE__
	File.open(ARGV.first, 'rb') { |fd| fd.read }.hexdump
end
