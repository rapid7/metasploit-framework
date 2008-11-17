#!/usr/bin/env ruby

#
#   $Id: objdumptoc.rb 40 2008-11-17 02:45:30Z ramon $
#
#   objdumptoc.rb - Convert GNU objdump output to C source
#   Copyright 2007 Ramon de Carvalho Valle <ramon@risesecurity.org>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
#

class Parser

	SIZE1 = 28
	SIZE2 = 28 + 4 + 32
	SIZE3 = 28 + 4 + 32 + 4

	attr_accessor :file, :block, :block_size

	def initialize(filename)
		unless filename.empty?
			self.file = File.new(filename)
		else
			self.file = STDIN
		end

		self.block = Array.new
		self.block_size = 0
	end

	def block_begin(line)
		# Get the block name from label
		temp = line.scan(/\w+/)
		block_name = temp[1].delete('<>:')

		self.block << Array.new
		self.block[-1] << "char #{block_name}[]="
	end

	def block_end
		# Insert the block size
		self.block[-1][0] = block[-1][0].ljust(SIZE1)
		self.block[-1][0] << '/*  '
		self.block[-1][0] << "#{block_size} bytes"
		self.block[-1][0] = block[-1][0].ljust(SIZE2)
		self.block[-1][0] << '  */'

		# Reset the block size
		self.block_size = 0

		self.block[-1] << ';'
		self.block[-1] << ''
	end

	def block_do(line)
		temp = line.split("\t")

		temp[1].strip!
		temp[1] = temp[1].scan(/\w+/)

		self.block[-1] << '    "'

		temp[1].each do |byte|
			self.block[-1][-1] << "\\x#{byte}"
			self.block_size += 1
		end

		self.block[-1][-1] << '"'
		self.block[-1][-1] = block[-1][-1].ljust(SIZE1)
		self.block[-1][-1] << '/*  '

		# For file format aixcoff-rs6000
		if temp.length == 4
			temp[2] << ' '
			temp[2] << temp[3]
			temp.pop
		end

		if temp.length == 3
			temp[2].strip!
			temp[2] = temp[2].scan(/[$%()+,\-\.<>\w]+/)

			if temp[2].length == 2
				self.block[-1][-1] << temp[2][0].ljust(8)
				self.block[-1][-1] << temp[2][1]
			elsif temp[2].length == 3
				self.block[-1][-1] << temp[2][0].ljust(8)
				self.block[-1][-1] << temp[2][1]
				self.block[-1][-1] << ' '
				self.block[-1][-1] << temp[2][2]
			else
				self.block[-1][-1] << temp[2].to_s
			end
		end

		self.block[-1][-1] = block[-1][-1].ljust(SIZE2)
		self.block[-1][-1] << '  */'
	end

	def parse_line(line)
		if line =~ /\w+ <[\.\w]+>:/
			# End a previous block
			unless block_size == 0
				block_end
			end
			block_begin(line)

		elsif line =~ /\w+:\t/
			block_do(line)

		end
	end

	def parse_file(file)
		while (line = file.gets)
			parse_line(line)
		end

		# End the last block
		unless block_size == 0
			block_end
		end
	end

	def parse
		parse_file(file)
	end

	def dump_all
		block.each do |block|
			block.each do |line|
				print "#{line}\n"
			end
		end
	end

end

unless STDIN.tty?
	p = ::Parser.new('')
	p.parse
	p.dump_all
else
	print "Tested with:\n"
	print "\tGNU objdump 2.9-aix51-020209\n"
	print "\tGNU objdump 2.15.92.0.2 20040927\n"
	print "Usage: objdump -dM suffix <file(s)> | ruby objdumptoc.rb\n"
end
