#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# this script reads a list of elf files, and lists its dependencies recursively
# libraries are searched in LD_LIBRARY_PATH, /usr/lib and /lib
# includes the elf interpreter
# can be useful when chrooting a binary
#

require 'metasm'


paths = ENV['LD_LIBRARY_PATH'].to_s.split(':') + %w[/usr/lib /lib]
todo = ARGV.map { |file| (file[0] == ?/) ? file : "./#{file}" }
done = []
while src = todo.shift
	puts src
	# could do a simple ELF.decode_file, but this is quicker
	elf = Metasm::ELF.decode_file_header(src)

	if s = elf.segments.find { |s_| s_.type == 'INTERP' }
		interp = elf.encoded[s.offset, s.filesz].data.chomp("\0")
		if not done.include? interp
			puts interp
			done << interp
		end
	end

	elf.decode_tags
	elf.decode_segments_tags_interpret
	deps = elf.tag['NEEDED'].to_a - done
	done.concat deps

	deps.each { |dep|
		if not path = paths.find { |path_| File.exist? File.join(path_, dep) }
			$stderr.puts "cannot find #{dep} for #{src}"
		else
			todo << File.join(path, dep)
		end
	}
end
