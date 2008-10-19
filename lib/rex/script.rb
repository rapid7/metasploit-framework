#!/usr/bin/env ruby

module Rex

###
#
# This class provides an easy interface for loading and executing ruby
# scripts.
#
###
module Script

	#
	# Reads the contents of the supplied file and exeutes them.
	#
	def self.execute_file(file, in_binding = nil)
		str = ''

		File.open(file) { |f|
			begin
				while data = f.read and data.length > 0
					str += data
				end
			rescue EOFError
			end
		}

		execute(str, in_binding)
	end

	#
	# Executes arbitrary ruby from the supplied string.
	#
	def self.execute(str, in_binding = nil)
		eval(str, in_binding)
	end

end

end