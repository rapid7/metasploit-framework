require 'msf/ui'

module Msf
module Ui
module Console

###
#
# InputMethod
# -----------
#
# This class is the base class for the three kinds of console input methods:
# Stdio, File, and Readline.  These classes are nearly idential to the classes
# found in irb.
#
###
class InputMethod
	def initialize
		self.eof = false
	end

	def gets
		raise NotImplementedError
	end

	def eof?
		return eof
	end

	attr_accessor :prompt, :eof
end

class StdioInputMethod < InputMethod
	def gets
		print prompt
		return $stdin.gets
	end

	def eof?
		return $stdin.eof?
	end
end

begin 
	require 'readline'

	class ReadlineInputMethod < InputMethod
		include Readline

		def gets
			if ((line = readline(prompt, true)))
				HISTORY.pop if (line.empty?)
				return line + "\n"
			else
				eof = true
				return line
			end
		end
	end
rescue LoadError
end

class FileInputMethod < InputMethod
end

end
end
end
