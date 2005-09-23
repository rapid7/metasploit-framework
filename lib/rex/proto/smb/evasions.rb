module Rex
module Proto
module SMB
class Evasions

require 'rex/text'

EVASION_NONE  = 0
EVASION_LOW   = 1
EVASION_HIGH  = 2
EVASION_MAX   = 3

	# Causes sends to be broken into small pieces
	def self.send_block_size(level)		
		case level
			when EVASION_NONE
				return 0
			when EVASION_LOW
				return 125
			when EVASION_HIGH
				return 29
			when EVASION_MAX
				return 3
		end
	end
	
	# Slows down network traffic based on evasion level
	def self.send_wait_time(level)		
		case level
			when EVASION_NONE
				return 0
			when EVASION_LOW
				return 0.25
			when EVASION_HIGH
				return 0.25
			when EVASION_MAX
				return 0.25
		end
	end

	# Obscures a named pipe pathname via leading and trailing slashes
	def self.make_named_pipe_path(level, pipe)
		case level
			when EVASION_NONE
				return '\\' + pipe
			when EVASION_LOW
				return ('\\' * (1024 + rand(512))) + pipe
			when EVASION_HIGH, EVASION_MAX
				return ('\\' * (1024 + rand(512))) + pipe + ('\\' * (1024 + rand(512)))
		end	
	end
	
	# Obscures the TransactNamedPipe \PIPE\ string
	def self.make_trans_named_pipe_name(level)
		case level
			when EVASION_NONE
				return '\\PIPE\\'
			when EVASION_LOW
				return ('\\' * (1024 + rand(512))) + 'PIPE\\'
			when EVASION_HIGH
				return ('\\' * (1024 + rand(512))) + 'PIPE' + ('\\' * (1024 + rand(512)))
			when EVASION_MAX
				return Rex::Text.rand_text(4096 - rand(1024))
		end
	end	

end
end
end
end


