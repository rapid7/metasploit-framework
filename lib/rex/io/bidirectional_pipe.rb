# -*- coding: binary -*-
module Rex
module IO

require 'rex/ui/text/output'
require 'rex/ui/text/output/buffer'
require 'rex/ui/text/input/buffer'

class BidirectionalPipe < Rex::Ui::Text::Input

	def initialize
		@subscribers_out = {}
		@subscribers_ref = {}
		@subscribers_idx = 0
		@pipe_input = Rex::Ui::Text::Input::Buffer.new

		# We are the shell, the input, and the output
		self.output = self
		self.input  = self
	end

	def pipe_input
		@pipe_input
	end

	def close
		@pipe_input.close
	end

	def has_subscriber?(id)
		@subscribers_out.has_key?(id)
	end

	def create_subscriber(id=nil)
		id ||= (@subscribers_idx += 1).to_s
		@subscribers_out[id] = Rex::Ui::Text::Output::Buffer.new
		return id
	end

	def create_subscriber_proc(id=nil, &block)
		id = create_subscriber(id)
		@subscribers_ref[id] = block
	end

	def remove_subscriber(id)
		@subscribers_out.delete(id)
		@subscribers_ref.delete(id)
	end

	def write_input(buf)
		@pipe_input.put(buf)
	end

	def read_subscriber(id)
		output = @subscribers_out[id]

		return '' if output.nil?

		buf = output.buf

		output.reset

		buf
	end

	def print(msg='')
		@subscribers_out.each_pair { |id, buf|
			begin
				@subscribers_ref[id] ? @subscribers_ref[id].call(msg) : buf.print(msg)
			rescue ::Exception => e
				# $stderr.puts "Error handling subscriber #{id}: #{e} #{e.backtrace.inspect}"
				raise e
			end
		}
		msg
	end

	def print_error(msg='')
		print_line('[-] ' + msg)
	end

	def print_line(msg='')
		print(msg + "\n")
	end

	def print_good(msg='')
		print_line('[+] ' + msg)
	end

	def print_debug(msg='')
		print_line('[!] ' + msg)
	end

	def flush
	end

	def print_status(msg='')
		print_line('[*] ' + msg)
	end

	def print_warning(msg='')
		print_line('[!] ' + msg)
	end

	#
	# Wrappers for the pipe_input methods
	#

	def close
		@pipe_input.close
	end

	def sysread(len = 1)
		@pipe_input.sysread(len)
	end

	def put(msg)
		@pipe_input.put(msg)
	end

	def gets
		@pipe_input.gets
	end

	def eof?
		@pipe_input.eof?
	end

	def fd
		@pipe_input.fd
	end

	#
	# Wrappers for shell methods
	#

	attr_accessor :output, :prompt, :input

	def intrinsic_shell?
		true
	end

	def supports_readline
		false
	end

	def supports_color?
		false
	end

	def pgets
		gets
	end


protected

end

end
end
