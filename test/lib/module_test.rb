


module Msf::ModuleTest
	attr_accessor :error

	def it(msg="", &block)
		begin
			result = block.call
			unless result
				print_error("FAILED: #{msg}")
				print_error("FAILED: #{error}") if error
				@error = nil
				return
			end
		rescue ::Exception => e
			print_error("FAILED: #{msg}")
			print_error("Exception: #{e.class} : #{e}")
			return
		end

		print_good("#{msg}")
	end
end



