

module Msf

module ModuleTest
	attr_accessor :tests
	attr_accessor :failures

	def initialize(info={})
		@tests = 0
		@failures = 0
		super
	end

	def run_all_tests
		tests = self.methods.select { |m| m.to_s =~ /^test_/ }
		tests.each { |test_method|
			self.send(test_method)
		}

	end

	def it(msg="", &block)
		@tests  += 1
		begin
			result = block.call
			unless result
				print_error("FAILED: #{msg}")
				print_error("FAILED: #{error}") if error
				@failures  += 1
				return
			end
		rescue ::Exception => e
			print_error("FAILED: #{msg}")
			print_error("Exception: #{e.class} : #{e}")
			return
		end

		print_good("#{msg}")
	end

	def pending(msg="", &block)
		print_status("PENDING: #{msg}")
	end
end

module ModuleTest::PostTest
	include ModuleTest
	def run
		print_status("Running against session #{datastore["SESSION"]}")
		print_status("Session type is #{session.type}")
		print_status("Session platform is #{session.platform}")

		@tests = 0; @failures = 0
		run_all_tests

		vprint_status("Testing complete.")
		if (@failures > 0)
			print_error("Passed: #{@tests - @failures}; Failed: #{@failures}")
		else
			print_status("Passed: #{@tests - @failures}; Failed: #{@failures}")
		end
	end
end

end
