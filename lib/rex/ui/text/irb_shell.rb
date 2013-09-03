# -*- coding: binary -*-
module Rex
module Ui
module Text

###
#
# This class wraps the creation of an IRB shell.
#
###
class IrbShell

	@@IrbInitialized = false

	def initialize(binding)
		@binding_ctx = binding
	end

	#
	# Runs the IRB shell until completion.  The binding parameter initializes
	# IRB to the appropriate binding context.
	#
	def run
		# Initialize IRB by setting up its internal configuration hash and
		# stuff.
		if (@@IrbInitialized == false)
			load('irb.rb')

			IRB.setup(nil)
			IRB.conf[:PROMPT_MODE]  = :SIMPLE

			@@IrbInitialized = true
		end

		# Create a new IRB instance
		irb = IRB::Irb.new(IRB::WorkSpace.new(@binding_ctx))

		# Set the primary irb context so that exit and other intrinsic
		# commands will work.
		IRB.conf[:MAIN_CONTEXT] = irb.context

		# Trap interrupt
		old_sigint = trap("SIGINT") do
			begin
				irb.signal_handle
			rescue RubyLex::TerminateLineInput
				irb.eval_input
			end
		end

		# Keep processing input until the cows come home...
		catch(:IRB_EXIT) do
			irb.eval_input
		end

		trap("SIGINT", old_sigint)
	end

end
end
end
end
