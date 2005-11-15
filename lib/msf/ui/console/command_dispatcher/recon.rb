module Msf
module Ui
module Console
module CommandDispatcher

###
#
# Recon module command dispatcher.
#
###
class Recon

	include Msf::Ui::Console::ModuleCommandDispatcher

	#
	# Returns the hash of commands specific to recon modules.
	#
	def commands
		{
			"discover" => "Initiates the recon discovery process for this module",
		}
	end

	#
	#
	# Returns the command dispatcher name.
	#
	def name
		"Recon"
	end

	# Starts discovering like a good recon module should.
	#
	def cmd_discover(*args)
		begin
			mod.discover_simple(
				'LocalInput'  => driver.input,
				'LocalOutput' => driver.output)
		rescue
			log_error("Recon failed: #{$!}")
			return false
		end
	end

end

end end end end
