module Msf
module Ui
module Console
module CommandDispatcher

class Recon

	include Msf::Ui::Console::ModuleCommandDispatcher

	def name
		"Recon"
	end

	def commands
		{
			"discover" => "Initiates the recon discovery process for this module",
		}
	end

	#
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
