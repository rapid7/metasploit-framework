module Msf
module Ui
module Console
module CommandDispatcher

###
#
# Recon module command dispatcher.
#
###
class Auxiliary

	include Msf::Ui::Console::ModuleCommandDispatcher

	#
	# Returns the hash of commands specific to auxiliary modules.
	#
	def commands
		{
			"run" => "Initiates the auxiliary module",
		}.merge( (mod ? mod.auxiliary_commands : {}) )
	end

	#
	# Allow modules to define their own commands :-)
	#
	def method_missing(meth, *args)
		if (mod and mod.respond_to?(meth.to_s)) 
			return mod.send(meth.to_s, *args)
		end
		return
	end

	#
	#
	# Returns the command dispatcher name.
	#
	def name
		"Auxiliary"
	end

	# Executes the standard 'run' command
	#
	def cmd_run(*args)
		begin
			mod.run_simple(
				'LocalInput'  => driver.input,
				'LocalOutput' => driver.output)
		rescue
			log_error("Auxiliary failed: #{$!}")
			return false
		end
	end

end

end end end end
