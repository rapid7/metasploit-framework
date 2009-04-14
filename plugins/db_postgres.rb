
module Msf
class Plugin::DeprecatedStub < Msf::Plugin
	def name
		"Deprecated_plugin_stub"
	end
	def initialize(framework, opts)
		super
		print_error("")
		print_error("The functionality previously provided by this plugin has been")
		print_error("integrated into the core command set.  Use the new 'db_driver'")
		print_error("command to use a database driver other than sqlite3 (which")
		print_error("is now the default).  All of the old commands are the same.")
		print_error("")
		raise RuntimeError.new("Deprecated plugin")
	end
end
end

