module Msf
	module Simple
		module Framework
			module ModulePaths
				# Initialize the module paths
				#
				# @return [void]
				def init_module_paths
					# Ensure the module cache is accurate
					self.modules.refresh_cache_from_database

					# Initialize the default module search paths
					if (Msf::Config.module_directory)
						self.modules.add_path(
								Msf::Config.module_directory,
								gem: 'metasploit-framework',
								name: 'modules'
						)
					end

					# Initialize the user module search path
					if (Msf::Config.user_module_directory)
						self.modules.add_path(
								Msf::Config.user_module_directory,
								gem: 'metasploit-framework',
								name: 'user'
						)
					end

					# If additional module paths have been defined globally, then load them.
					# They should be separated by semi-colons.
					if self.datastore['MsfModulePaths']
						self.datastore['MsfModulePaths'].split(";").each { |path|
							self.modules.add_path(path)
						}
					end
				end
			end
		end
	end
end