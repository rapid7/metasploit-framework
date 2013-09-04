class Metasploit::Framework::Module::Ancestor < Metasploit::Model::Base
	include Metasploit::Model::Module::Ancestor

	#
	# CONSTANTS
	#

	MODULE_TYPE_BY_DIRECTORY = DIRECTORY_BY_MODULE_TYPE.invert
end

# Explicitly require modules under class so lexical scopes won't resolve
# `Metasploit::Framework::Module::Ancestor::Error::Base` to
# `ActiveModel::MassAssignmentSecurity::Error::Base`
require 'metasploit/framework/module/ancestor/error/base'
require 'metasploit/framework/module/ancestor/error/metasploit_module_incompatibility'
require 'metasploit/framework/module/ancestor/error/version_incompatibility'