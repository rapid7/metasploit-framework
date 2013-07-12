# A set of {Metasploit::Framework::Module::Path
# Metasploit::Framework::Module::Paths} or Mdm::Module::Paths (depending
# on if the database is active.)
class Metasploit::Framework::Module::PathSet::Base
	# Adds path to this set.
	#
	# @param path [String] path with modules
	# @param options [Hash{Symbol => String}]
	# @option options [String] :gem The name of the gem that is adding this
	#   module path to metasploit-framework.  For paths normally added by
	#   metasploit-framework itself, this would be `'metasploit-framework'`,
	#   while for Metasploit Pro this would be `'metasploit-pro'`.  The
	#   name used for `gem` does not have to be a gem on rubygems, it just
	#   functions as a namespace for :name so that projects using
	#   metasploit-framework do not need to worry about collisions on
	#   :name which could disrupt the cache behavior.
	# @option options [String] :name The name scoped to :gem of path.
	# @raise [NotImplementedError]
	def add(path, options={})
		raise NotImplementedError,
					"#{self.class.name}##{__method__} is not implemented"
	end

	# @!attribute [r] framework
	#   The framework that is loading the modules on the paths in this set.
	#
	#   @return [Msf::Simple::Frameo]
	attr_reader :framework

	# @param attributes [Hash{Symbol => Object}]
	# @option attributes [Msf::Simple::Framework] :framework framework using
	#   these module paths.
	def initialize(attributes={})
		attributes.assert_valid_keys(:framework)

		@framework = attributes.fetch(:framework)
	end
end
