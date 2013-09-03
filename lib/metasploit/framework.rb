# Top-level namespace that is shared between {Metasploit::Framework
# metasploit-framework} and pro, which uses Metasploit::Pro.
module Metasploit
	# Supports Rails and Rails::Engine like access to metasploit-framework so it
	# works in compatible manner with activerecord's rake tasks and other
	# railties.
	module Framework
		# Returns the environment for {Metasploit::Framework}.  Checks
		# `METASPLOIT_FRAMEWORK_ENV` environment variable for value.  Defaults to
		# `'development'` if `METASPLOIT_FRAMEWORK_ENV` is not set in the
		# environment variables.
		#
		# {env} is a ActiveSupport::StringInquirer like `Rails.env` so it can be
		# queried for its value.
		#
		# @example check if environment is development
		#   if Metasploit::Framework.env.development?
		#     # runs only when in development
		#   end
		#
		# @return [ActiveSupport::StringInquirer] the environment name
		def self.env
			unless instance_variable_defined? :@env
				name = ENV['METASPLOIT_FRAMEWORK_ENV']
				name ||= 'development'
				@env = ActiveSupport::StringInquirer.new(name)
			end

			@env
		end

		# Returns the root of the metasploit-framework project.  Use in place of
		# `Rails.root`.
		#
		# @return [Pathname]
		def self.root
			unless instance_variable_defined? :@root
				pathname = Pathname.new(__FILE__)
				@root = pathname.parent.parent.parent
			end

			@root
		end
	end
end