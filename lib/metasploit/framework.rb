require 'metasploit/model'

# Top-level namespace that is shared between {Metasploit::Framework
# metasploit-framework} and pro, which uses Metasploit::Pro.
module Metasploit
	# Supports Rails and Rails::Engine like access to metasploit-framework so it
	# works in compatible manner with activerecord's rake tasks and other
	# railties.
	module Framework
		# Paths that should be added to
		# `ActiveSupport::Dependencies.autoload_paths`.
		#
		# @return [Array<String>]
		def self.autoload_paths
			autoload_paths = []

			models_path = root.join('app', 'models').to_path
			autoload_paths << models_path

			lib_path = root.join('lib').to_path
			autoload_paths << lib_path

			autoload_paths
		end

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

Metasploit::Framework.autoload_paths.each do |autoload_path|
	unless ActiveSupport::Dependencies.autoload_paths.include? autoload_path
		ActiveSupport::Dependencies.autoload_paths << autoload_path
	end
end

locale_yaml_glob = Metasploit::Framework.root.join('lib', 'metasploit', 'framework', 'locale', '*.yml').to_path

Dir.glob(locale_yaml_glob) do |locale_yaml|
	unless I18n.load_path.include? locale_yaml
		I18n.load_path << locale_yaml
	end
end
