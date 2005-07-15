require 'fileutils'

module Msf

###
#
# Config
# ------
#
# This class wraps interaction with global configuration that can be used as a
# persistent storage point for configuration, logs, and other such fun things.
#
###
class Config < Hash

	#
	# The installation root directory for the distribution
	#
	InstallRoot = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..'))

	#
	# Default values
	#
	FileSep     = File::SEPARATOR
	Defaults    =
		{
			'ConfigDirectory' => File.expand_path("~#{FileSep}.msf3"),
			'ConfigFile'      => "config",
			'LogDirectory'    => "logs",
		}

	##
	#
	# Class methods
	#
	##

	def self.install_root
		InstallRoot
	end

	def self.config_directory
		self.new.config_directory
	end

	def self.log_directory
		self.new.log_directory
	end

	def self.config_file
		self.new.config_file
	end

	def self.init
		self.new.init
	end

	def self.load(path = nil)
		self.new.load(path)
	end

	def self.save(opts)
		self.new.save(opts)
	end

	#
	# Updates the config class' self with the default hash.
	#
	def initialize
		update(Defaults)
	end

	#
	# Returns the installation root directory
	#
	def install_root
		InstallRoot
	end

	#
	# Returns the configuration directory default.
	#
	def config_directory
		self['ConfigDirectory']
	end

	#
	# Returns the full path to the configuration file.
	#
	def config_file
		config_directory + FileSep + self['ConfigFile']
	end

	#
	# Returns the directory that log files should be stored in.
	#
	def log_directory
		config_directory + self['LogDirectory']
	end

	#
	# Initializes configuration, creating directories as necessary.
	#
	def init
		FileUtils.mkdir_p(config_directory)
		FileUtils.mkdir_p(log_directory)
	end

	#
	# Loads configuration from the supplied file path, or the default one if
	# none is specified.
	#
	def load(path = nil)
		path = config_file if (!path)

		return Rex::Parser::Ini.new(path)
	end

	#
	# Saves configuration to the path specified in the ConfigFile hash key or
	# the default path is one isn't specified.  The options should be group
	# references that have named value pairs.  Example:
	#
	# save(
	#   'ExampleGroup' =>
	#      {
	#         'Foo' => 'Cat'
	#      })
	#
	def save(opts)
		ini = Rex::Parser::Ini.new(opts['ConfigFile'] || config_file)

		ini.update(opts)

		ini.to_file
	end

end

end
