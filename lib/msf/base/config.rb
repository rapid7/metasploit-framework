# -*- coding: binary -*-

#
# Standard Library
#

require 'fileutils'

#
# Project
#

require 'metasploit/framework/version'
require 'rex/compat'

module Msf

# This class wraps interaction with global configuration that can be used as a
# persistent storage point for configuration, logs, and other such fun things.
class Config < Hash

  # The installation's root directory for the distribution
  InstallRoot = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..'))

  # Determines the base configuration directory. This method should be considered `private`.
  #
  # @return [String] the base configuration directory
  def self.get_config_root

    # Use MSF_CFGROOT_CONFIG environment variable first.
    val = Rex::Compat.getenv('MSF_CFGROOT_CONFIG')
    if (val and File.directory?(val))
      return val
    end

    # XXX Update this when there is a need to break compatibility
    config_dir_major = 4
    config_dir = ".msf#{config_dir_major}"

    # Windows-specific environment variables
    ['HOME', 'LOCALAPPDATA', 'APPDATA', 'USERPROFILE'].each do |dir|
      val = Rex::Compat.getenv(dir)
      if (val and File.directory?(val))
        return File.join(val, config_dir)
      end
    end

    begin
      # First we try $HOME/.msfx
      File.expand_path("~#{FileSep}#{config_dir}")
    rescue ::ArgumentError
      # Give up and install root + ".msfx"
      InstallRoot + config_dir
    end
  end

  #
  # Default values
  #

  # Default system file separator.
  FileSep     = File::SEPARATOR

  # Default configuration locations.
  Defaults    =
    {
      'ConfigDirectory'     => get_config_root,
      'ConfigFile'          => "config",
      'ModuleDirectory'     => "modules",
      'ScriptDirectory'     => "scripts",
      'LogDirectory'        => "logs",
      'LogosDirectory'      => "logos",
      'SessionLogDirectory' => "logs/sessions",
      'PluginDirectory'     => "plugins",
      'DataDirectory'       => "data",
      'LootDirectory'       => "loot",
      'LocalDirectory'      => "local",
      'HistoriesDirectory'  => "histories"
    }

  ##
  #
  # Class methods
  #
  ##

  # Returns the framework installation root.
  #
  # @return [String] the framework installation root {InstallRoot}.
  def self.install_root
    InstallRoot
  end

  # Returns the configuration directory default.
  #
  # @return [String] the root configuration directory.
  def self.config_directory
    self.new.config_directory
  end

  # Returns the histories directory default.
  #
  # @return [String] the SQL session histories directory.
  def self.histories_directory
    self.new.histories_directory
  end

  # Return the directory that logo files should be loaded from.
  #
  # @return [String] path to the logos directory.
  def self.logos_directory
    self.new.logos_directory
  end

  # Returns the global module directory.
  #
  # @return [String] path to global module directory.
  def self.module_directory
    self.new.module_directory
  end

  # Returns the path that scripts can be loaded from.
  #
  # @return [String] path to script directory.
  def self.script_directory
    self.new.script_directory
  end

  # Returns the directory that log files should be stored in.
  #
  # @return [String] path to log directory.
  def self.log_directory
    self.new.log_directory
  end

  # Returns the directory that plugins are stored in.
  #
  # @return [String] path to plugin directory.
  def self.plugin_directory
    self.new.plugin_directory
  end

  # Returns the user-specific plugin base path
  #
  # @return [String] path to user-specific plugin directory.
  def self.user_plugin_directory
    self.new.user_plugin_directory
  end

  # Returns the directory in which session log files are to reside.
  #
  # @return [String] path to session log directory.
  def self.session_log_directory
    self.new.session_log_directory
  end

  # Returns the directory in which captured data will reside.
  #
  # @return [String] path to loot directory.
  def self.loot_directory
    self.new.loot_directory
  end

  # Returns the directory in which locally-generated data will reside.
  #
  # @return [String] path to locally-generated data directory.
  def self.local_directory
    self.new.local_directory
  end

  # Return the user-specific directory that logo files should be loaded from.
  #
  # @return [String] path to the logos directory.
  def self.user_logos_directory
    self.new.user_logos_directory
  end

  # Returns the user-specific module base path
  #
  # @return [String] path to user-specific modules directory.
  def self.user_module_directory
    self.new.user_module_directory
  end

  # Returns the user-specific script base path
  #
  # @return [String] path to user-specific script directory.
  def self.user_script_directory
    self.new.user_script_directory
  end

  # @return [String] path to user-specific data directory.
  def self.user_data_directory
    self.new.user_data_directory
  end

  # Returns the data directory
  #
  # @return [String] path to data directory.
  def self.data_directory
    self.new.data_directory
  end

  # Returns the full path to the configuration file.
  #
  # @return [String] path to the configuration file.
  def self.config_file
    self.new.config_file
  end

  # Returns the full path to the history file.
  #
  # @return [String] path to the history file.
  def self.history_file
    self.new.history_file
  end

  # Returns the full path to the meterpreter history file.
  #
  # @return [String] path to the history file.
  def self.meterpreter_history
    self.new.meterpreter_history
  end

  # Returns the full path to the smb session history file.
  #
  # @return [String] path to the history file.
  def self.smb_session_history
    self.new.smb_session_history
  end

  # Returns the full path to the ldap session history file.
  #
  # @return [String] path to the history file.
  def self.ldap_session_history
    self.new.ldap_session_history
  end

  # Returns the full path to the MySQL interactive query history file
  #
  # @return [String] path to the interactive query history file.
  def self.history_file_for_session_type(opts)
    self.new.history_file_for_session_type(opts)
  end

  def self.pry_history
    self.new.pry_history
  end
  # Returns the full path to the fav_modules file.
  #
  # @return [String] path to the fav_modules file.
  def self.fav_modules_file
    self.new.fav_modules_file
  end

  # Returns the full path to the handler file.
  #
  # @return [String] path to the handler file.
  def self.persist_file
    self.new.persist_file
  end

  # Initializes configuration, creating directories as necessary.
  #
  # @return [void]
  def self.init
    self.new.init
  end

  # Loads configuration from the supplied file path, or the default one if
  # none is specified.
  #
  # @param path [String] the path to the configuration file.
  # @return [Rex::Parser::Ini] INI file parser.
  def self.load(path = nil)
    self.new.load(path)
  end

  # Saves configuration to the path specified in the ConfigFile hash key or
  # the default path if one isn't specified.  The options should be group
  # references that have named value pairs.
  #
  # @param opts [Hash] Hash containing configuration options.
  # @option opts 'ConfigFile' [Hash] configuration file these options apply
  #   to.
  # @return [void]
  # @example Save 'Cat' => 'Foo' in group 'ExampleGroup'
  #   save(
  #     'ExampleGroup' =>
  #        {
  #           'Foo' => 'Cat'
  #        })
  def self.save(opts)
    self.new.save(opts)
  end

  # Deletes the specified config group from the ini file
  #
  # @param group [String] The name of the group to remove
  # @return [void]
  def self.delete_group(group)
    self.new.delete_group(group)
  end

  # Updates the config class' self with the default hash.
  #
  # @return [Hash] the updated Hash.
  def initialize
    update(Defaults)
  end

  # Returns the installation root directory
  #
  # @return [String] the installation root directory {InstallRoot}.
  def install_root
    InstallRoot
  end

  # Return the directory that logo files should be loaded from.
  #
  # @return [String] path to the logos directory.
  def logos_directory
    data_directory + FileSep + self['LogosDirectory']
  end

  # Returns the configuration directory default.
  #
  # @return [String] the root configuration directory.
  def config_directory
    self['ConfigDirectory']
  end

  # Returns the histories directory default.
  #
  # @return [String] the SQL session histories directory.
  def histories_directory
    config_directory + FileSep + self['HistoriesDirectory']
  end

  # Returns the full path to the configuration file.
  #
  # @return [String] path to the configuration file.
  def config_file
    config_directory + FileSep + self['ConfigFile']
  end

  # Returns the full path to the history file.
  #
  # @return [String] path the history file.
  def history_file
    config_directory + FileSep + "history"
  end

  def meterpreter_history
    config_directory + FileSep + "meterpreter_history"
  end

  def smb_session_history
    config_directory + FileSep + "smb_session_history"
  end

  def ldap_session_history
    config_directory + FileSep + "ldap_session_history"
  end

  def history_options_valid?(opts)
    return false if (opts[:session_type].nil? || opts[:interactive].nil?)

    true
  end

  def interactive_to_string_map(interactive)
    # Check for true explicitly rather than just a value that is truthy.
    interactive == true ? '_interactive' : ''
  end

  def history_file_for_session_type(opts)
    return nil unless history_options_valid?(opts)

    session_type_name = opts[:session_type]
    interactive = interactive_to_string_map(opts[:interactive])

    histories_directory + FileSep + "#{session_type_name}_session#{interactive}_history"
  end

  def pry_history
    config_directory + FileSep + "pry_history"
  end

  # Returns the full path to the fav_modules file.
  #
  # @return [String] path the fav_modules file.
  def fav_modules_file
    config_directory + FileSep + "fav_modules"
  end

  # Returns the full path to the handler file.
  #
  # @return [String] path the handler file.
  def persist_file
    config_directory + FileSep + "persist"
  end

  # Returns the global module directory.
  #
  # @return [String] path to global module directory.
  def module_directory
    install_root + FileSep + self['ModuleDirectory']
  end

  # Returns the path that scripts can be loaded from.
  #
  # @return [String] path to script directory.
  def script_directory
    install_root + FileSep + self['ScriptDirectory']
  end

  # Returns the directory that log files should be stored in.
  #
  # @return [String] path to log directory.
  def log_directory
    config_directory + FileSep + self['LogDirectory']
  end

  # Returns the directory that plugins are stored in.
  #
  # @return [String] path to plugin directory.
  def plugin_directory
    install_root + FileSep + self['PluginDirectory']
  end

  # Returns the directory in which session log files are to reside.
  #
  # @return [String] path to session log directory.
  def session_log_directory
    config_directory + FileSep + self['SessionLogDirectory']
  end

  # Returns the directory in which captured data will reside.
  #
  # @return [String] path to loot directory.
  def loot_directory
    config_directory + FileSep + self['LootDirectory']
  end

  # Returns the directory in which locally-generated data will reside.
  #
  # @return [String] path to locally-generated data directory.
  def local_directory
    config_directory + FileSep + self['LocalDirectory']
  end

  # Return the user-specific directory that logo files should be loaded from.
  #
  # @return [String] path to the logos directory.
  def user_logos_directory
    config_directory + FileSep + self['LogosDirectory']
  end

  # Returns the user-specific module base path
  #
  # @return [String] path to user-specific modules directory.
  def user_module_directory
    config_directory + FileSep + "modules"
  end

  # Returns the user-specific plugin base path
  #
  # @return [String] path to user-specific plugin directory.
  def user_plugin_directory
    config_directory + FileSep + "plugins"
  end

  # Returns the user-specific script base path
  #
  # @return [String] path to user-specific script directory.
  def user_script_directory
    config_directory + FileSep + "scripts"
  end

  # @return [String] path to user-specific data directory.
  def user_data_directory
    config_directory + FileSep + self['DataDirectory']
  end

  # Returns the data directory
  #
  # @return [String] path to data directory.
  def data_directory
    install_root + FileSep + self['DataDirectory']
  end

  # Initializes configuration, creating directories as necessary.
  #
  # @return [void]
  def init
    FileUtils.mkdir_p(module_directory)
    FileUtils.mkdir_p(config_directory)
    FileUtils.mkdir_p(log_directory)
    FileUtils.mkdir_p(session_log_directory)
    FileUtils.mkdir_p(loot_directory)
    FileUtils.mkdir_p(local_directory)
    FileUtils.mkdir_p(user_logos_directory)
    FileUtils.mkdir_p(user_module_directory)
    FileUtils.mkdir_p(user_plugin_directory)
    FileUtils.mkdir_p(user_data_directory)
    FileUtils.mkdir_p(histories_directory)
  end

  # Loads configuration from the supplied file path, or the default one if
  # none is specified.
  #
  # @param path [String] the path to the configuration file.
  # @return [Rex::Parser::Ini] INI file parser.
  def load(path = nil)
    path = config_file if (!path)

    return Rex::Parser::Ini.new(path)
  end

  # Saves configuration to the path specified in the ConfigFile hash key or
  # the default path if one isn't specified.  The options should be group
  # references that have named value pairs.
  #
  # @param opts [Hash] Hash containing configuration options.
  # @option opts 'ConfigFile' [Hash] configuration file these options apply
  #   to.
  # @return [void]
  # @example Save 'Cat' => 'Foo' in group 'ExampleGroup'
  #   save(
  #     'ExampleGroup' =>
  #        {
  #           'Foo' => 'Cat'
  #        })
  def save(opts)
    ini = Rex::Parser::Ini.new(opts['ConfigFile'] || config_file)

    ini.update(opts)

    ini.to_file
  end

  # Deletes the specified config group from the ini file
  #
  # @param group [String] The name of the group to remove
  # @return [void]
  def delete_group(group)
    ini = Rex::Parser::Ini.new(config_file)

    ini.delete(group)

    ini.to_file
  end
end

end
