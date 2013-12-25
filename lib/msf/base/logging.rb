# -*- coding: binary -*-
require 'rex'
require 'msf/base'

module Msf

# This module provides an initialization interface for logging.
class Logging

  #Is logging initialized
  #@private
  @@initialized = false
  #Is session logging enabled
  #@private
  @@session_logging = false

  # Initialize logging.
  # @return [void]
  def self.init
    if (! @@initialized)
      @@initialized = true

      f = Rex::Logging::Sinks::Flatfile.new(
        Msf::Config.log_directory + File::SEPARATOR + "framework.log")

      # Register each known log source
      [
        Rex::LogSource,
        Msf::LogSource,
        'base',
      ].each { |src|
        register_log_source(src, f)
      }
    end
  end

  # Enables a log source of name src. Creates the .log file in the
  # configured directory if logging is not already enabled for this
  # source.
  # @param [String] src log source name.
  # @param [Integer] level logging level.
  # @return [void]
  def self.enable_log_source(src, level = 0)
    if (log_source_registered?(src) == false)
      f = Rex::Logging::Sinks::Flatfile.new(
        Msf::Config.log_directory + File::SEPARATOR + "#{src}.log")

      register_log_source(src, f, level)
    end
  end

  # Stops logging for a given log source.
  # @param [String] src the log source to disable.
  # @return [Boolean] true if successful. false if not.
  def self.disable_log_source(src)
    deregister_log_source(src)
  end

  # Sets whether or not session logging is to be enabled.
  # @param [Boolean] tf true if enabling. false if disabling.
  # @return [void]
  def self.enable_session_logging(tf)
    @@session_logging = tf
  end

  # Returns whether or not session logging is enabled.
  # @return [Boolean] true if enabled. false if disabled.
  def self.session_logging_enabled?
    @@session_logging || false
  end

  # Starts logging for a given session.
  # @param [Msf::Session] session the session to start logging on.
  # @return [void]
  def self.start_session_log(session)
    if (log_source_registered?(session.log_source) == false)
      f = Rex::Logging::Sinks::Flatfile.new(
      Msf::Config.session_log_directory + File::SEPARATOR + "#{session.log_file_name}.log")

      register_log_source(session.log_source, f)

      rlog("\n[*] Logging started: #{Time.now}\n\n", session.log_source)
    end
  end

  # Stops logging for a given session.
  # @param [Msf::Session] session the session to stop logging.
  # @return [Boolean] true if sucessful. false if not.
  def self.stop_session_log(session)
    rlog("\n[*] Logging stopped: #{Time.now}\n\n", session.log_source)

    deregister_log_source(session.log_source)
  end

end

end
